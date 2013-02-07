#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <cutils/memory.h>
#include <time.h>

/*
 * All systems must implement or emulate the rdhwr instruction to read
 * the userlocal register. Systems that emulate also return teh count register
 * when accessing register $2 so this should work on most systems
 */
#define USE_RDHWR

#ifdef USE_RDHWR
#define UNITS "cycles"
#define SCALE 2			/* Most CPU's */
static inline uint32_t
get_count(void)
{
  uint32_t res;
  asm volatile (".set push; .set mips32r2; rdhwr %[res],$2; .set pop" : [res] "=r" (res) : : "memory");
  return res;
}
#else
#define UNITS "ns"
#define SCALE 1
static inline uint32_t
get_count(void)
{
  struct timespec now;
  uint32_t res;
  clock_gettime(CLOCK_REALTIME, &now);
  res = (uint32_t)(now.tv_sec * 1000000000LL + now.tv_nsec);
  // printf ("now=%d.%09d res=%d\n", (int)now.tv_sec, (int)now.tv_nsec, res);
  return res;
}
#endif

uint32_t overhead;
void
measure_overhead(void)
{
  int i;
  uint32_t start, stop, delta;
  for (i = 0; i < 32; i++) {
    start = get_count();
    stop = get_count();
    delta = stop - start;
    if (overhead == 0 || delta < overhead)
      overhead = delta;
  }
  printf("overhead is %d"UNITS"\n", overhead);
}

uint32_t
timeone(void (*fn)(), void *d, uint32_t val, uint32_t bytes)
{
  uint32_t start, stop, delta;
  start = get_count();
  (*fn)(d, val, bytes);
  stop = get_count();
  delta = stop - start - overhead;
  // printf ("start=0x%08x stop=0x%08x delta=0x%08x\n", start, stop, delta);
  return delta * SCALE;
}

/* define VERIFY to check that memset only touches the bytes it's supposed to */
/*#define VERIFY*/

/*
 * Using a big arena means that memset will most likely miss in the cache
 * NB Enabling verification effectively warms up the cache...
 */
#define ARENASIZE 0x1000000
#ifdef VERIFY
char arena[ARENASIZE+8];	/* Allow space for guard words */
#else
char arena[ARENASIZE];
#endif

void
testone(char *tag, void (*fn)(), int trials, int minbytes, int maxbytes, int size, int threshold)
{
  int offset;
  void *d;
  void *p;
  uint32_t v, notv = 0;
  uint32_t n;
  int i, units;
  int totalunits = 0, totalbytes = 0, samples = 0;

  /* Reset RNG to ensure each test uses same random values */
  srand(0);			/* FIXME should be able to use some other seed than 0 */

  for (i = 0; i < trials; i++) {
    n = minbytes + (rand() % (maxbytes-minbytes));	/* How many bytes to do */
    offset = ((rand() % (ARENASIZE-n)));		/* Where to start */

#ifdef VERIFY
    offset += 4;		/* Allow space for guard word at beginning */
#endif
    v = rand();

    /* Adjust alignment and sizes based on transfer size */
    switch (size) {
    case 1:
      v &= 0xff;
      notv = ~v & 0xff;
      break;
    case 2:
      v &= 0xffff;
      notv = ~v & 0xffff;
      offset &= ~1;
      n &= ~1;
      break;
    case 4:
      notv = ~v;
      offset &= ~3;
      n &= ~3;
      break;
    }

    d = &arena[offset];

#ifdef VERIFY
    /* Initialise the area and guard words */
    for (p = &arena[offset-4]; p < (void *)&arena[offset+n+4]; p = (void *)((uint32_t)p + size)) {
      if (size == 1)
	*(uint8_t *)p = notv;
      else if (size == 2)
	*(uint16_t *)p = notv;
      else if (size == 4)
	*(uint32_t *)p = notv;
    }
#endif
    units = timeone(fn, d, v, n);
#ifdef VERIFY
    /* Check the area and guard words */
    for (p = &arena[offset-4]; p < (void *)&arena[offset+n+4]; p = (void *)((uint32_t)p + size)) {
      uint32_t got = 0;
      if (size == 1)
	got = *(uint8_t *)p;
      else if (size == 2)
	got = *(uint16_t *)p;
      else if (size == 4)
	got = *(uint32_t *)p;
      if (p < (void *)&arena[offset]) {
	if (got != notv)
	  printf ("%s: verify failure: preguard:%p d=%p v=%08x got=%08x n=%d\n", tag, p, d, v, got, n);
      }
      else if (p < (void *)&arena[offset+n]) {
	if (got != v)
	  printf ("%s: verify failure: arena:%p d=%p v=%08x got=%08x n=%d\n", tag, p, d, v, n);
      }
      else {
	if (got != notv)
	  printf ("%s: verify failure: postguard:%p d=%p v=%08x got=%08x n=%d\n", tag, p, d, v, n);
      }
    }
#endif

    /* If the cycle count looks reasonable include it in the statistics */
    if (units < threshold) {
      totalbytes += n;
      totalunits += units;
      samples++;
    }
  }

  printf("%s: samples=%d avglen=%d avg" UNITS "=%d bp"UNITS"=%g\n",
	 tag, samples, totalbytes/samples, totalunits/samples, (double)totalbytes/(double)totalunits);
}

extern void android_memset32_dumb(uint32_t* dst, uint32_t value, size_t size);
extern void android_memset16_dumb(uint32_t* dst, uint16_t value, size_t size);
extern void android_memset32_test(uint32_t* dst, uint32_t value, size_t size);
extern void android_memset16_test(uint32_t* dst, uint16_t value, size_t size);
extern void memset_cmips(void* dst, int value, size_t size);
extern void memset_omips(void* dst, int value, size_t size);

int
main(int argc, char **argv)
{
  int i;
  struct {
    char *type;
    int trials;
    int minbytes, maxbytes;
  } *pp, params[] = {
    {"small",  10000,   0,   64},
    {"medium", 10000,  64,  512},
    {"large",  10000, 512, 1280},
    {"varied", 10000,   0, 1280},
  };
#define NPARAMS (sizeof(params)/sizeof(params[0]))
  struct {
    char *name;
    void (*fn)();
    int size;
  } *fp, functions[] = {
    {"dmemset16", (void (*)())android_memset16_dumb, 2},
    {"tmemset16", (void (*)())android_memset16_test, 2},
    {"lmemset16", (void (*)())android_memset16,      2},

    {"dmemset32", (void (*)())android_memset32_dumb, 4},
    {"tmemset32", (void (*)())android_memset32_test, 4},
    {"lmemset32", (void (*)())android_memset32,      4},

    {"cmemset",    (void (*)())memset_cmips,         1},
    {"omemset",    (void (*)())memset_omips,         1},
    {"lmemset",    (void (*)())memset,               1},
  };
#define NFUNCTIONS (sizeof(functions)/sizeof(functions[0]))
  char tag[40];
  int threshold;

  measure_overhead();

  /* Warm up the page cache */
  memset(arena, 0xff, ARENASIZE); /* use 0xff now to avoid COW later */

  for (fp = functions; fp < &functions[NFUNCTIONS]; fp++) {
    (fp->fn)(arena, 0xffffffff, ARENASIZE);	/* one call to get the code into Icache */
    for (pp = params; pp < &params[NPARAMS]; pp++) {
      sprintf(tag, "%10s: %7s %4d-%4d", fp->name, pp->type, pp->minbytes, pp->maxbytes);

      /* Set the cycle threshold */
      threshold = pp->maxbytes * 4 * 10;	/* reasonable for cycles and ns */
      testone(tag, fp->fn, pp->trials, pp->minbytes, pp->maxbytes, fp->size, threshold);
    }
    printf ("\n");
  }

  return 0;
}
