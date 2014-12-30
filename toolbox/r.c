#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if __LP64__
#define strtoptr strtoull
#else
#define strtoptr strtoul
#endif

static int usage()
{
    fprintf(stderr,"r [-b|-s] <address> [<value>]\n");
    return -1;
}

int main(int argc, char *argv[])
{
    if(argc < 2) return usage();

    int width = 4;
    if(!strcmp(argv[1], "-b")) {
        width = 1;
        argc--;
        argv++;
    } else if(!strcmp(argv[1], "-s")) {
        width = 2;
        argc--;
        argv++;
    }

    if(argc < 2) return usage();
    uintptr_t addr = strtoptr(argv[1], 0, 16);

    uintptr_t endaddr = 0;
    char* end = strchr(argv[1], '-');
    if (end)
        endaddr = strtoptr(end + 1, 0, 16);

    if (!endaddr)
        endaddr = addr + width - 1;

    if (endaddr <= addr) {
        fprintf(stderr, "end address <= start address\n");
        return -1;
    }

    bool set = false;
    uint32_t value = 0;
    if(argc > 2) {
        set = true;
        value = strtoul(argv[2], 0, 16);
    }

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if(fd < 0) {
        fprintf(stderr,"cannot open /dev/mem\n");
        return -1;
    }

    off64_t mmap_start = addr & ~(PAGE_SIZE - 1);
    size_t mmap_size = endaddr - mmap_start + 1;
    mmap_size = (mmap_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    void* page = mmap64(0, mmap_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, mmap_start);

    if(page == MAP_FAILED){
        fprintf(stderr,"cannot mmap region\n");
        return -1;
    }

    while (addr <= endaddr) {
        switch(width){
        case 4: {
            uint32_t* x = (uint32_t*) (((uintptr_t) page) + (addr & 4095));
            if(set) *x = value;
            fprintf(stderr,"%08"PRIxPTR": %08x\n", addr, *x);
            break;
        }
        case 2: {
            uint16_t* x = (uint16_t*) (((uintptr_t) page) + (addr & 4095));
            if(set) *x = value;
            fprintf(stderr,"%08"PRIxPTR": %04x\n", addr, *x);
            break;
        }
        case 1: {
            uint8_t* x = (uint8_t*) (((uintptr_t) page) + (addr & 4095));
            if(set) *x = value;
            fprintf(stderr,"%08"PRIxPTR": %02x\n", addr, *x);
            break;
        }
        }
        addr += width;
    }
    return 0;
}
