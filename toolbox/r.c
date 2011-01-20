#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

static int usage()
{
    fprintf(stderr,"r [-b|-s] <address> [<value>]\n");
    return -1;
}

int r_main(int argc, char *argv[])
{
    int width = 4, set = 0, fd;
    unsigned addr, value, endaddr = 0;
    unsigned long mmap_start, mmap_size;
    void *page;
    char *end;
    
    if(argc < 2) return usage();

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
    addr = strtoul(argv[1], 0, 16);

    end = strchr(argv[1], '-');
    if (end)
        endaddr = strtoul(end + 1, 0, 16);

    if (!endaddr)
        endaddr = addr + width - 1;

    if (endaddr <= addr) {
        fprintf(stderr, "invalid end address\n");
        return -1;
    }

    if(argc > 2) {
        set = 1;
        value = strtoul(argv[2], 0, 16);
    }

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if(fd < 0) {
        fprintf(stderr,"cannot open /dev/mem\n");
        return -1;
    }
    
    mmap_start = addr & ~(PAGE_SIZE - 1);
    mmap_size = endaddr - mmap_start + 1;
    mmap_size = (mmap_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    page = mmap(0, mmap_size, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, mmap_start);

    if(page == MAP_FAILED){
        fprintf(stderr,"cannot mmap region\n");
        return -1;
    }

    while (addr <= endaddr) {
        switch(width){
        case 4: {
            unsigned *x = (unsigned*) (((unsigned) page) + (addr & 4095));
            if(set) *x = value;
            fprintf(stderr,"%08x: %08x\n", addr, *x);
            break;
        }
        case 2: {
            unsigned short *x = (unsigned short*) (((unsigned) page) + (addr & 4095));
            if(set) *x = value;
            fprintf(stderr,"%08x: %04x\n", addr, *x);
            break;
        }
        case 1: {
            unsigned char *x = (unsigned char*) (((unsigned) page) + (addr & 4095));
            if(set) *x = value;
            fprintf(stderr,"%08x: %02x\n", addr, *x);
            break;
        }
        }
        addr += width;
    }
    return 0;
}
