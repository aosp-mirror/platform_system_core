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
    unsigned addr, value;
    void *page;
    
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

    if(argc > 2) {
        set = 1;
        value = strtoul(argv[2], 0, 16);
    }

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if(fd < 0) {
        fprintf(stderr,"cannot open /dev/mem\n");
        return -1;
    }
    
    page = mmap(0, 8192, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, addr & (~4095));

    if(page == MAP_FAILED){
        fprintf(stderr,"cannot mmap region\n");
        return -1;
    }

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
    return 0;
}
