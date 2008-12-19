#include <stdio.h>
#include <stdint.h>

extern "C" void ggl_test_codegen(
        uint32_t n, uint32_t p, uint32_t t0, uint32_t t1);


int main(int argc, char** argv)
{
    if (argc != 2) {
        printf("usage: %s 00000117:03454504_00001501_00000000\n", argv[0]);
        return 0;
    }
    uint32_t n;
    uint32_t p;
    uint32_t t0;
    uint32_t t1;
    sscanf(argv[1], "%08x:%08x_%08x_%08x", &p, &n, &t0, &t1);
    ggl_test_codegen(n, p,  t0, t1);
    return 0;
}
