#include <stdio.h>
#include <stdint.h>

#include "private/pixelflinger/ggl_context.h"

#include "buffer.h"
#include "scanline.h"

#include "codeflinger/CodeCache.h"
#include "codeflinger/GGLAssembler.h"
#include "codeflinger/ARMAssembler.h"
#if defined(__mips__) && !defined(__LP64__) && __mips_isa_rev < 6
#include "codeflinger/MIPSAssembler.h"
#elif defined(__mips__) && defined(__LP64__) && __mips_isa_rev == 6
#include "codeflinger/MIPS64Assembler.h"
#endif
#include "codeflinger/Arm64Assembler.h"

#if defined(__arm__) || (defined(__mips__) && ((!defined(__LP64__) && __mips_isa_rev < 6) || (defined(__LP64__) && __mips_isa_rev == 6))) || defined(__aarch64__)
#   define ANDROID_ARM_CODEGEN  1
#else
#   define ANDROID_ARM_CODEGEN  0
#endif

#if defined(__mips__) && ((!defined(__LP64__) && __mips_isa_rev < 6) || (defined(__LP64__) && __mips_isa_rev == 6))
#define ASSEMBLY_SCRATCH_SIZE   4096
#elif defined(__aarch64__)
#define ASSEMBLY_SCRATCH_SIZE   8192
#else
#define ASSEMBLY_SCRATCH_SIZE   2048
#endif

using namespace android;

class ScanlineAssembly : public Assembly {
    AssemblyKey<needs_t> mKey;
public:
    ScanlineAssembly(needs_t needs, size_t size)
        : Assembly(size), mKey(needs) { }
    const AssemblyKey<needs_t>& key() const { return mKey; }
};

#if ANDROID_ARM_CODEGEN
static void ggl_test_codegen(uint32_t n, uint32_t p, uint32_t t0, uint32_t t1)
{
    GGLContext* c;
    gglInit(&c);
    needs_t needs;
    needs.n = n;
    needs.p = p;
    needs.t[0] = t0;
    needs.t[1] = t1;
    sp<ScanlineAssembly> a(new ScanlineAssembly(needs, ASSEMBLY_SCRATCH_SIZE));

#if defined(__arm__)
    GGLAssembler assembler( new ARMAssembler(a) );
#endif

#if defined(__mips__) && !defined(__LP64__) && __mips_isa_rev < 6
    GGLAssembler assembler( new ArmToMipsAssembler(a) );
#endif

#if defined(__mips__) && defined(__LP64__) && __mips_isa_rev == 6
    GGLAssembler assembler( new ArmToMips64Assembler(a) );
#endif

#if defined(__aarch64__)
    GGLAssembler assembler( new ArmToArm64Assembler(a) );
#endif

    int err = assembler.scanline(needs, (context_t*)c);
    if (err != 0) {
        printf("error %08x (%s)\n", err, strerror(-err));
    }
    gglUninit(c);
}
#else
static void ggl_test_codegen(uint32_t, uint32_t, uint32_t, uint32_t) {
    printf("This test runs only on ARM, Arm64 or MIPS\n");
}
#endif

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
