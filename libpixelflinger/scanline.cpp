/* libs/pixelflinger/scanline.cpp
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/


#define LOG_TAG "pixelflinger"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <cutils/memory.h>
#include <cutils/log.h>

#include "buffer.h"
#include "scanline.h"

#include "codeflinger/CodeCache.h"
#include "codeflinger/GGLAssembler.h"
#include "codeflinger/ARMAssembler.h"
//#include "codeflinger/ARMAssemblerOptimizer.h"

// ----------------------------------------------------------------------------

#define ANDROID_CODEGEN_GENERIC     0   // force generic pixel pipeline
#define ANDROID_CODEGEN_C           1   // hand-written C, fallback generic 
#define ANDROID_CODEGEN_ASM         2   // hand-written asm, fallback generic
#define ANDROID_CODEGEN_GENERATED   3   // hand-written asm, fallback codegen

#ifdef NDEBUG
#   define ANDROID_RELEASE
#   define ANDROID_CODEGEN      ANDROID_CODEGEN_GENERATED
#else
#   define ANDROID_DEBUG
#   define ANDROID_CODEGEN      ANDROID_CODEGEN_GENERATED
#endif

#if defined(__arm__)
#   define ANDROID_ARM_CODEGEN  1
#else
#   define ANDROID_ARM_CODEGEN  0
#endif

#define DEBUG__CODEGEN_ONLY     0


#define ASSEMBLY_SCRATCH_SIZE   2048

// ----------------------------------------------------------------------------
namespace android {
// ----------------------------------------------------------------------------

static void init_y(context_t*, int32_t);
static void init_y_noop(context_t*, int32_t);
static void init_y_packed(context_t*, int32_t);
static void init_y_error(context_t*, int32_t);

static void step_y__generic(context_t* c);
static void step_y__nop(context_t*);
static void step_y__smooth(context_t* c);
static void step_y__tmu(context_t* c);
static void step_y__w(context_t* c);

static void scanline(context_t* c);
static void scanline_perspective(context_t* c);
static void scanline_perspective_single(context_t* c);
static void scanline_t32cb16blend(context_t* c);
static void scanline_t32cb16(context_t* c);
static void scanline_col32cb16blend(context_t* c);
static void scanline_memcpy(context_t* c);
static void scanline_memset8(context_t* c);
static void scanline_memset16(context_t* c);
static void scanline_memset32(context_t* c);
static void scanline_noop(context_t* c);
static void scanline_set(context_t* c);
static void scanline_clear(context_t* c);

static void rect_generic(context_t* c, size_t yc);
static void rect_memcpy(context_t* c, size_t yc);

extern "C" void scanline_t32cb16blend_arm(uint16_t*, uint32_t*, size_t);
extern "C" void scanline_t32cb16_arm(uint16_t *dst, uint32_t *src, size_t ct);
extern "C" void scanline_col32cb16blend_neon(uint16_t *dst, uint32_t *col, size_t ct);
extern "C" void scanline_col32cb16blend_arm(uint16_t *dst, uint32_t col, size_t ct);

// ----------------------------------------------------------------------------

struct shortcut_t {
    needs_filter_t  filter;
    const char*     desc;
    void            (*scanline)(context_t*);
    void            (*init_y)(context_t*, int32_t);
};

// Keep in sync with needs
static shortcut_t shortcuts[] = {
    { { { 0x03515104, 0x00000077, { 0x00000A01, 0x00000000 } },
        { 0xFFFFFFFF, 0xFFFFFFFF, { 0xFFFFFFFF, 0x0000003F } } },
        "565 fb, 8888 tx, blend", scanline_t32cb16blend, init_y_noop },
    { { { 0x03010104, 0x00000077, { 0x00000A01, 0x00000000 } },
        { 0xFFFFFFFF, 0xFFFFFFFF, { 0xFFFFFFFF, 0x0000003F } } },
        "565 fb, 8888 tx", scanline_t32cb16, init_y_noop  },  
    { { { 0x03515104, 0x00000077, { 0x00000000, 0x00000000 } },
        { 0xFFFFFFFF, 0xFFFFFFFF, { 0xFFFFFFFF, 0xFFFFFFFF } } },
        "565 fb, 8888 fixed color", scanline_col32cb16blend, init_y_packed  },  
    { { { 0x00000000, 0x00000000, { 0x00000000, 0x00000000 } },
        { 0x00000000, 0x00000007, { 0x00000000, 0x00000000 } } },
        "(nop) alpha test", scanline_noop, init_y_noop },
    { { { 0x00000000, 0x00000000, { 0x00000000, 0x00000000 } },
        { 0x00000000, 0x00000070, { 0x00000000, 0x00000000 } } },
        "(nop) depth test", scanline_noop, init_y_noop },
    { { { 0x05000000, 0x00000000, { 0x00000000, 0x00000000 } },
        { 0x0F000000, 0x00000080, { 0x00000000, 0x00000000 } } },
        "(nop) logic_op", scanline_noop, init_y_noop },
    { { { 0xF0000000, 0x00000000, { 0x00000000, 0x00000000 } },
        { 0xF0000000, 0x00000080, { 0x00000000, 0x00000000 } } },
        "(nop) color mask", scanline_noop, init_y_noop },
    { { { 0x0F000000, 0x00000077, { 0x00000000, 0x00000000 } },
        { 0xFF000000, 0x000000F7, { 0x00000000, 0x00000000 } } },
        "(set) logic_op", scanline_set, init_y_noop },
    { { { 0x00000000, 0x00000077, { 0x00000000, 0x00000000 } },
        { 0xFF000000, 0x000000F7, { 0x00000000, 0x00000000 } } },
        "(clear) logic_op", scanline_clear, init_y_noop },
    { { { 0x03000000, 0x00000077, { 0x00000000, 0x00000000 } },
        { 0xFFFFFF00, 0x000000F7, { 0x00000000, 0x00000000 } } },
        "(clear) blending 0/0", scanline_clear, init_y_noop },
    { { { 0x00000000, 0x00000000, { 0x00000000, 0x00000000 } },
        { 0x0000003F, 0x00000000, { 0x00000000, 0x00000000 } } },
        "(error) invalid color-buffer format", scanline_noop, init_y_error },
};
static const needs_filter_t noblend1to1 = {
        // (disregard dithering, see below)
        { 0x03010100, 0x00000077, { 0x00000A00, 0x00000000 } },
        { 0xFFFFFFC0, 0xFFFFFEFF, { 0xFFFFFFC0, 0x0000003F } }
};
static  const needs_filter_t fill16noblend = {
        { 0x03010100, 0x00000077, { 0x00000000, 0x00000000 } },
        { 0xFFFFFFC0, 0xFFFFFFFF, { 0x0000003F, 0x0000003F } }
};

// ----------------------------------------------------------------------------

#if ANDROID_ARM_CODEGEN
static CodeCache gCodeCache(12 * 1024);

class ScanlineAssembly : public Assembly {
    AssemblyKey<needs_t> mKey;
public:
    ScanlineAssembly(needs_t needs, size_t size)
        : Assembly(size), mKey(needs) { }
    const AssemblyKey<needs_t>& key() const { return mKey; }
};
#endif

// ----------------------------------------------------------------------------

void ggl_init_scanline(context_t* c)
{
    c->init_y = init_y;
    c->step_y = step_y__generic;
    c->scanline = scanline;
}

void ggl_uninit_scanline(context_t* c)
{
    if (c->state.buffers.coverage)
        free(c->state.buffers.coverage);
#if ANDROID_ARM_CODEGEN
    if (c->scanline_as)
        c->scanline_as->decStrong(c);
#endif
}

// ----------------------------------------------------------------------------

static void pick_scanline(context_t* c)
{
#if (!defined(DEBUG__CODEGEN_ONLY) || (DEBUG__CODEGEN_ONLY == 0))

#if ANDROID_CODEGEN == ANDROID_CODEGEN_GENERIC
    c->init_y = init_y;
    c->step_y = step_y__generic;
    c->scanline = scanline;
    return;
#endif

    //printf("*** needs [%08lx:%08lx:%08lx:%08lx]\n",
    //    c->state.needs.n, c->state.needs.p,
    //    c->state.needs.t[0], c->state.needs.t[1]);

    // first handle the special case that we cannot test with a filter
    const uint32_t cb_format = GGL_READ_NEEDS(CB_FORMAT, c->state.needs.n);
    if (GGL_READ_NEEDS(T_FORMAT, c->state.needs.t[0]) == cb_format) {
        if (c->state.needs.match(noblend1to1)) {
            // this will match regardless of dithering state, since both
            // src and dest have the same format anyway, there is no dithering
            // to be done.
            const GGLFormat* f =
                &(c->formats[GGL_READ_NEEDS(T_FORMAT, c->state.needs.t[0])]);
            if ((f->components == GGL_RGB) ||
                (f->components == GGL_RGBA) ||
                (f->components == GGL_LUMINANCE) ||
                (f->components == GGL_LUMINANCE_ALPHA))
            {
                // format must have all of RGB components
                // (so the current color doesn't show through)
                c->scanline = scanline_memcpy;
                c->init_y = init_y_noop;
                return;
            }
        }
    }

    if (c->state.needs.match(fill16noblend)) {
        c->init_y = init_y_packed;
        switch (c->formats[cb_format].size) {
        case 1: c->scanline = scanline_memset8;  return;
        case 2: c->scanline = scanline_memset16; return;
        case 4: c->scanline = scanline_memset32; return;
        }
    }

    const int numFilters = sizeof(shortcuts)/sizeof(shortcut_t);
    for (int i=0 ; i<numFilters ; i++) {
        if (c->state.needs.match(shortcuts[i].filter)) {
            c->scanline = shortcuts[i].scanline;
            c->init_y = shortcuts[i].init_y;
            return;
        }
    }

#endif // DEBUG__CODEGEN_ONLY

    c->init_y = init_y;
    c->step_y = step_y__generic;

#if ANDROID_ARM_CODEGEN
    // we're going to have to generate some code...
    // here, generate code for our pixel pipeline
    const AssemblyKey<needs_t> key(c->state.needs);
    sp<Assembly> assembly = gCodeCache.lookup(key);
    if (assembly == 0) {
        // create a new assembly region
        sp<ScanlineAssembly> a = new ScanlineAssembly(c->state.needs, 
                ASSEMBLY_SCRATCH_SIZE);
        // initialize our assembler
        GGLAssembler assembler( new ARMAssembler(a) );
        //GGLAssembler assembler(
        //        new ARMAssemblerOptimizer(new ARMAssembler(a)) );
        // generate the scanline code for the given needs
        int err = assembler.scanline(c->state.needs, c);
        if (ggl_likely(!err)) {
            // finally, cache this assembly
            err = gCodeCache.cache(a->key(), a);
        }
        if (ggl_unlikely(err)) {
            LOGE("error generating or caching assembly. Reverting to NOP.");
            c->scanline = scanline_noop;
            c->init_y = init_y_noop;
            c->step_y = step_y__nop;
            return;
        }
        assembly = a;
    }

    // release the previous assembly
    if (c->scanline_as) {
        c->scanline_as->decStrong(c);
    }

    //LOGI("using generated pixel-pipeline");
    c->scanline_as = assembly.get();
    c->scanline_as->incStrong(c); //  hold on to assembly
    c->scanline = (void(*)(context_t* c))assembly->base();
#else
//    LOGW("using generic (slow) pixel-pipeline");
    c->scanline = scanline;
#endif
}

void ggl_pick_scanline(context_t* c)
{
    pick_scanline(c);
    if ((c->state.enables & GGL_ENABLE_W) &&
        (c->state.enables & GGL_ENABLE_TMUS))
    {
        c->span = c->scanline;
        c->scanline = scanline_perspective;
        if (!(c->state.enabled_tmu & (c->state.enabled_tmu - 1))) {
            // only one TMU enabled
            c->scanline = scanline_perspective_single;
        }
    }
}

// ----------------------------------------------------------------------------

static void blending(context_t* c, pixel_t* fragment, pixel_t* fb);
static void blend_factor(context_t* c, pixel_t* r, uint32_t factor,
        const pixel_t* src, const pixel_t* dst);
static void rescale(uint32_t& u, uint8_t& su, uint32_t& v, uint8_t& sv);

#if ANDROID_ARM_CODEGEN && (ANDROID_CODEGEN == ANDROID_CODEGEN_GENERATED)

// no need to compile the generic-pipeline, it can't be reached
void scanline(context_t*)
{
}

#else

void rescale(uint32_t& u, uint8_t& su, uint32_t& v, uint8_t& sv)
{
    if (su && sv) {
        if (su > sv) {
            v = ggl_expand(v, sv, su);
            sv = su;
        } else if (su < sv) {
            u = ggl_expand(u, su, sv);
            su = sv;
        }
    }
}

void blending(context_t* c, pixel_t* fragment, pixel_t* fb)
{
    rescale(fragment->c[0], fragment->s[0], fb->c[0], fb->s[0]);
    rescale(fragment->c[1], fragment->s[1], fb->c[1], fb->s[1]);
    rescale(fragment->c[2], fragment->s[2], fb->c[2], fb->s[2]);
    rescale(fragment->c[3], fragment->s[3], fb->c[3], fb->s[3]);

    pixel_t sf, df;
    blend_factor(c, &sf, c->state.blend.src, fragment, fb);
    blend_factor(c, &df, c->state.blend.dst, fragment, fb);

    fragment->c[1] =
            gglMulAddx(fragment->c[1], sf.c[1], gglMulx(fb->c[1], df.c[1]));
    fragment->c[2] =
            gglMulAddx(fragment->c[2], sf.c[2], gglMulx(fb->c[2], df.c[2]));
    fragment->c[3] =
            gglMulAddx(fragment->c[3], sf.c[3], gglMulx(fb->c[3], df.c[3]));

    if (c->state.blend.alpha_separate) {
        blend_factor(c, &sf, c->state.blend.src_alpha, fragment, fb);
        blend_factor(c, &df, c->state.blend.dst_alpha, fragment, fb);
    }

    fragment->c[0] =
            gglMulAddx(fragment->c[0], sf.c[0], gglMulx(fb->c[0], df.c[0]));

    // clamp to 1.0
    if (fragment->c[0] >= (1LU<<fragment->s[0]))
        fragment->c[0] = (1<<fragment->s[0])-1;
    if (fragment->c[1] >= (1LU<<fragment->s[1]))
        fragment->c[1] = (1<<fragment->s[1])-1;
    if (fragment->c[2] >= (1LU<<fragment->s[2]))
        fragment->c[2] = (1<<fragment->s[2])-1;
    if (fragment->c[3] >= (1LU<<fragment->s[3]))
        fragment->c[3] = (1<<fragment->s[3])-1;
}

static inline int blendfactor(uint32_t x, uint32_t size, uint32_t def = 0)
{
    if (!size)
        return def;

    // scale to 16 bits
    if (size > 16) {
        x >>= (size - 16);
    } else if (size < 16) {
        x = ggl_expand(x, size, 16);
    }
    x += x >> 15;
    return x;
}

void blend_factor(context_t* c, pixel_t* r, 
        uint32_t factor, const pixel_t* src, const pixel_t* dst)
{
    switch (factor) {
        case GGL_ZERO:
            r->c[1] = 
            r->c[2] = 
            r->c[3] = 
            r->c[0] = 0;
            break;
        case GGL_ONE:
            r->c[1] = 
            r->c[2] = 
            r->c[3] = 
            r->c[0] = FIXED_ONE;
            break;
        case GGL_DST_COLOR:
            r->c[1] = blendfactor(dst->c[1], dst->s[1]);
            r->c[2] = blendfactor(dst->c[2], dst->s[2]);
            r->c[3] = blendfactor(dst->c[3], dst->s[3]);
            r->c[0] = blendfactor(dst->c[0], dst->s[0]);
            break;
        case GGL_SRC_COLOR:
            r->c[1] = blendfactor(src->c[1], src->s[1]);
            r->c[2] = blendfactor(src->c[2], src->s[2]);
            r->c[3] = blendfactor(src->c[3], src->s[3]);
            r->c[0] = blendfactor(src->c[0], src->s[0]);
            break;
        case GGL_ONE_MINUS_DST_COLOR:
            r->c[1] = FIXED_ONE - blendfactor(dst->c[1], dst->s[1]);
            r->c[2] = FIXED_ONE - blendfactor(dst->c[2], dst->s[2]);
            r->c[3] = FIXED_ONE - blendfactor(dst->c[3], dst->s[3]);
            r->c[0] = FIXED_ONE - blendfactor(dst->c[0], dst->s[0]);
            break;
        case GGL_ONE_MINUS_SRC_COLOR:
            r->c[1] = FIXED_ONE - blendfactor(src->c[1], src->s[1]);
            r->c[2] = FIXED_ONE - blendfactor(src->c[2], src->s[2]);
            r->c[3] = FIXED_ONE - blendfactor(src->c[3], src->s[3]);
            r->c[0] = FIXED_ONE - blendfactor(src->c[0], src->s[0]);
            break;
        case GGL_SRC_ALPHA:
            r->c[1] = 
            r->c[2] = 
            r->c[3] = 
            r->c[0] = blendfactor(src->c[0], src->s[0], FIXED_ONE);
            break;
        case GGL_ONE_MINUS_SRC_ALPHA:
            r->c[1] = 
            r->c[2] = 
            r->c[3] = 
            r->c[0] = FIXED_ONE - blendfactor(src->c[0], src->s[0], FIXED_ONE);
            break;
        case GGL_DST_ALPHA:
            r->c[1] = 
            r->c[2] = 
            r->c[3] = 
            r->c[0] = blendfactor(dst->c[0], dst->s[0], FIXED_ONE);
            break;
        case GGL_ONE_MINUS_DST_ALPHA:
            r->c[1] = 
            r->c[2] = 
            r->c[3] = 
            r->c[0] = FIXED_ONE - blendfactor(dst->c[0], dst->s[0], FIXED_ONE);
            break;
        case GGL_SRC_ALPHA_SATURATE:
            // XXX: GGL_SRC_ALPHA_SATURATE
            break;
    }
}

static GGLfixed wrapping(int32_t coord, uint32_t size, int tx_wrap)
{
    GGLfixed d;
    if (tx_wrap == GGL_REPEAT) {
        d = (uint32_t(coord)>>16) * size;
    } else if (tx_wrap == GGL_CLAMP) { // CLAMP_TO_EDGE semantics
        const GGLfixed clamp_min = FIXED_HALF;
        const GGLfixed clamp_max = (size << 16) - FIXED_HALF;
        if (coord < clamp_min)     coord = clamp_min;
        if (coord > clamp_max)     coord = clamp_max;
        d = coord;
    } else { // 1:1
        const GGLfixed clamp_min = 0;
        const GGLfixed clamp_max = (size << 16);
        if (coord < clamp_min)     coord = clamp_min;
        if (coord > clamp_max)     coord = clamp_max;
        d = coord;
    }
    return d;
}

static inline
GGLcolor ADJUST_COLOR_ITERATOR(GGLcolor v, GGLcolor dvdx, int len)
{
    const int32_t end = dvdx * (len-1) + v;
    if (end < 0)
        v -= end;
    v &= ~(v>>31);
    return v;
}

void scanline(context_t* c)
{
    const uint32_t enables = c->state.enables;
    const int xs = c->iterators.xl;
    const int x1 = c->iterators.xr;
	int xc = x1 - xs;
    const int16_t* covPtr = c->state.buffers.coverage + xs;

    // All iterated values are sampled at the pixel center

    // reset iterators for that scanline...
    GGLcolor r, g, b, a;
    iterators_t& ci = c->iterators;
    if (enables & GGL_ENABLE_SMOOTH) {
        r = (xs * c->shade.drdx) + ci.ydrdy;
        g = (xs * c->shade.dgdx) + ci.ydgdy;
        b = (xs * c->shade.dbdx) + ci.ydbdy;
        a = (xs * c->shade.dadx) + ci.ydady;
        r = ADJUST_COLOR_ITERATOR(r, c->shade.drdx, xc);
        g = ADJUST_COLOR_ITERATOR(g, c->shade.dgdx, xc);
        b = ADJUST_COLOR_ITERATOR(b, c->shade.dbdx, xc);
        a = ADJUST_COLOR_ITERATOR(a, c->shade.dadx, xc);
    } else {
        r = ci.ydrdy;
        g = ci.ydgdy;
        b = ci.ydbdy;
        a = ci.ydady;
    }

    // z iterators are 1.31
    GGLfixed z = (xs * c->shade.dzdx) + ci.ydzdy;
    GGLfixed f = (xs * c->shade.dfdx) + ci.ydfdy;

    struct {
        GGLfixed s, t;
    } tc[GGL_TEXTURE_UNIT_COUNT];
    if (enables & GGL_ENABLE_TMUS) {
        for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
            if (c->state.texture[i].enable) {
                texture_iterators_t& ti = c->state.texture[i].iterators;
                if (enables & GGL_ENABLE_W) {
                    tc[i].s = ti.ydsdy;
                    tc[i].t = ti.ydtdy;
                } else {
                    tc[i].s = (xs * ti.dsdx) + ti.ydsdy;
                    tc[i].t = (xs * ti.dtdx) + ti.ydtdy;
                }
            }
        }
    }

    pixel_t fragment;
    pixel_t texel;
    pixel_t fb;

	uint32_t x = xs;
	uint32_t y = c->iterators.y;

	while (xc--) {
    
        { // just a scope

		// read color (convert to 8 bits by keeping only the integer part)
        fragment.s[1] = fragment.s[2] =
        fragment.s[3] = fragment.s[0] = 8;
        fragment.c[1] = r >> (GGL_COLOR_BITS-8);
        fragment.c[2] = g >> (GGL_COLOR_BITS-8);
        fragment.c[3] = b >> (GGL_COLOR_BITS-8);
        fragment.c[0] = a >> (GGL_COLOR_BITS-8);

		// texturing
        if (enables & GGL_ENABLE_TMUS) {
            for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
                texture_t& tx = c->state.texture[i];
                if (!tx.enable)
                    continue;
                texture_iterators_t& ti = tx.iterators;
                int32_t u, v;

                // s-coordinate
                if (tx.s_coord != GGL_ONE_TO_ONE) {
                    const int w = tx.surface.width;
                    u = wrapping(tc[i].s, w, tx.s_wrap);
                    tc[i].s += ti.dsdx;
                } else {
                    u = (((tx.shade.is0>>16) + x)<<16) + FIXED_HALF;
                }

                // t-coordinate
                if (tx.t_coord != GGL_ONE_TO_ONE) {
                    const int h = tx.surface.height;
                    v = wrapping(tc[i].t, h, tx.t_wrap);
                    tc[i].t += ti.dtdx;
                } else {
                    v = (((tx.shade.it0>>16) + y)<<16) + FIXED_HALF;
                }

                // read texture
                if (tx.mag_filter == GGL_NEAREST &&
                    tx.min_filter == GGL_NEAREST)
                {
                    u >>= 16;
                    v >>= 16;
                    tx.surface.read(&tx.surface, c, u, v, &texel);
                } else {
                    const int w = tx.surface.width;
                    const int h = tx.surface.height;
                    u -= FIXED_HALF;
                    v -= FIXED_HALF;
                    int u0 = u >> 16;
                    int v0 = v >> 16;
                    int u1 = u0 + 1;
                    int v1 = v0 + 1;
                    if (tx.s_wrap == GGL_REPEAT) {
                        if (u0<0)  u0 += w;
                        if (u1<0)  u1 += w;
                        if (u0>=w) u0 -= w;
                        if (u1>=w) u1 -= w;
                    } else {
                        if (u0<0)  u0 = 0;
                        if (u1<0)  u1 = 0;
                        if (u0>=w) u0 = w-1;
                        if (u1>=w) u1 = w-1;
                    }
                    if (tx.t_wrap == GGL_REPEAT) {
                        if (v0<0)  v0 += h;
                        if (v1<0)  v1 += h;
                        if (v0>=h) v0 -= h;
                        if (v1>=h) v1 -= h;
                    } else {
                        if (v0<0)  v0 = 0;
                        if (v1<0)  v1 = 0;
                        if (v0>=h) v0 = h-1;
                        if (v1>=h) v1 = h-1;
                    }
                    pixel_t texels[4];
                    uint32_t mm[4];
                    tx.surface.read(&tx.surface, c, u0, v0, &texels[0]);
                    tx.surface.read(&tx.surface, c, u0, v1, &texels[1]);
                    tx.surface.read(&tx.surface, c, u1, v0, &texels[2]);
                    tx.surface.read(&tx.surface, c, u1, v1, &texels[3]);
                    u = (u >> 12) & 0xF; 
                    v = (v >> 12) & 0xF;
                    u += u>>3;
                    v += v>>3;
                    mm[0] = (0x10 - u) * (0x10 - v);
                    mm[1] = (0x10 - u) * v;
                    mm[2] = u * (0x10 - v);
                    mm[3] = 0x100 - (mm[0] + mm[1] + mm[2]);
                    for (int j=0 ; j<4 ; j++) {
                        texel.s[j] = texels[0].s[j];
                        if (!texel.s[j]) continue;
                        texel.s[j] += 8;
                        texel.c[j] =    texels[0].c[j]*mm[0] +
                                        texels[1].c[j]*mm[1] +
                                        texels[2].c[j]*mm[2] +
                                        texels[3].c[j]*mm[3] ;
                    }
                }

                // Texture environnement...
                for (int j=0 ; j<4 ; j++) {
                    uint32_t& Cf = fragment.c[j];
                    uint32_t& Ct = texel.c[j];
                    uint8_t& sf  = fragment.s[j];
                    uint8_t& st  = texel.s[j];
                    uint32_t At = texel.c[0];
                    uint8_t sat = texel.s[0];
                    switch (tx.env) {
                    case GGL_REPLACE:
                        if (st) {
                            Cf = Ct;
                            sf = st;
                        }
                        break;
                    case GGL_MODULATE:
                        if (st) {
                            uint32_t factor = Ct + (Ct>>(st-1));
                            Cf = (Cf * factor) >> st;
                        }
                        break;
                    case GGL_DECAL:
                        if (sat) {
                            rescale(Cf, sf, Ct, st);
                            Cf += ((Ct - Cf) * (At + (At>>(sat-1)))) >> sat;
                        }
                        break;
                    case GGL_BLEND:
                        if (st) {
                            uint32_t Cc = tx.env_color[i];
                            if (sf>8)       Cc = (Cc * ((1<<sf)-1))>>8;
                            else if (sf<8)  Cc = (Cc - (Cc>>(8-sf)))>>(8-sf);
                            uint32_t factor = Ct + (Ct>>(st-1));
                            Cf = ((((1<<st) - factor) * Cf) + Ct*Cc)>>st;
                        }
                        break;
                    case GGL_ADD:
                        if (st) {
                            rescale(Cf, sf, Ct, st);
                            Cf += Ct;
                        }
                        break;
                    }
                }
            }
		}
    
        // coverage application
        if (enables & GGL_ENABLE_AA) {
            int16_t cf = *covPtr++;
            fragment.c[0] = (int64_t(fragment.c[0]) * cf) >> 15;
        }
        
        // alpha-test
        if (enables & GGL_ENABLE_ALPHA_TEST) {
            GGLcolor ref = c->state.alpha_test.ref;
            GGLcolor alpha = (uint64_t(fragment.c[0]) *
                    ((1<<GGL_COLOR_BITS)-1)) / ((1<<fragment.s[0])-1);
            switch (c->state.alpha_test.func) {
            case GGL_NEVER:     goto discard;
            case GGL_LESS:      if (alpha<ref)  break; goto discard;
            case GGL_EQUAL:     if (alpha==ref) break; goto discard;
            case GGL_LEQUAL:    if (alpha<=ref) break; goto discard;
            case GGL_GREATER:   if (alpha>ref)  break; goto discard;
            case GGL_NOTEQUAL:  if (alpha!=ref) break; goto discard;
            case GGL_GEQUAL:    if (alpha>=ref) break; goto discard;
            }
        }
        
        // depth test
        if (c->state.buffers.depth.format) {
            if (enables & GGL_ENABLE_DEPTH_TEST) {
                surface_t* cb = &(c->state.buffers.depth);
                uint16_t* p = (uint16_t*)(cb->data)+(x+(cb->stride*y));
                uint16_t zz = uint32_t(z)>>(16);
                uint16_t depth = *p;
                switch (c->state.depth_test.func) {
                case GGL_NEVER:     goto discard;
                case GGL_LESS:      if (zz<depth)    break; goto discard;
                case GGL_EQUAL:     if (zz==depth)   break; goto discard;
                case GGL_LEQUAL:    if (zz<=depth)   break; goto discard;
                case GGL_GREATER:   if (zz>depth)    break; goto discard;
                case GGL_NOTEQUAL:  if (zz!=depth)   break; goto discard;
                case GGL_GEQUAL:    if (zz>=depth)   break; goto discard;
                }
                // depth buffer is not enabled, if depth-test is not enabled
/*
        fragment.s[1] = fragment.s[2] =
        fragment.s[3] = fragment.s[0] = 8;
        fragment.c[1] = 
        fragment.c[2] = 
        fragment.c[3] = 
        fragment.c[0] = 255 - (zz>>8);
*/
                if (c->state.mask.depth) {
                    *p = zz;
                }
            }
        }

        // fog
        if (enables & GGL_ENABLE_FOG) {
            for (int i=1 ; i<=3 ; i++) {
                GGLfixed fc = (c->state.fog.color[i] * 0x10000) / 0xFF;
                uint32_t& c = fragment.c[i];
                uint8_t& s  = fragment.s[i];
                c = (c * 0x10000) / ((1<<s)-1);
                c = gglMulAddx(c, f, gglMulx(fc, 0x10000 - f));
                s = 16;
            }
        }

        // blending
        if (enables & GGL_ENABLE_BLENDING) {
            fb.c[1] = fb.c[2] = fb.c[3] = fb.c[0] = 0; // placate valgrind
            fb.s[1] = fb.s[2] = fb.s[3] = fb.s[0] = 0;
            c->state.buffers.color.read(
                    &(c->state.buffers.color), c, x, y, &fb);
            blending( c, &fragment, &fb );
        }

		// write
        c->state.buffers.color.write(
                &(c->state.buffers.color), c, x, y, &fragment);
        }

discard:
		// iterate...
        x += 1;
        if (enables & GGL_ENABLE_SMOOTH) {
            r += c->shade.drdx;
            g += c->shade.dgdx;
            b += c->shade.dbdx;
            a += c->shade.dadx;
        }
        z += c->shade.dzdx;
        f += c->shade.dfdx;
	}
}

#endif // ANDROID_ARM_CODEGEN && (ANDROID_CODEGEN == ANDROID_CODEGEN_GENERATED)

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Scanline
#endif

template <typename T, typename U>
static inline __attribute__((const))
T interpolate(int y, T v0, U dvdx, U dvdy) {
    // interpolates in pixel's centers
    // v = v0 + (y + 0.5) * dvdy + (0.5 * dvdx)
    return (y * dvdy) + (v0 + ((dvdy + dvdx) >> 1));
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#endif

void init_y(context_t* c, int32_t ys)
{
    const uint32_t enables = c->state.enables;

    // compute iterators...
    iterators_t& ci = c->iterators;
    
    // sample in the center
    ci.y = ys;

    if (enables & (GGL_ENABLE_DEPTH_TEST|GGL_ENABLE_W|GGL_ENABLE_FOG)) {
        ci.ydzdy = interpolate(ys, c->shade.z0, c->shade.dzdx, c->shade.dzdy);
        ci.ydwdy = interpolate(ys, c->shade.w0, c->shade.dwdx, c->shade.dwdy);
        ci.ydfdy = interpolate(ys, c->shade.f0, c->shade.dfdx, c->shade.dfdy);
    }

    if (ggl_unlikely(enables & GGL_ENABLE_SMOOTH)) {
        ci.ydrdy = interpolate(ys, c->shade.r0, c->shade.drdx, c->shade.drdy);
        ci.ydgdy = interpolate(ys, c->shade.g0, c->shade.dgdx, c->shade.dgdy);
        ci.ydbdy = interpolate(ys, c->shade.b0, c->shade.dbdx, c->shade.dbdy);
        ci.ydady = interpolate(ys, c->shade.a0, c->shade.dadx, c->shade.dady);
        c->step_y = step_y__smooth;
    } else {
        ci.ydrdy = c->shade.r0;
        ci.ydgdy = c->shade.g0;
        ci.ydbdy = c->shade.b0;
        ci.ydady = c->shade.a0;
        // XXX: do only if needed, or make sure this is fast
        c->packed = ggl_pack_color(c, c->state.buffers.color.format,
                ci.ydrdy, ci.ydgdy, ci.ydbdy, ci.ydady);
        c->packed8888 = ggl_pack_color(c, GGL_PIXEL_FORMAT_RGBA_8888, 
                ci.ydrdy, ci.ydgdy, ci.ydbdy, ci.ydady);
    }

    // initialize the variables we need in the shader
    generated_vars_t& gen = c->generated_vars;
    gen.argb[GGLFormat::ALPHA].c  = ci.ydady;
    gen.argb[GGLFormat::ALPHA].dx = c->shade.dadx;
    gen.argb[GGLFormat::RED  ].c  = ci.ydrdy;
    gen.argb[GGLFormat::RED  ].dx = c->shade.drdx;
    gen.argb[GGLFormat::GREEN].c  = ci.ydgdy;
    gen.argb[GGLFormat::GREEN].dx = c->shade.dgdx;
    gen.argb[GGLFormat::BLUE ].c  = ci.ydbdy;
    gen.argb[GGLFormat::BLUE ].dx = c->shade.dbdx;
    gen.dzdx = c->shade.dzdx;
    gen.f    = ci.ydfdy;
    gen.dfdx = c->shade.dfdx;

    if (enables & GGL_ENABLE_TMUS) {
        for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
            texture_t& t = c->state.texture[i];
            if (!t.enable) continue;

            texture_iterators_t& ti = t.iterators;
            if (t.s_coord == GGL_ONE_TO_ONE && t.t_coord == GGL_ONE_TO_ONE) {
                // we need to set all of these to 0 because in some cases
                // step_y__generic() or step_y__tmu() will be used and
                // therefore will update dtdy, however, in 1:1 mode
                // this is always done by the scanline rasterizer.
                ti.dsdx = ti.dsdy = ti.dtdx = ti.dtdy = 0;
                ti.ydsdy = t.shade.is0;
                ti.ydtdy = t.shade.it0;
            } else {
                const int adjustSWrap = ((t.s_wrap==GGL_CLAMP)?0:16);
                const int adjustTWrap = ((t.t_wrap==GGL_CLAMP)?0:16);
                ti.sscale = t.shade.sscale + adjustSWrap;
                ti.tscale = t.shade.tscale + adjustTWrap;
                if (!(enables & GGL_ENABLE_W)) {
                    // S coordinate
                    const int32_t sscale = ti.sscale;
                    const int32_t sy = interpolate(ys,
                            t.shade.is0, t.shade.idsdx, t.shade.idsdy);
                    if (sscale>=0) {
                        ti.ydsdy= sy            << sscale;
                        ti.dsdx = t.shade.idsdx << sscale; 
                        ti.dsdy = t.shade.idsdy << sscale;
                    } else {
                        ti.ydsdy= sy            >> -sscale;
                        ti.dsdx = t.shade.idsdx >> -sscale; 
                        ti.dsdy = t.shade.idsdy >> -sscale;
                    }
                    // T coordinate
                    const int32_t tscale = ti.tscale;
                    const int32_t ty = interpolate(ys,
                            t.shade.it0, t.shade.idtdx, t.shade.idtdy);
                    if (tscale>=0) {
                        ti.ydtdy= ty            << tscale;
                        ti.dtdx = t.shade.idtdx << tscale; 
                        ti.dtdy = t.shade.idtdy << tscale;
                    } else {
                        ti.ydtdy= ty            >> -tscale;
                        ti.dtdx = t.shade.idtdx >> -tscale; 
                        ti.dtdy = t.shade.idtdy >> -tscale;
                    }
                }
            }
            // mirror for generated code...
            generated_tex_vars_t& gen = c->generated_vars.texture[i];
            gen.width   = t.surface.width;
            gen.height  = t.surface.height;
            gen.stride  = t.surface.stride;
            gen.data    = int32_t(t.surface.data);
            gen.dsdx = ti.dsdx;
            gen.dtdx = ti.dtdx;
        }
    }

    // choose the y-stepper
    c->step_y = step_y__nop;
    if (enables & GGL_ENABLE_FOG) {
        c->step_y = step_y__generic;
    } else if (enables & GGL_ENABLE_TMUS) {
        if (enables & GGL_ENABLE_SMOOTH) {
            c->step_y = step_y__generic;
        } else if (enables & GGL_ENABLE_W) {
            c->step_y = step_y__w;
        } else {
            c->step_y = step_y__tmu;
        }
    } else {
        if (enables & GGL_ENABLE_SMOOTH) {
            c->step_y = step_y__smooth;
        }
    }
    
    // choose the rectangle blitter
    c->rect = rect_generic;
    if ((c->step_y == step_y__nop) &&
        (c->scanline == scanline_memcpy))
    {
        c->rect = rect_memcpy;
    }
}

void init_y_packed(context_t* c, int32_t y0)
{
    uint8_t f = c->state.buffers.color.format;
    c->packed = ggl_pack_color(c, f,
            c->shade.r0, c->shade.g0, c->shade.b0, c->shade.a0);
    c->packed8888 = ggl_pack_color(c, GGL_PIXEL_FORMAT_RGBA_8888,
            c->shade.r0, c->shade.g0, c->shade.b0, c->shade.a0);
    c->iterators.y = y0;
    c->step_y = step_y__nop;
    // choose the rectangle blitter
    c->rect = rect_generic;
    if (c->scanline == scanline_memcpy) {
        c->rect = rect_memcpy;
    }
}

void init_y_noop(context_t* c, int32_t y0)
{
    c->iterators.y = y0;
    c->step_y = step_y__nop;
    // choose the rectangle blitter
    c->rect = rect_generic;
    if (c->scanline == scanline_memcpy) {
        c->rect = rect_memcpy;
    }
}

void init_y_error(context_t* c, int32_t y0)
{
    // woooops, shoud never happen,
    // fail gracefully (don't display anything)
    init_y_noop(c, y0);
    LOGE("color-buffer has an invalid format!");
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#endif

void step_y__generic(context_t* c)
{
    const uint32_t enables = c->state.enables;

    // iterate...
    iterators_t& ci = c->iterators;
    ci.y += 1;
                
    if (enables & GGL_ENABLE_SMOOTH) {
        ci.ydrdy += c->shade.drdy;
        ci.ydgdy += c->shade.dgdy;
        ci.ydbdy += c->shade.dbdy;
        ci.ydady += c->shade.dady;
    }

    const uint32_t mask =
            GGL_ENABLE_DEPTH_TEST |
            GGL_ENABLE_W |
            GGL_ENABLE_FOG;
    if (enables & mask) {
        ci.ydzdy += c->shade.dzdy;
        ci.ydwdy += c->shade.dwdy;
        ci.ydfdy += c->shade.dfdy;
    }

    if ((enables & GGL_ENABLE_TMUS) && (!(enables & GGL_ENABLE_W))) {
        for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
            if (c->state.texture[i].enable) {
                texture_iterators_t& ti = c->state.texture[i].iterators;
                ti.ydsdy += ti.dsdy;
                ti.ydtdy += ti.dtdy;
            }
        }
    }
}

void step_y__nop(context_t* c)
{
    c->iterators.y += 1;
    c->iterators.ydzdy += c->shade.dzdy;
}

void step_y__smooth(context_t* c)
{
    iterators_t& ci = c->iterators;
    ci.y += 1;
    ci.ydrdy += c->shade.drdy;
    ci.ydgdy += c->shade.dgdy;
    ci.ydbdy += c->shade.dbdy;
    ci.ydady += c->shade.dady;
    ci.ydzdy += c->shade.dzdy;
}

void step_y__w(context_t* c)
{
    iterators_t& ci = c->iterators;
    ci.y += 1;
    ci.ydzdy += c->shade.dzdy;
    ci.ydwdy += c->shade.dwdy;
}

void step_y__tmu(context_t* c)
{
    iterators_t& ci = c->iterators;
    ci.y += 1;
    ci.ydzdy += c->shade.dzdy;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
        if (c->state.texture[i].enable) {
            texture_iterators_t& ti = c->state.texture[i].iterators;
            ti.ydsdy += ti.dsdy;
            ti.ydtdy += ti.dtdy;
        }
    }
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#endif

void scanline_perspective(context_t* c)
{
    struct {
        union {
            struct {
                int32_t s, sq;
                int32_t t, tq;
            };
            struct {
                int32_t v, q;
            } st[2];
        };
    } tc[GGL_TEXTURE_UNIT_COUNT] __attribute__((aligned(16)));

    // XXX: we should have a special case when dwdx = 0

    // 32 pixels spans works okay. 16 is a lot better,
    // but hey, it's a software renderer...
    const uint32_t SPAN_BITS = 5; 
    const uint32_t ys = c->iterators.y;
    const uint32_t xs = c->iterators.xl;
    const uint32_t x1 = c->iterators.xr;
	const uint32_t xc = x1 - xs;
    uint32_t remainder = xc & ((1<<SPAN_BITS)-1);
    uint32_t numSpans = xc >> SPAN_BITS;

    const iterators_t& ci = c->iterators;
    int32_t w0 = (xs * c->shade.dwdx) + ci.ydwdy;
    int32_t q0 = gglRecipQ(w0, 30);
    const int iwscale = 32 - gglClz(q0);

    const int32_t dwdx = c->shade.dwdx << SPAN_BITS;
    int32_t xl = c->iterators.xl;

    // We process s & t with a loop to reduce the code size
    // (and i-cache pressure).

    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
        const texture_t& tmu = c->state.texture[i];
        if (!tmu.enable) continue;
        int32_t s =   tmu.shade.is0 +
                     (tmu.shade.idsdy * ys) + (tmu.shade.idsdx * xs) +
                     ((tmu.shade.idsdx + tmu.shade.idsdy)>>1);
        int32_t t =   tmu.shade.it0 +
                     (tmu.shade.idtdy * ys) + (tmu.shade.idtdx * xs) +
                     ((tmu.shade.idtdx + tmu.shade.idtdy)>>1);
        tc[i].s  = s;
        tc[i].t  = t;
        tc[i].sq = gglMulx(s, q0, iwscale);
        tc[i].tq = gglMulx(t, q0, iwscale);
    }

    int32_t span = 0;
    do {
        int32_t w1;
        if (ggl_likely(numSpans)) {
            w1 = w0 + dwdx;
        } else {
            if (remainder) {
                // finish off the scanline...
                span = remainder;
                w1 = (c->shade.dwdx * span) + w0;
            } else {
                break;
            }
        }
        int32_t q1 = gglRecipQ(w1, 30);
        for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
            texture_t& tmu = c->state.texture[i];
            if (!tmu.enable) continue;
            texture_iterators_t& ti = tmu.iterators;

            for (int j=0 ; j<2 ; j++) {
                int32_t v = tc[i].st[j].v;
                if (span)   v += (tmu.shade.st[j].dx)*span;
                else        v += (tmu.shade.st[j].dx)<<SPAN_BITS;
                const int32_t v0 = tc[i].st[j].q;
                const int32_t v1 = gglMulx(v, q1, iwscale);
                int32_t dvdx = v1 - v0;
                if (span)   dvdx /= span;
                else        dvdx >>= SPAN_BITS;
                tc[i].st[j].v = v;
                tc[i].st[j].q = v1;

                const int scale = ti.st[j].scale + (iwscale - 30);
                if (scale >= 0) {
                    ti.st[j].ydvdy = v0   << scale;
                    ti.st[j].dvdx  = dvdx << scale;
                } else {
                    ti.st[j].ydvdy = v0   >> -scale;
                    ti.st[j].dvdx  = dvdx >> -scale;
                }
            }
            generated_tex_vars_t& gen = c->generated_vars.texture[i];
            gen.dsdx = ti.st[0].dvdx;
            gen.dtdx = ti.st[1].dvdx;
        }
        c->iterators.xl = xl;
        c->iterators.xr = xl = xl + (span ? span : (1<<SPAN_BITS));
        w0 = w1;
        q0 = q1;
        c->span(c);
    } while(numSpans--);
}

void scanline_perspective_single(context_t* c)
{
    // 32 pixels spans works okay. 16 is a lot better,
    // but hey, it's a software renderer...
    const uint32_t SPAN_BITS = 5; 
    const uint32_t ys = c->iterators.y;
    const uint32_t xs = c->iterators.xl;
    const uint32_t x1 = c->iterators.xr;
	const uint32_t xc = x1 - xs;

    const iterators_t& ci = c->iterators;
    int32_t w = (xs * c->shade.dwdx) + ci.ydwdy;
    int32_t iw = gglRecipQ(w, 30);
    const int iwscale = 32 - gglClz(iw);

    const int i = 31 - gglClz(c->state.enabled_tmu);
    generated_tex_vars_t& gen = c->generated_vars.texture[i];
    texture_t& tmu = c->state.texture[i];
    texture_iterators_t& ti = tmu.iterators;
    const int sscale = ti.sscale + (iwscale - 30);
    const int tscale = ti.tscale + (iwscale - 30);
    int32_t s =   tmu.shade.is0 +
                 (tmu.shade.idsdy * ys) + (tmu.shade.idsdx * xs) +
                 ((tmu.shade.idsdx + tmu.shade.idsdy)>>1);
    int32_t t =   tmu.shade.it0 +
                 (tmu.shade.idtdy * ys) + (tmu.shade.idtdx * xs) +
                 ((tmu.shade.idtdx + tmu.shade.idtdy)>>1);
    int32_t s0 = gglMulx(s, iw, iwscale);
    int32_t t0 = gglMulx(t, iw, iwscale);
    int32_t xl = c->iterators.xl;

    int32_t sq, tq, dsdx, dtdx;
    int32_t premainder = xc & ((1<<SPAN_BITS)-1);
    uint32_t numSpans = xc >> SPAN_BITS;
    if (c->shade.dwdx == 0) {
        // XXX: we could choose to do this if the error is small enough
        numSpans = 0;
        premainder = xc;
        goto no_perspective;
    }

    if (premainder) {
        w += c->shade.dwdx   * premainder;
        iw = gglRecipQ(w, 30);
no_perspective:        
        s += tmu.shade.idsdx * premainder;
        t += tmu.shade.idtdx * premainder;
        sq = gglMulx(s, iw, iwscale);
        tq = gglMulx(t, iw, iwscale);
        dsdx = (sq - s0) / premainder;
        dtdx = (tq - t0) / premainder;
        c->iterators.xl = xl;
        c->iterators.xr = xl = xl + premainder;
        goto finish;
    }

    while (numSpans--) {
        w += c->shade.dwdx   << SPAN_BITS;
        s += tmu.shade.idsdx << SPAN_BITS;
        t += tmu.shade.idtdx << SPAN_BITS;
        iw = gglRecipQ(w, 30);
        sq = gglMulx(s, iw, iwscale);
        tq = gglMulx(t, iw, iwscale);
        dsdx = (sq - s0) >> SPAN_BITS;
        dtdx = (tq - t0) >> SPAN_BITS;
        c->iterators.xl = xl;
        c->iterators.xr = xl = xl + (1<<SPAN_BITS);
finish:
        if (sscale >= 0) {
            ti.ydsdy = s0   << sscale;
            ti.dsdx  = dsdx << sscale;
        } else {
            ti.ydsdy = s0   >>-sscale;
            ti.dsdx  = dsdx >>-sscale;
        }
        if (tscale >= 0) {
            ti.ydtdy = t0   << tscale;
            ti.dtdx  = dtdx << tscale;
        } else {
            ti.ydtdy = t0   >>-tscale;
            ti.dtdx  = dtdx >>-tscale;
        }
        s0 = sq;
        t0 = tq;
        gen.dsdx = ti.dsdx;
        gen.dtdx = ti.dtdx;
        c->span(c);
    }
}

// ----------------------------------------------------------------------------

void scanline_col32cb16blend(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    union {
        uint16_t* dst;
        uint32_t* dst32;
    };
    dst = reinterpret_cast<uint16_t*>(cb->data) + (x+(cb->stride*y));

#if ((ANDROID_CODEGEN >= ANDROID_CODEGEN_ASM) && defined(__arm__))
#if defined(__ARM_HAVE_NEON) && BYTE_ORDER == LITTLE_ENDIAN
    scanline_col32cb16blend_neon(dst, &(c->packed8888), ct);
#else  // defined(__ARM_HAVE_NEON) && BYTE_ORDER == LITTLE_ENDIAN
    scanline_col32cb16blend_arm(dst, GGL_RGBA_TO_HOST(c->packed8888), ct);
#endif // defined(__ARM_HAVE_NEON) && BYTE_ORDER == LITTLE_ENDIAN
#else
    uint32_t s = GGL_RGBA_TO_HOST(c->packed8888);
    int sA = (s>>24);
    int f = 0x100 - (sA + (sA>>7));
    while (ct--) {
        uint16_t d = *dst;
        int dR = (d>>11)&0x1f;
        int dG = (d>>5)&0x3f;
        int dB = (d)&0x1f;
        int sR = (s >> (   3))&0x1F;
        int sG = (s >> ( 8+2))&0x3F;
        int sB = (s >> (16+3))&0x1F;
        sR += (f*dR)>>8;
        sG += (f*dG)>>8;
        sB += (f*dB)>>8;
        *dst++ = uint16_t((sR<<11)|(sG<<5)|sB);
    }
#endif

}

void scanline_t32cb16(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;    
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    union {
        uint16_t* dst;
        uint32_t* dst32;
    };
    dst = reinterpret_cast<uint16_t*>(cb->data) + (x+(cb->stride*y));

    surface_t* tex = &(c->state.texture[0].surface);
    const int32_t u = (c->state.texture[0].shade.is0>>16) + x;
    const int32_t v = (c->state.texture[0].shade.it0>>16) + y;
    uint32_t *src = reinterpret_cast<uint32_t*>(tex->data)+(u+(tex->stride*v));
    int sR, sG, sB;
    uint32_t s, d;

    if (ct==1 || uint32_t(dst)&2) {
last_one:
        s = GGL_RGBA_TO_HOST( *src++ );
        sR = (s >> (   3))&0x1F;
        sG = (s >> ( 8+2))&0x3F;
        sB = (s >> (16+3))&0x1F;
        *dst++ = uint16_t((sR<<11)|(sG<<5)|sB);
        ct--;
    }

    while (ct >= 2) {
        s = GGL_RGBA_TO_HOST( *src++ );
        sR = (s >> (   3))&0x1F;
        sG = (s >> ( 8+2))&0x3F;
        sB = (s >> (16+3))&0x1F;
        d = (sR<<11)|(sG<<5)|sB;
        
        s = GGL_RGBA_TO_HOST( *src++ );
        sR = (s >> (   3))&0x1F;
        sG = (s >> ( 8+2))&0x3F;
        sB = (s >> (16+3))&0x1F;        
        d |= ((sR<<11)|(sG<<5)|sB)<<16;

#if BYTE_ORDER == BIG_ENDIAN
        d = (d>>16) | (d<<16);
#endif

        *dst32++ = d;
        ct -= 2;
    }
    
    if (ct > 0) {
        goto last_one;
    }
}

void scanline_t32cb16blend(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    uint16_t* dst = reinterpret_cast<uint16_t*>(cb->data) + (x+(cb->stride*y));

    surface_t* tex = &(c->state.texture[0].surface);
    const int32_t u = (c->state.texture[0].shade.is0>>16) + x;
    const int32_t v = (c->state.texture[0].shade.it0>>16) + y;
    uint32_t *src = reinterpret_cast<uint32_t*>(tex->data)+(u+(tex->stride*v));

#if ((ANDROID_CODEGEN >= ANDROID_CODEGEN_ASM) && defined(__arm__))
    scanline_t32cb16blend_arm(dst, src, ct);
#else
    while (ct--) {
        uint32_t s = *src++;
        if (!s) {
            dst++;
            continue;
        }
        uint16_t d = *dst;
        s = GGL_RGBA_TO_HOST(s);
        int sR = (s >> (   3))&0x1F;
        int sG = (s >> ( 8+2))&0x3F;
        int sB = (s >> (16+3))&0x1F;
        int sA = (s>>24);
        int f = 0x100 - (sA + (sA>>7));
        int dR = (d>>11)&0x1f;
        int dG = (d>>5)&0x3f;
        int dB = (d)&0x1f;
        sR += (f*dR)>>8;
        sG += (f*dG)>>8;
        sB += (f*dB)>>8;
        *dst++ = uint16_t((sR<<11)|(sG<<5)|sB);
    }
#endif
}

void scanline_memcpy(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    const GGLFormat* fp = &(c->formats[cb->format]);
    uint8_t* dst = reinterpret_cast<uint8_t*>(cb->data) +
                            (x + (cb->stride * y)) * fp->size;

    surface_t* tex = &(c->state.texture[0].surface);
    const int32_t u = (c->state.texture[0].shade.is0>>16) + x;
    const int32_t v = (c->state.texture[0].shade.it0>>16) + y;
    uint8_t *src = reinterpret_cast<uint8_t*>(tex->data) +
                            (u + (tex->stride * v)) * fp->size;

    const size_t size = ct * fp->size;
    memcpy(dst, src, size);
}

void scanline_memset8(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    uint8_t* dst = reinterpret_cast<uint8_t*>(cb->data) + (x+(cb->stride*y));
    uint32_t packed = c->packed;
    memset(dst, packed, ct);
}

void scanline_memset16(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    uint16_t* dst = reinterpret_cast<uint16_t*>(cb->data) + (x+(cb->stride*y));
    uint32_t packed = c->packed;
    android_memset16(dst, packed, ct*2);
}

void scanline_memset32(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    uint32_t* dst = reinterpret_cast<uint32_t*>(cb->data) + (x+(cb->stride*y));
    uint32_t packed = GGL_HOST_TO_RGBA(c->packed);
    android_memset32(dst, packed, ct*4);
}

void scanline_clear(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    const GGLFormat* fp = &(c->formats[cb->format]);
    uint8_t* dst = reinterpret_cast<uint8_t*>(cb->data) +
                            (x + (cb->stride * y)) * fp->size;
    const size_t size = ct * fp->size;
    memset(dst, 0, size);
}

void scanline_set(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    const GGLFormat* fp = &(c->formats[cb->format]);
    uint8_t* dst = reinterpret_cast<uint8_t*>(cb->data) +
                            (x + (cb->stride * y)) * fp->size;
    const size_t size = ct * fp->size;
    memset(dst, 0xFF, size);
}

void scanline_noop(context_t* c)
{
}

void rect_generic(context_t* c, size_t yc)
{
    do {
        c->scanline(c);
        c->step_y(c);
    } while (--yc);
}

void rect_memcpy(context_t* c, size_t yc)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    const GGLFormat* fp = &(c->formats[cb->format]);
    uint8_t* dst = reinterpret_cast<uint8_t*>(cb->data) +
                            (x + (cb->stride * y)) * fp->size;

    surface_t* tex = &(c->state.texture[0].surface);
    const int32_t u = (c->state.texture[0].shade.is0>>16) + x;
    const int32_t v = (c->state.texture[0].shade.it0>>16) + y;
    uint8_t *src = reinterpret_cast<uint8_t*>(tex->data) +
                            (u + (tex->stride * v)) * fp->size;

    if (cb->stride == tex->stride && ct == size_t(cb->stride)) {
        memcpy(dst, src, ct * fp->size * yc);
    } else {
        const size_t size = ct * fp->size;
        const size_t dbpr = cb->stride  * fp->size;
        const size_t sbpr = tex->stride * fp->size;
        do {
            memcpy(dst, src, size);
            dst += dbpr;
            src += sbpr;        
        } while (--yc);
    }
}
// ----------------------------------------------------------------------------
}; // namespace android

