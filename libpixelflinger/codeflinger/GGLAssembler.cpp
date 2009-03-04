/* libs/pixelflinger/codeflinger/GGLAssembler.cpp
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

#define LOG_TAG "GGLAssembler"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <cutils/log.h>

#include "codeflinger/GGLAssembler.h"

namespace android {

// ----------------------------------------------------------------------------

GGLAssembler::GGLAssembler(ARMAssemblerInterface* target)
    : ARMAssemblerProxy(target), RegisterAllocator(), mOptLevel(7)
{
}

GGLAssembler::~GGLAssembler()
{
}

void GGLAssembler::prolog()
{
    ARMAssemblerProxy::prolog();
}

void GGLAssembler::epilog(uint32_t touched)
{
    ARMAssemblerProxy::epilog(touched);
}

void GGLAssembler::reset(int opt_level)
{
    ARMAssemblerProxy::reset();
    RegisterAllocator::reset();
    mOptLevel = opt_level;
}

// ---------------------------------------------------------------------------

int GGLAssembler::scanline(const needs_t& needs, context_t const* c)
{
    int err = 0;
    int opt_level = mOptLevel;
    while (opt_level >= 0) {
        reset(opt_level);
        err = scanline_core(needs, c);
        if (err == 0)
            break;
        opt_level--;
    }
    
    // XXX: in theory, pcForLabel is not valid before generate()
    uint32_t* fragment_start_pc = pcForLabel("fragment_loop");
    uint32_t* fragment_end_pc = pcForLabel("epilog");
    const int per_fragment_ops = int(fragment_end_pc - fragment_start_pc);
    
    // build a name for our pipeline
    char name[64];    
    sprintf(name,
            "scanline__%08X:%08X_%08X_%08X [%3d ipp]",
            needs.p, needs.n, needs.t[0], needs.t[1], per_fragment_ops);

    if (err) {
        LOGE("Error while generating ""%s""\n", name);
        disassemble(name);
        return -1;
    }

    return generate(name);
}

int GGLAssembler::scanline_core(const needs_t& needs, context_t const* c)
{
    int64_t duration = ggl_system_time();

    mBlendFactorCached = 0;
    mBlending = 0;
    mMasking = 0;
    mAA        = GGL_READ_NEEDS(P_AA, needs.p);
    mDithering = GGL_READ_NEEDS(P_DITHER, needs.p);
    mAlphaTest = GGL_READ_NEEDS(P_ALPHA_TEST, needs.p) + GGL_NEVER;
    mDepthTest = GGL_READ_NEEDS(P_DEPTH_TEST, needs.p) + GGL_NEVER;
    mFog       = GGL_READ_NEEDS(P_FOG, needs.p) != 0;
    mSmooth    = GGL_READ_NEEDS(SHADE, needs.n) != 0;
    mBuilderContext.needs = needs;
    mBuilderContext.c = c;
    mBuilderContext.Rctx = reserveReg(R0); // context always in R0
    mCbFormat = c->formats[ GGL_READ_NEEDS(CB_FORMAT, needs.n) ];

    // ------------------------------------------------------------------------

    decodeLogicOpNeeds(needs);

    decodeTMUNeeds(needs, c);

    mBlendSrc  = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_SRC, needs.n));
    mBlendDst  = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_DST, needs.n));
    mBlendSrcA = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_SRCA, needs.n));
    mBlendDstA = ggl_needs_to_blendfactor(GGL_READ_NEEDS(BLEND_DSTA, needs.n));

    if (!mCbFormat.c[GGLFormat::ALPHA].h) {
        if ((mBlendSrc == GGL_ONE_MINUS_DST_ALPHA) ||
            (mBlendSrc == GGL_DST_ALPHA)) {
            mBlendSrc = GGL_ONE;
        }
        if ((mBlendSrcA == GGL_ONE_MINUS_DST_ALPHA) ||
            (mBlendSrcA == GGL_DST_ALPHA)) {
            mBlendSrcA = GGL_ONE;
        }
        if ((mBlendDst == GGL_ONE_MINUS_DST_ALPHA) ||
            (mBlendDst == GGL_DST_ALPHA)) {
            mBlendDst = GGL_ONE;
        }
        if ((mBlendDstA == GGL_ONE_MINUS_DST_ALPHA) ||
            (mBlendDstA == GGL_DST_ALPHA)) {
            mBlendDstA = GGL_ONE;
        }
    }

    // if we need the framebuffer, read it now
    const int blending =    blending_codes(mBlendSrc, mBlendDst) |
                            blending_codes(mBlendSrcA, mBlendDstA);

    // XXX: handle special cases, destination not modified...
    if ((mBlendSrc==GGL_ZERO) && (mBlendSrcA==GGL_ZERO) &&
        (mBlendDst==GGL_ONE) && (mBlendDstA==GGL_ONE)) {
        // Destination unmodified (beware of logic ops)
    } else if ((mBlendSrc==GGL_ZERO) && (mBlendSrcA==GGL_ZERO) &&
        (mBlendDst==GGL_ZERO) && (mBlendDstA==GGL_ZERO)) {
        // Destination is zero (beware of logic ops)
    }
    
    int fbComponents = 0;
    const int masking = GGL_READ_NEEDS(MASK_ARGB, needs.n);
    for (int i=0 ; i<4 ; i++) {
        const int mask = 1<<i;
        component_info_t& info = mInfo[i];
        int fs = i==GGLFormat::ALPHA ? mBlendSrcA : mBlendSrc;
        int fd = i==GGLFormat::ALPHA ? mBlendDstA : mBlendDst;
        if (fs==GGL_SRC_ALPHA_SATURATE && i==GGLFormat::ALPHA)
            fs = GGL_ONE;
        info.masked =   !!(masking & mask);
        info.inDest =   !info.masked && mCbFormat.c[i].h && 
                        ((mLogicOp & LOGIC_OP_SRC) || (!mLogicOp));
        if (mCbFormat.components >= GGL_LUMINANCE &&
                (i==GGLFormat::GREEN || i==GGLFormat::BLUE)) {
            info.inDest = false;
        }
        info.needed =   (i==GGLFormat::ALPHA) && 
                        (isAlphaSourceNeeded() || mAlphaTest != GGL_ALWAYS);
        info.replaced = !!(mTextureMachine.replaced & mask);
        info.iterated = (!info.replaced && (info.inDest || info.needed)); 
        info.smooth =   mSmooth && info.iterated;
        info.fog =      mFog && info.inDest && (i != GGLFormat::ALPHA);
        info.blend =    (fs != int(GGL_ONE)) || (fd > int(GGL_ZERO));

        mBlending |= (info.blend ? mask : 0);
        mMasking |= (mCbFormat.c[i].h && info.masked) ? mask : 0;
        fbComponents |= mCbFormat.c[i].h ? mask : 0;
    }

    mAllMasked = (mMasking == fbComponents);
    if (mAllMasked) {
        mDithering = 0;
    }
    
    fragment_parts_t parts;

    // ------------------------------------------------------------------------
    prolog();
    // ------------------------------------------------------------------------

    build_scanline_prolog(parts, needs);

    if (registerFile().status())
        return registerFile().status();

    // ------------------------------------------------------------------------
    label("fragment_loop");
    // ------------------------------------------------------------------------
    {
        Scratch regs(registerFile());

        if (mDithering) {
            // update the dither index.
            MOV(AL, 0, parts.count.reg,
                    reg_imm(parts.count.reg, ROR, GGL_DITHER_ORDER_SHIFT));
            ADD(AL, 0, parts.count.reg, parts.count.reg,
                    imm( 1 << (32 - GGL_DITHER_ORDER_SHIFT)));
            MOV(AL, 0, parts.count.reg,
                    reg_imm(parts.count.reg, ROR, 32 - GGL_DITHER_ORDER_SHIFT));
        }

        // XXX: could we do an early alpha-test here in some cases?
        // It would probaly be used only with smooth-alpha and no texture
        // (or no alpha component in the texture).

        // Early z-test
        if (mAlphaTest==GGL_ALWAYS) {
            build_depth_test(parts, Z_TEST|Z_WRITE);
        } else {
            // we cannot do the z-write here, because
            // it might be killed by the alpha-test later
            build_depth_test(parts, Z_TEST);
        }

        { // texture coordinates
            Scratch scratches(registerFile());

            // texel generation
            build_textures(parts, regs);
        }        

        if ((blending & (FACTOR_DST|BLEND_DST)) || 
                (mMasking && !mAllMasked) ||
                (mLogicOp & LOGIC_OP_DST)) 
        {
            // blending / logic_op / masking need the framebuffer
            mDstPixel.setTo(regs.obtain(), &mCbFormat);

            // load the framebuffer pixel
            comment("fetch color-buffer");
            load(parts.cbPtr, mDstPixel);
        }

        if (registerFile().status())
            return registerFile().status();

        pixel_t pixel;
        int directTex = mTextureMachine.directTexture;
        if (directTex | parts.packed) {
            // note: we can't have both here
            // iterated color or direct texture
            pixel = directTex ? parts.texel[directTex-1] : parts.iterated;
            pixel.flags &= ~CORRUPTIBLE;
        } else {
            if (mDithering) {
                const int ctxtReg = mBuilderContext.Rctx;
                const int mask = GGL_DITHER_SIZE-1;
                parts.dither = reg_t(regs.obtain());
                AND(AL, 0, parts.dither.reg, parts.count.reg, imm(mask));
                ADD(AL, 0, parts.dither.reg, parts.dither.reg, ctxtReg);
                LDRB(AL, parts.dither.reg, parts.dither.reg,
                        immed12_pre(GGL_OFFSETOF(ditherMatrix)));
            }
        
            // allocate a register for the resulting pixel
            pixel.setTo(regs.obtain(), &mCbFormat, FIRST);

            build_component(pixel, parts, GGLFormat::ALPHA,    regs);

            if (mAlphaTest!=GGL_ALWAYS) {
                // only handle the z-write part here. We know z-test
                // was successful, as well as alpha-test.
                build_depth_test(parts, Z_WRITE);
            }

            build_component(pixel, parts, GGLFormat::RED,      regs);
            build_component(pixel, parts, GGLFormat::GREEN,    regs);
            build_component(pixel, parts, GGLFormat::BLUE,     regs);

            pixel.flags |= CORRUPTIBLE;
        }

        if (registerFile().status())
            return registerFile().status();
        
        if (pixel.reg == -1) {
            // be defensive here. if we're here it's probably
            // that this whole fragment is a no-op.
            pixel = mDstPixel;
        }
        
        if (!mAllMasked) {
            // logic operation
            build_logic_op(pixel, regs);
    
            // masking
            build_masking(pixel, regs); 
    
            comment("store");
            store(parts.cbPtr, pixel, WRITE_BACK);
        }
    }

    if (registerFile().status())
        return registerFile().status();

    // update the iterated color...
    if (parts.reload != 3) {
        build_smooth_shade(parts);
    }

    // update iterated z
    build_iterate_z(parts);

    // update iterated fog
    build_iterate_f(parts);

    SUB(AL, S, parts.count.reg, parts.count.reg, imm(1<<16));
    B(PL, "fragment_loop");
    label("epilog");
    epilog(registerFile().touched());

    if ((mAlphaTest!=GGL_ALWAYS) || (mDepthTest!=GGL_ALWAYS)) {
        if (mDepthTest!=GGL_ALWAYS) {
            label("discard_before_textures");
            build_iterate_texture_coordinates(parts);
        }
        label("discard_after_textures");
        build_smooth_shade(parts);
        build_iterate_z(parts);
        build_iterate_f(parts);
        if (!mAllMasked) {
            ADD(AL, 0, parts.cbPtr.reg, parts.cbPtr.reg, imm(parts.cbPtr.size>>3));
        }
        SUB(AL, S, parts.count.reg, parts.count.reg, imm(1<<16));
        B(PL, "fragment_loop");
        epilog(registerFile().touched());
    }

    return registerFile().status();
}

// ---------------------------------------------------------------------------

void GGLAssembler::build_scanline_prolog(
    fragment_parts_t& parts, const needs_t& needs)
{
    Scratch scratches(registerFile());
    int Rctx = mBuilderContext.Rctx;

    // compute count
    comment("compute ct (# of pixels to process)");
    parts.count.setTo(obtainReg());
    int Rx = scratches.obtain();    
    int Ry = scratches.obtain();
    CONTEXT_LOAD(Rx, iterators.xl);
    CONTEXT_LOAD(parts.count.reg, iterators.xr);
    CONTEXT_LOAD(Ry, iterators.y);

    // parts.count = iterators.xr - Rx
    SUB(AL, 0, parts.count.reg, parts.count.reg, Rx);
    SUB(AL, 0, parts.count.reg, parts.count.reg, imm(1));

    if (mDithering) {
        // parts.count.reg = 0xNNNNXXDD
        // NNNN = count-1
        // DD   = dither offset
        // XX   = 0xxxxxxx (x = garbage)
        Scratch scratches(registerFile());
        int tx = scratches.obtain();
        int ty = scratches.obtain();
        AND(AL, 0, tx, Rx, imm(GGL_DITHER_MASK));
        AND(AL, 0, ty, Ry, imm(GGL_DITHER_MASK));
        ADD(AL, 0, tx, tx, reg_imm(ty, LSL, GGL_DITHER_ORDER_SHIFT));
        ORR(AL, 0, parts.count.reg, tx, reg_imm(parts.count.reg, LSL, 16));
    } else {
        // parts.count.reg = 0xNNNN0000
        // NNNN = count-1
        MOV(AL, 0, parts.count.reg, reg_imm(parts.count.reg, LSL, 16));
    }

    if (!mAllMasked) {
        // compute dst ptr
        comment("compute color-buffer pointer");
        const int cb_bits = mCbFormat.size*8;
        int Rs = scratches.obtain();
        parts.cbPtr.setTo(obtainReg(), cb_bits);
        CONTEXT_LOAD(Rs, state.buffers.color.stride);
        CONTEXT_LOAD(parts.cbPtr.reg, state.buffers.color.data);
        SMLABB(AL, Rs, Ry, Rs, Rx);  // Rs = Rx + Ry*Rs
        base_offset(parts.cbPtr, parts.cbPtr, Rs);
        scratches.recycle(Rs);
    }
    
    // init fog
    const int need_fog = GGL_READ_NEEDS(P_FOG, needs.p);
    if (need_fog) {
        comment("compute initial fog coordinate");
        Scratch scratches(registerFile());
        int dfdx = scratches.obtain();
        int ydfdy = scratches.obtain();
        int f = ydfdy;
        CONTEXT_LOAD(dfdx,  generated_vars.dfdx);
        CONTEXT_LOAD(ydfdy, iterators.ydfdy);
        MLA(AL, 0, f, Rx, dfdx, ydfdy);
        CONTEXT_STORE(f, generated_vars.f);
    }

    // init Z coordinate
    if ((mDepthTest != GGL_ALWAYS) || GGL_READ_NEEDS(P_MASK_Z, needs.p)) {
        parts.z = reg_t(obtainReg());
        comment("compute initial Z coordinate");
        Scratch scratches(registerFile());
        int dzdx = scratches.obtain();
        int ydzdy = parts.z.reg;
        CONTEXT_LOAD(dzdx,  generated_vars.dzdx);   // 1.31 fixed-point
        CONTEXT_LOAD(ydzdy, iterators.ydzdy);       // 1.31 fixed-point
        MLA(AL, 0, parts.z.reg, Rx, dzdx, ydzdy);

        // we're going to index zbase of parts.count
        // zbase = base + (xl-count + stride*y)*2
        int Rs = dzdx;
        int zbase = scratches.obtain();
        CONTEXT_LOAD(Rs, state.buffers.depth.stride);
        CONTEXT_LOAD(zbase, state.buffers.depth.data);
        SMLABB(AL, Rs, Ry, Rs, Rx);
        ADD(AL, 0, Rs, Rs, reg_imm(parts.count.reg, LSR, 16));
        ADD(AL, 0, zbase, zbase, reg_imm(Rs, LSL, 1));
        CONTEXT_STORE(zbase, generated_vars.zbase);
    }

    // init texture coordinates
    init_textures(parts.coords, reg_t(Rx), reg_t(Ry));
    scratches.recycle(Ry);

    // iterated color
    init_iterated_color(parts, reg_t(Rx));

    // init coverage factor application (anti-aliasing)
    if (mAA) {
        parts.covPtr.setTo(obtainReg(), 16);
        CONTEXT_LOAD(parts.covPtr.reg, state.buffers.coverage);
        ADD(AL, 0, parts.covPtr.reg, parts.covPtr.reg, reg_imm(Rx, LSL, 1));
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::build_component( pixel_t& pixel,
                                    const fragment_parts_t& parts,
                                    int component,
                                    Scratch& regs)
{
    static char const * comments[] = {"alpha", "red", "green", "blue"};
    comment(comments[component]);

    // local register file
    Scratch scratches(registerFile());
    const int dst_component_size = pixel.component_size(component);

    component_t temp(-1);
    build_incoming_component( temp, dst_component_size,
            parts, component, scratches, regs);

    if (mInfo[component].inDest) {

        // blending...
        build_blending( temp, mDstPixel, component, scratches );

        // downshift component and rebuild pixel...
        downshift(pixel, component, temp, parts.dither);
    }
}

void GGLAssembler::build_incoming_component(
                                    component_t& temp,
                                    int dst_size,
                                    const fragment_parts_t& parts,
                                    int component,
                                    Scratch& scratches,
                                    Scratch& global_regs)
{
    const uint32_t component_mask = 1<<component;

    // Figure out what we need for the blending stage...
    int fs = component==GGLFormat::ALPHA ? mBlendSrcA : mBlendSrc;
    int fd = component==GGLFormat::ALPHA ? mBlendDstA : mBlendDst;
    if (fs==GGL_SRC_ALPHA_SATURATE && component==GGLFormat::ALPHA) {
        fs = GGL_ONE;
    }

    // Figure out what we need to extract and for what reason
    const int blending = blending_codes(fs, fd);

    // Are we actually going to blend?
    const int need_blending = (fs != int(GGL_ONE)) || (fd > int(GGL_ZERO));
    
    // expand the source if the destination has more bits
    int need_expander = false;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT-1 ; i++) {
        texture_unit_t& tmu = mTextureMachine.tmu[i];
        if ((tmu.format_idx) &&
            (parts.texel[i].component_size(component) < dst_size)) {
            need_expander = true;
        }
    }

    // do we need to extract this component?
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    const int blend_needs_alpha_source = (component==GGLFormat::ALPHA) &&
                                        (isAlphaSourceNeeded());
    int need_extract = mInfo[component].needed;
    if (mInfo[component].inDest)
    {
        need_extract |= ((need_blending ?
                (blending & (BLEND_SRC|FACTOR_SRC)) : need_expander));
        need_extract |= (mTextureMachine.mask != mTextureMachine.replaced);
        need_extract |= mInfo[component].smooth;
        need_extract |= mInfo[component].fog;
        need_extract |= mDithering;
        need_extract |= multiTexture;
    }

    if (need_extract) {
        Scratch& regs = blend_needs_alpha_source ? global_regs : scratches;
        component_t fragment;

        // iterated color
        build_iterated_color(fragment, parts, component, regs);

        // texture environement (decal, modulate, replace)
        build_texture_environment(fragment, parts, component, regs);

        // expand the source if the destination has more bits
        if (need_expander && (fragment.size() < dst_size)) {
            // we're here only if we fetched a texel
            // (so we know for sure fragment is CORRUPTIBLE)
            expand(fragment, fragment, dst_size);
        }

        // We have a few specific things to do for the alpha-channel
        if ((component==GGLFormat::ALPHA) &&
            (mInfo[component].needed || fragment.size()<dst_size))
        {
            // convert to integer_t first and make sure
            // we don't corrupt a needed register
            if (fragment.l) {
                component_t incoming(fragment);
                modify(fragment, regs);
                MOV(AL, 0, fragment.reg, reg_imm(incoming.reg, LSR, incoming.l));
                fragment.h -= fragment.l;
                fragment.l = 0;
            }

            // coverage factor application
            build_coverage_application(fragment, parts, regs);

            // alpha-test
            build_alpha_test(fragment, parts);

            if (blend_needs_alpha_source) {
                // We keep only 8 bits for the blending stage
                const int shift = fragment.h <= 8 ? 0 : fragment.h-8;
                if (fragment.flags & CORRUPTIBLE) {
                    fragment.flags &= ~CORRUPTIBLE;
                    mAlphaSource.setTo(fragment.reg,
                            fragment.size(), fragment.flags);
                    if (shift) {
                        MOV(AL, 0, mAlphaSource.reg,
                            reg_imm(mAlphaSource.reg, LSR, shift));
                    }
                } else {
                    // XXX: it would better to do this in build_blend_factor()
                    // so we can avoid the extra MOV below.
                    mAlphaSource.setTo(regs.obtain(),
                            fragment.size(), CORRUPTIBLE);
                    if (shift) {
                        MOV(AL, 0, mAlphaSource.reg,
                            reg_imm(fragment.reg, LSR, shift));
                    } else {
                        MOV(AL, 0, mAlphaSource.reg, fragment.reg);
                    }
                }
                mAlphaSource.s -= shift;
            }
        }

        // fog...
        build_fog( fragment, component, regs );

        temp = fragment;
    } else {
        if (mInfo[component].inDest) {
            // extraction not needed and replace
            // we just select the right component
            if ((mTextureMachine.replaced & component_mask) == 0) {
                // component wasn't replaced, so use it!
                temp = component_t(parts.iterated, component);
            }
            for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; i++) {
                const texture_unit_t& tmu = mTextureMachine.tmu[i];
                if ((tmu.mask & component_mask) &&
                    ((tmu.replaced & component_mask) == 0)) {
                    temp = component_t(parts.texel[i], component);
                }
            }
        }
    }
}

bool GGLAssembler::isAlphaSourceNeeded() const
{
    // XXX: also needed for alpha-test
    const int bs = mBlendSrc;
    const int bd = mBlendDst;
    return  bs==GGL_SRC_ALPHA_SATURATE ||
            bs==GGL_SRC_ALPHA || bs==GGL_ONE_MINUS_SRC_ALPHA ||
            bd==GGL_SRC_ALPHA || bd==GGL_ONE_MINUS_SRC_ALPHA ; 
}

// ---------------------------------------------------------------------------

void GGLAssembler::build_smooth_shade(const fragment_parts_t& parts)
{
    if (mSmooth && !parts.iterated_packed) {
        // update the iterated color in a pipelined way...
        comment("update iterated color");
        Scratch scratches(registerFile());

        const int reload = parts.reload;
        for (int i=0 ; i<4 ; i++) {
            if (!mInfo[i].iterated) 
                continue;
                
            int c = parts.argb[i].reg;
            int dx = parts.argb_dx[i].reg;
            
            if (reload & 1) {
                c = scratches.obtain();
                CONTEXT_LOAD(c, generated_vars.argb[i].c);
            }
            if (reload & 2) {
                dx = scratches.obtain();
                CONTEXT_LOAD(dx, generated_vars.argb[i].dx);
            }
            
            if (mSmooth) {
                ADD(AL, 0, c, c, dx);
            }
            
            if (reload & 1) {
                CONTEXT_STORE(c, generated_vars.argb[i].c);
                scratches.recycle(c);
            }
            if (reload & 2) {
                scratches.recycle(dx);
            }
        }
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::build_coverage_application(component_t& fragment,
        const fragment_parts_t& parts, Scratch& regs)
{
    // here fragment.l is guarenteed to be 0
    if (mAA) {
        // coverages are 1.15 fixed-point numbers
        comment("coverage application");

        component_t incoming(fragment);
        modify(fragment, regs);

        Scratch scratches(registerFile());
        int cf = scratches.obtain();
        LDRH(AL, cf, parts.covPtr.reg, immed8_post(2));
        if (fragment.h > 31) {
            fragment.h--;
            SMULWB(AL, fragment.reg, incoming.reg, cf);
        } else {
            MOV(AL, 0, fragment.reg, reg_imm(incoming.reg, LSL, 1));
            SMULWB(AL, fragment.reg, fragment.reg, cf);
        }
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::build_alpha_test(component_t& fragment,
                                    const fragment_parts_t& parts)
{
    if (mAlphaTest != GGL_ALWAYS) {
        comment("Alpha Test");
        Scratch scratches(registerFile());
        int ref = scratches.obtain();
        const int shift = GGL_COLOR_BITS-fragment.size();
        CONTEXT_LOAD(ref, state.alpha_test.ref);
        if (shift) CMP(AL, fragment.reg, reg_imm(ref, LSR, shift));
        else       CMP(AL, fragment.reg, ref);
        int cc = NV;
        switch (mAlphaTest) {
        case GGL_NEVER:     cc = NV;    break;
        case GGL_LESS:      cc = LT;    break;
        case GGL_EQUAL:     cc = EQ;    break;
        case GGL_LEQUAL:    cc = LS;    break;
        case GGL_GREATER:   cc = HI;    break;
        case GGL_NOTEQUAL:  cc = NE;    break;
        case GGL_GEQUAL:    cc = HS;    break;
        }
        B(cc^1, "discard_after_textures");
    }
}

// ---------------------------------------------------------------------------
            
void GGLAssembler::build_depth_test(
        const fragment_parts_t& parts, uint32_t mask)
{
    mask &= Z_TEST|Z_WRITE;
    const needs_t& needs = mBuilderContext.needs;
    const int zmask = GGL_READ_NEEDS(P_MASK_Z, needs.p);
    Scratch scratches(registerFile());

    if (mDepthTest != GGL_ALWAYS || zmask) {
        int cc=AL, ic=AL;
        switch (mDepthTest) {
        case GGL_LESS:      ic = HI;    break;
        case GGL_EQUAL:     ic = EQ;    break;
        case GGL_LEQUAL:    ic = HS;    break;
        case GGL_GREATER:   ic = LT;    break;
        case GGL_NOTEQUAL:  ic = NE;    break;
        case GGL_GEQUAL:    ic = LS;    break;
        case GGL_NEVER:
            // this never happens, because it's taken care of when 
            // computing the needs. but we keep it for completness.
            comment("Depth Test (NEVER)");
            B(AL, "discard_before_textures");
            return;
        case GGL_ALWAYS:
            // we're here because zmask is enabled
            mask &= ~Z_TEST;    // test always passes.
            break;
        }
        
        // inverse the condition
        cc = ic^1;
        
        if ((mask & Z_WRITE) && !zmask) {
            mask &= ~Z_WRITE;
        }
        
        if (!mask)
            return;

        comment("Depth Test");

        int zbase = scratches.obtain();
        int depth = scratches.obtain();
        int z = parts.z.reg;
        
        CONTEXT_LOAD(zbase, generated_vars.zbase);  // stall
        SUB(AL, 0, zbase, zbase, reg_imm(parts.count.reg, LSR, 15));
            // above does zbase = zbase + ((count >> 16) << 1)

        if (mask & Z_TEST) {
            LDRH(AL, depth, zbase);  // stall
            CMP(AL, depth, reg_imm(z, LSR, 16));
            B(cc, "discard_before_textures");
        }
        if (mask & Z_WRITE) {
            if (mask == Z_WRITE) {
                // only z-write asked, cc is meaningless
                ic = AL;
            }
            MOV(AL, 0, depth, reg_imm(z, LSR, 16));
            STRH(ic, depth, zbase);
        }
    }
}

void GGLAssembler::build_iterate_z(const fragment_parts_t& parts)
{
    const needs_t& needs = mBuilderContext.needs;
    if ((mDepthTest != GGL_ALWAYS) || GGL_READ_NEEDS(P_MASK_Z, needs.p)) {
        Scratch scratches(registerFile());
        int dzdx = scratches.obtain();
        CONTEXT_LOAD(dzdx, generated_vars.dzdx);    // stall
        ADD(AL, 0, parts.z.reg, parts.z.reg, dzdx); 
    }
}

void GGLAssembler::build_iterate_f(const fragment_parts_t& parts)
{
    const needs_t& needs = mBuilderContext.needs;
    if (GGL_READ_NEEDS(P_FOG, needs.p)) {
        Scratch scratches(registerFile());
        int dfdx = scratches.obtain();
        int f = scratches.obtain();
        CONTEXT_LOAD(f,     generated_vars.f);
        CONTEXT_LOAD(dfdx,  generated_vars.dfdx);   // stall
        ADD(AL, 0, f, f, dfdx);
        CONTEXT_STORE(f,    generated_vars.f);
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::build_logic_op(pixel_t& pixel, Scratch& regs)
{
    const needs_t& needs = mBuilderContext.needs;
    const int opcode = GGL_READ_NEEDS(LOGIC_OP, needs.n) | GGL_CLEAR;
    if (opcode == GGL_COPY)
        return;
    
    comment("logic operation");

    pixel_t s(pixel);
    if (!(pixel.flags & CORRUPTIBLE)) {
        pixel.reg = regs.obtain();
        pixel.flags |= CORRUPTIBLE;
    }
    
    pixel_t d(mDstPixel);
    switch(opcode) {
    case GGL_CLEAR:         MOV(AL, 0, pixel.reg, imm(0));          break;
    case GGL_AND:           AND(AL, 0, pixel.reg, s.reg, d.reg);    break;
    case GGL_AND_REVERSE:   BIC(AL, 0, pixel.reg, s.reg, d.reg);    break;
    case GGL_COPY:                                                  break;
    case GGL_AND_INVERTED:  BIC(AL, 0, pixel.reg, d.reg, s.reg);    break;
    case GGL_NOOP:          MOV(AL, 0, pixel.reg, d.reg);           break;
    case GGL_XOR:           EOR(AL, 0, pixel.reg, s.reg, d.reg);    break;
    case GGL_OR:            ORR(AL, 0, pixel.reg, s.reg, d.reg);    break;
    case GGL_NOR:           ORR(AL, 0, pixel.reg, s.reg, d.reg);
                            MVN(AL, 0, pixel.reg, pixel.reg);       break;
    case GGL_EQUIV:         EOR(AL, 0, pixel.reg, s.reg, d.reg);
                            MVN(AL, 0, pixel.reg, pixel.reg);       break;
    case GGL_INVERT:        MVN(AL, 0, pixel.reg, d.reg);           break;
    case GGL_OR_REVERSE:    // s | ~d == ~(~s & d)
                            BIC(AL, 0, pixel.reg, d.reg, s.reg);
                            MVN(AL, 0, pixel.reg, pixel.reg);       break;
    case GGL_COPY_INVERTED: MVN(AL, 0, pixel.reg, s.reg);           break;
    case GGL_OR_INVERTED:   // ~s | d == ~(s & ~d)
                            BIC(AL, 0, pixel.reg, s.reg, d.reg);
                            MVN(AL, 0, pixel.reg, pixel.reg);       break;
    case GGL_NAND:          AND(AL, 0, pixel.reg, s.reg, d.reg);
                            MVN(AL, 0, pixel.reg, pixel.reg);       break;
    case GGL_SET:           MVN(AL, 0, pixel.reg, imm(0));          break;
    };        
}

// ---------------------------------------------------------------------------

static uint32_t find_bottom(uint32_t val)
{
    uint32_t i = 0;
    while (!(val & (3<<i)))
        i+= 2;
    return i;
}

static void normalize(uint32_t& val, uint32_t& rot)
{
    rot = 0;
    while (!(val&3)  || (val & 0xFC000000)) {
        uint32_t newval;
        newval = val >> 2;
        newval |= (val&3) << 30;
        val = newval;
        rot += 2;
        if (rot == 32) {
            rot = 0;
            break;
        }
    }
}

void GGLAssembler::build_and_immediate(int d, int s, uint32_t mask, int bits)
{
    uint32_t rot;
    uint32_t size = ((bits>=32) ? 0 : (1LU << bits)) - 1;
    mask &= size;

    if (mask == size) {
        if (d != s)
            MOV( AL, 0, d, s);
        return;
    }
    
    int negative_logic = !isValidImmediate(mask);
    if (negative_logic) {
        mask = ~mask & size;
    }
    normalize(mask, rot);

    if (mask) {
        while (mask) {
            uint32_t bitpos = find_bottom(mask);
            int shift = rot + bitpos;
            uint32_t m = mask & (0xff << bitpos);
            mask &= ~m;
            m >>= bitpos;
            int32_t newMask =  (m<<shift) | (m>>(32-shift));
            if (!negative_logic) {
                AND( AL, 0, d, s, imm(newMask) );
            } else {
                BIC( AL, 0, d, s, imm(newMask) );
            }
            s = d;
        }
    } else {
        MOV( AL, 0, d, imm(0));
    }
}		

void GGLAssembler::build_masking(pixel_t& pixel, Scratch& regs)
{
    if (!mMasking || mAllMasked) {
        return;
    }

    comment("color mask");

    pixel_t fb(mDstPixel);
    pixel_t s(pixel);
    if (!(pixel.flags & CORRUPTIBLE)) {
        pixel.reg = regs.obtain();
        pixel.flags |= CORRUPTIBLE;
    }

    int mask = 0;
    for (int i=0 ; i<4 ; i++) {
        const int component_mask = 1<<i;
        const int h = fb.format.c[i].h;
        const int l = fb.format.c[i].l;
        if (h && (!(mMasking & component_mask))) {
            mask |= ((1<<(h-l))-1) << l;
        }
    }

    // There is no need to clear the masked components of the source
    // (unless we applied a logic op), because they're already zeroed 
    // by construction (masked components are not computed)

    if (mLogicOp) {
        const needs_t& needs = mBuilderContext.needs;
        const int opcode = GGL_READ_NEEDS(LOGIC_OP, needs.n) | GGL_CLEAR;
        if (opcode != GGL_CLEAR) {
            // clear masked component of source
            build_and_immediate(pixel.reg, s.reg, mask, fb.size());
            s = pixel;
        }
    }

    // clear non masked components of destination
    build_and_immediate(fb.reg, fb.reg, ~mask, fb.size()); 

    // or back the channels that were masked
    if (s.reg == fb.reg) {
         // this is in fact a MOV
        if (s.reg == pixel.reg) {
            // ugh. this in in fact a nop
        } else {
            MOV(AL, 0, pixel.reg, fb.reg);
        }
    } else {
        ORR(AL, 0, pixel.reg, s.reg, fb.reg);
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::base_offset(
        const pointer_t& d, const pointer_t& b, const reg_t& o)
{
    switch (b.size) {
    case 32:
        ADD(AL, 0, d.reg, b.reg, reg_imm(o.reg, LSL, 2));
        break;
    case 24:
        if (d.reg == b.reg) {
            ADD(AL, 0, d.reg, b.reg, reg_imm(o.reg, LSL, 1));
            ADD(AL, 0, d.reg, d.reg, o.reg);
        } else {
            ADD(AL, 0, d.reg, o.reg, reg_imm(o.reg, LSL, 1));
            ADD(AL, 0, d.reg, d.reg, b.reg);
        }
        break;
    case 16:
        ADD(AL, 0, d.reg, b.reg, reg_imm(o.reg, LSL, 1));
        break;
    case 8:
        ADD(AL, 0, d.reg, b.reg, o.reg);
        break;
    }
}

// ----------------------------------------------------------------------------
// cheezy register allocator...
// ----------------------------------------------------------------------------

void RegisterAllocator::reset()
{
    mRegs.reset();
}

int RegisterAllocator::reserveReg(int reg)
{
    return mRegs.reserve(reg);
}

int RegisterAllocator::obtainReg()
{
    return mRegs.obtain();
}

void RegisterAllocator::recycleReg(int reg)
{
    mRegs.recycle(reg);
}

RegisterAllocator::RegisterFile& RegisterAllocator::registerFile()
{
    return mRegs;
}

// ----------------------------------------------------------------------------

RegisterAllocator::RegisterFile::RegisterFile()
    : mRegs(0), mTouched(0), mStatus(0)
{
    reserve(ARMAssemblerInterface::SP);
    reserve(ARMAssemblerInterface::PC);
}

RegisterAllocator::RegisterFile::RegisterFile(const RegisterFile& rhs)
    : mRegs(rhs.mRegs), mTouched(rhs.mTouched)
{
}

RegisterAllocator::RegisterFile::~RegisterFile()
{
}

bool RegisterAllocator::RegisterFile::operator == (const RegisterFile& rhs) const
{
    return (mRegs == rhs.mRegs);
}

void RegisterAllocator::RegisterFile::reset()
{
    mRegs = mTouched = mStatus = 0;
    reserve(ARMAssemblerInterface::SP);
    reserve(ARMAssemblerInterface::PC);
}

int RegisterAllocator::RegisterFile::reserve(int reg)
{
    LOG_ALWAYS_FATAL_IF(isUsed(reg),
                        "reserving register %d, but already in use",
                        reg);
    mRegs |= (1<<reg);
    mTouched |= mRegs;
    return reg;
}

void RegisterAllocator::RegisterFile::reserveSeveral(uint32_t regMask)
{
    mRegs |= regMask;
    mTouched |= regMask;
}

int RegisterAllocator::RegisterFile::isUsed(int reg) const
{
    LOG_ALWAYS_FATAL_IF(reg>=16, "invalid register %d", reg);
    return mRegs & (1<<reg);
}

int RegisterAllocator::RegisterFile::obtain()
{
    const char priorityList[14] = {  0,  1, 2, 3, 
                                    12, 14, 4, 5, 
                                     6,  7, 8, 9,
                                    10, 11 };
    const int nbreg = sizeof(priorityList);
    int i, r;
    for (i=0 ; i<nbreg ; i++) {
        r = priorityList[i];
        if (!isUsed(r)) {
            break;
        }
    }
    // this is not an error anymore because, we'll try again with
    // a lower optimization level.
    //LOGE_IF(i >= nbreg, "pixelflinger ran out of registers\n");
    if (i >= nbreg) {
        mStatus |= OUT_OF_REGISTERS;
        // we return SP so we can more easily debug things
        // the code will never be run anyway.
        return ARMAssemblerInterface::SP; 
    }
    reserve(r);
    return r;
}

bool RegisterAllocator::RegisterFile::hasFreeRegs() const
{
    return ((mRegs & 0xFFFF) == 0xFFFF) ? false : true;
}

int RegisterAllocator::RegisterFile::countFreeRegs() const
{
    int f = ~mRegs & 0xFFFF;
    // now count number of 1
   f = (f & 0x5555) + ((f>>1) & 0x5555);
   f = (f & 0x3333) + ((f>>2) & 0x3333);
   f = (f & 0x0F0F) + ((f>>4) & 0x0F0F);
   f = (f & 0x00FF) + ((f>>8) & 0x00FF);
   return f;
}

void RegisterAllocator::RegisterFile::recycle(int reg)
{
    LOG_FATAL_IF(!isUsed(reg),
            "recycling unallocated register %d",
            reg);
    mRegs &= ~(1<<reg);
}

void RegisterAllocator::RegisterFile::recycleSeveral(uint32_t regMask)
{
    LOG_FATAL_IF((mRegs & regMask)!=regMask,
            "recycling unallocated registers "
            "(recycle=%08x, allocated=%08x, unallocated=%08x)",
            regMask, mRegs, mRegs&regMask);
    mRegs &= ~regMask;
}

uint32_t RegisterAllocator::RegisterFile::touched() const
{
    return mTouched;
}

// ----------------------------------------------------------------------------

}; // namespace android

