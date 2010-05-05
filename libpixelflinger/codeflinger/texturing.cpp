/* libs/pixelflinger/codeflinger/texturing.cpp
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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include <cutils/log.h>

#include "codeflinger/GGLAssembler.h"

#ifdef __ARM_ARCH__
#include <machine/cpu-features.h>
#endif

namespace android {

// ---------------------------------------------------------------------------

// iterators are initialized like this:
// (intToFixedCenter(x) * dx)>>16 + x0
// ((x<<16 + 0x8000) * dx)>>16 + x0
// ((x<<16)*dx + (0x8000*dx))>>16 + x0
// ( (x*dx) + dx>>1 ) + x0
// (x*dx) + (dx>>1 + x0)

void GGLAssembler::init_iterated_color(fragment_parts_t& parts, const reg_t& x)
{
    context_t const* c = mBuilderContext.c;
    const needs_t& needs = mBuilderContext.needs;

    if (mSmooth) {
        // NOTE: we could take this case in the mDithering + !mSmooth case,
        // but this would use up to 4 more registers for the color components
        // for only a little added quality.
        // Currently, this causes the system to run out of registers in
        // some case (see issue #719496)

        comment("compute initial iterated color (smooth and/or dither case)");

        parts.iterated_packed = 0;
        parts.packed = 0;

        // 0x1: color component
        // 0x2: iterators
        const int optReload = mOptLevel >> 1;
        if (optReload >= 3)         parts.reload = 0; // reload nothing
        else if (optReload == 2)    parts.reload = 2; // reload iterators
        else if (optReload == 1)    parts.reload = 1; // reload colors
        else if (optReload <= 0)    parts.reload = 3; // reload both

        if (!mSmooth) {
            // we're not smoothing (just dithering), we never have to 
            // reload the iterators
            parts.reload &= ~2;
        }

        Scratch scratches(registerFile());
        const int t0 = (parts.reload & 1) ? scratches.obtain() : 0;
        const int t1 = (parts.reload & 2) ? scratches.obtain() : 0;
        for (int i=0 ; i<4 ; i++) {
            if (!mInfo[i].iterated)
                continue;            
            
            // this component exists in the destination and is not replaced
            // by a texture unit.
            const int c = (parts.reload & 1) ? t0 : obtainReg();              
            if (i==0) CONTEXT_LOAD(c, iterators.ydady);
            if (i==1) CONTEXT_LOAD(c, iterators.ydrdy);
            if (i==2) CONTEXT_LOAD(c, iterators.ydgdy);
            if (i==3) CONTEXT_LOAD(c, iterators.ydbdy);
            parts.argb[i].reg = c;

            if (mInfo[i].smooth) {
                parts.argb_dx[i].reg = (parts.reload & 2) ? t1 : obtainReg();
                const int dvdx = parts.argb_dx[i].reg;
                CONTEXT_LOAD(dvdx, generated_vars.argb[i].dx);
                MLA(AL, 0, c, x.reg, dvdx, c);
                
                // adjust the color iterator to make sure it won't overflow
                if (!mAA) {
                    // this is not needed when we're using anti-aliasing
                    // because we will (have to) clamp the components
                    // anyway.
                    int end = scratches.obtain();
                    MOV(AL, 0, end, reg_imm(parts.count.reg, LSR, 16));
                    MLA(AL, 1, end, dvdx, end, c);
                    SUB(MI, 0, c, c, end);
                    BIC(AL, 0, c, c, reg_imm(c, ASR, 31)); 
                    scratches.recycle(end);
                }
            }
            
            if (parts.reload & 1) {
                CONTEXT_STORE(c, generated_vars.argb[i].c);
            }
        }
    } else {
        // We're not smoothed, so we can 
        // just use a packed version of the color and extract the
        // components as needed (or not at all if we don't blend)

        // figure out if we need the iterated color
        int load = 0;
        for (int i=0 ; i<4 ; i++) {
            component_info_t& info = mInfo[i];
            if ((info.inDest || info.needed) && !info.replaced)
                load |= 1;
        }
        
        parts.iterated_packed = 1;
        parts.packed = (!mTextureMachine.mask && !mBlending
                && !mFog && !mDithering);
        parts.reload = 0;
        if (load || parts.packed) {
            if (mBlending || mDithering || mInfo[GGLFormat::ALPHA].needed) {
                comment("load initial iterated color (8888 packed)");
                parts.iterated.setTo(obtainReg(),
                        &(c->formats[GGL_PIXEL_FORMAT_RGBA_8888]));
                CONTEXT_LOAD(parts.iterated.reg, packed8888);
            } else {
                comment("load initial iterated color (dest format packed)");

                parts.iterated.setTo(obtainReg(), &mCbFormat);

                // pre-mask the iterated color
                const int bits = parts.iterated.size();
                const uint32_t size = ((bits>=32) ? 0 : (1LU << bits)) - 1;
                uint32_t mask = 0;
                if (mMasking) {
                    for (int i=0 ; i<4 ; i++) {
                        const int component_mask = 1<<i;
                        const int h = parts.iterated.format.c[i].h;
                        const int l = parts.iterated.format.c[i].l;
                        if (h && (!(mMasking & component_mask))) {
                            mask |= ((1<<(h-l))-1) << l;
                        }
                    }
                }

                if (mMasking && ((mask & size)==0)) {
                    // none of the components are present in the mask
                } else {
                    CONTEXT_LOAD(parts.iterated.reg, packed);
                    if (mCbFormat.size == 1) {
                        AND(AL, 0, parts.iterated.reg,
                                parts.iterated.reg, imm(0xFF));
                    } else if (mCbFormat.size == 2) {
                        MOV(AL, 0, parts.iterated.reg,
                                reg_imm(parts.iterated.reg, LSR, 16));
                    }
                }

                // pre-mask the iterated color
                if (mMasking) {
                    build_and_immediate(parts.iterated.reg, parts.iterated.reg,
                            mask, bits);
                }
            }
        }
    }
}

void GGLAssembler::build_iterated_color(
        component_t& fragment,
        const fragment_parts_t& parts,
        int component,
        Scratch& regs)
{
    fragment.setTo( regs.obtain(), 0, 32, CORRUPTIBLE); 

    if (!mInfo[component].iterated)
        return;

    if (parts.iterated_packed) {
        // iterated colors are packed, extract the one we need
        extract(fragment, parts.iterated, component);
    } else {
        fragment.h = GGL_COLOR_BITS;
        fragment.l = GGL_COLOR_BITS - 8;
        fragment.flags |= CLEAR_LO;
        // iterated colors are held in their own register,
        // (smooth and/or dithering case)
        if (parts.reload==3) {
            // this implies mSmooth
            Scratch scratches(registerFile());
            int dx = scratches.obtain();
            CONTEXT_LOAD(fragment.reg, generated_vars.argb[component].c);
            CONTEXT_LOAD(dx, generated_vars.argb[component].dx);
            ADD(AL, 0, dx, fragment.reg, dx);
            CONTEXT_STORE(dx, generated_vars.argb[component].c);
        } else if (parts.reload & 1) {
            CONTEXT_LOAD(fragment.reg, generated_vars.argb[component].c);
        } else {
            // we don't reload, so simply rename the register and mark as
            // non CORRUPTIBLE so that the texture env or blending code
            // won't modify this (renamed) register
            regs.recycle(fragment.reg);
            fragment.reg = parts.argb[component].reg;
            fragment.flags &= ~CORRUPTIBLE;
        }
        if (mInfo[component].smooth && mAA) {
            // when using smooth shading AND anti-aliasing, we need to clamp
            // the iterators because there is always an extra pixel on the
            // edges, which most of the time will cause an overflow
            // (since technically its outside of the domain).
            BIC(AL, 0, fragment.reg, fragment.reg,
                    reg_imm(fragment.reg, ASR, 31));
            component_sat(fragment);
        }
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::decodeLogicOpNeeds(const needs_t& needs)
{
    // gather some informations about the components we need to process...
    const int opcode = GGL_READ_NEEDS(LOGIC_OP, needs.n) | GGL_CLEAR;
    switch(opcode) {
    case GGL_COPY:
        mLogicOp = 0;
        break;
    case GGL_CLEAR:
    case GGL_SET:
        mLogicOp = LOGIC_OP;
        break;
    case GGL_AND:
    case GGL_AND_REVERSE:
    case GGL_AND_INVERTED:
    case GGL_XOR:
    case GGL_OR:
    case GGL_NOR:
    case GGL_EQUIV:
    case GGL_OR_REVERSE:
    case GGL_OR_INVERTED:
    case GGL_NAND:
        mLogicOp = LOGIC_OP|LOGIC_OP_SRC|LOGIC_OP_DST;
        break;
    case GGL_NOOP:
    case GGL_INVERT:
        mLogicOp = LOGIC_OP|LOGIC_OP_DST;
        break;        
    case GGL_COPY_INVERTED:
        mLogicOp = LOGIC_OP|LOGIC_OP_SRC;
        break;
    };        
}

void GGLAssembler::decodeTMUNeeds(const needs_t& needs, context_t const* c)
{
    uint8_t replaced=0;
    mTextureMachine.mask = 0;
    mTextureMachine.activeUnits = 0;
    for (int i=GGL_TEXTURE_UNIT_COUNT-1 ; i>=0 ; i--) {
        texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (replaced == 0xF) {
            // all components are replaced, skip this TMU.
            tmu.format_idx = 0;
            tmu.mask = 0;
            tmu.replaced = replaced;
            continue;
        }
        tmu.format_idx = GGL_READ_NEEDS(T_FORMAT, needs.t[i]);
        tmu.format = c->formats[tmu.format_idx];
        tmu.bits = tmu.format.size*8;
        tmu.swrap = GGL_READ_NEEDS(T_S_WRAP, needs.t[i]);
        tmu.twrap = GGL_READ_NEEDS(T_T_WRAP, needs.t[i]);
        tmu.env = ggl_needs_to_env(GGL_READ_NEEDS(T_ENV, needs.t[i]));
        tmu.pot = GGL_READ_NEEDS(T_POT, needs.t[i]);
        tmu.linear = GGL_READ_NEEDS(T_LINEAR, needs.t[i])
                && tmu.format.size!=3; // XXX: only 8, 16 and 32 modes for now

        // 5551 linear filtering is not supported
        if (tmu.format_idx == GGL_PIXEL_FORMAT_RGBA_5551)
            tmu.linear = 0;
        
        tmu.mask = 0;
        tmu.replaced = replaced;

        if (tmu.format_idx) {
            mTextureMachine.activeUnits++;
            if (tmu.format.c[0].h)    tmu.mask |= 0x1;
            if (tmu.format.c[1].h)    tmu.mask |= 0x2;
            if (tmu.format.c[2].h)    tmu.mask |= 0x4;
            if (tmu.format.c[3].h)    tmu.mask |= 0x8;
            if (tmu.env == GGL_REPLACE) {
                replaced |= tmu.mask;
            } else if (tmu.env == GGL_DECAL) {
                if (!tmu.format.c[GGLFormat::ALPHA].h) {
                    // if we don't have alpha, decal does nothing
                    tmu.mask = 0;
                } else {
                    // decal always ignores At
                    tmu.mask &= ~(1<<GGLFormat::ALPHA);
                }
            }
        }
        mTextureMachine.mask |= tmu.mask;
        //printf("%d: mask=%08lx, replaced=%08lx\n",
        //    i, int(tmu.mask), int(tmu.replaced));
    }
    mTextureMachine.replaced = replaced;
    mTextureMachine.directTexture = 0;
    //printf("replaced=%08lx\n", mTextureMachine.replaced);
}


void GGLAssembler::init_textures(
        tex_coord_t* coords,
        const reg_t& x, const reg_t& y)
{
    context_t const* c = mBuilderContext.c;
    const needs_t& needs = mBuilderContext.needs;
    int Rctx = mBuilderContext.Rctx;
    int Rx = x.reg;
    int Ry = y.reg;

    if (mTextureMachine.mask) {
        comment("compute texture coordinates");
    }

    // init texture coordinates for each tmu
    const int cb_format_idx = GGL_READ_NEEDS(CB_FORMAT, needs.n);
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT; i++) {
        const texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (tmu.format_idx == 0)
            continue;
        if ((tmu.swrap == GGL_NEEDS_WRAP_11) &&
            (tmu.twrap == GGL_NEEDS_WRAP_11)) 
        {
            // 1:1 texture
            pointer_t& txPtr = coords[i].ptr;
            txPtr.setTo(obtainReg(), tmu.bits);
            CONTEXT_LOAD(txPtr.reg, state.texture[i].iterators.ydsdy);
            ADD(AL, 0, Rx, Rx, reg_imm(txPtr.reg, ASR, 16));    // x += (s>>16)
            CONTEXT_LOAD(txPtr.reg, state.texture[i].iterators.ydtdy);
            ADD(AL, 0, Ry, Ry, reg_imm(txPtr.reg, ASR, 16));    // y += (t>>16)
            // merge base & offset
            CONTEXT_LOAD(txPtr.reg, generated_vars.texture[i].stride);
            SMLABB(AL, Rx, Ry, txPtr.reg, Rx);               // x+y*stride
            CONTEXT_LOAD(txPtr.reg, generated_vars.texture[i].data);
            base_offset(txPtr, txPtr, Rx);
        } else {
            Scratch scratches(registerFile());
            reg_t& s = coords[i].s;
            reg_t& t = coords[i].t;
            // s = (x * dsdx)>>16 + ydsdy
            // s = (x * dsdx)>>16 + (y*dsdy)>>16 + s0
            // t = (x * dtdx)>>16 + ydtdy
            // t = (x * dtdx)>>16 + (y*dtdy)>>16 + t0
            s.setTo(obtainReg());
            t.setTo(obtainReg());
            const int need_w = GGL_READ_NEEDS(W, needs.n);
            if (need_w) {
                CONTEXT_LOAD(s.reg, state.texture[i].iterators.ydsdy);
                CONTEXT_LOAD(t.reg, state.texture[i].iterators.ydtdy);
            } else {
                int ydsdy = scratches.obtain();
                int ydtdy = scratches.obtain();
                CONTEXT_LOAD(s.reg, generated_vars.texture[i].dsdx);
                CONTEXT_LOAD(ydsdy, state.texture[i].iterators.ydsdy);
                CONTEXT_LOAD(t.reg, generated_vars.texture[i].dtdx);
                CONTEXT_LOAD(ydtdy, state.texture[i].iterators.ydtdy);
                MLA(AL, 0, s.reg, Rx, s.reg, ydsdy);
                MLA(AL, 0, t.reg, Rx, t.reg, ydtdy);
            }
            
            if ((mOptLevel&1)==0) {
                CONTEXT_STORE(s.reg, generated_vars.texture[i].spill[0]);
                CONTEXT_STORE(t.reg, generated_vars.texture[i].spill[1]);
                recycleReg(s.reg);
                recycleReg(t.reg);
            }
        }

        // direct texture?
        if (!multiTexture && !mBlending && !mDithering && !mFog && 
            cb_format_idx == tmu.format_idx && !tmu.linear &&
            mTextureMachine.replaced == tmu.mask) 
        {
                mTextureMachine.directTexture = i + 1; 
        }
    }
}

void GGLAssembler::build_textures(  fragment_parts_t& parts,
                                    Scratch& regs)
{
    context_t const* c = mBuilderContext.c;
    const needs_t& needs = mBuilderContext.needs;
    int Rctx = mBuilderContext.Rctx;

    // We don't have a way to spill registers automatically
    // spill depth and AA regs, when we know we may have to.
    // build the spill list...
    uint32_t spill_list = 0;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT; i++) {
        const texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (tmu.format_idx == 0)
            continue;
        if (tmu.linear) {
            // we may run out of register if we have linear filtering
            // at 1 or 4 bytes / pixel on any texture unit.
            if (tmu.format.size == 1) {
                // if depth and AA enabled, we'll run out of 1 register
                if (parts.z.reg > 0 && parts.covPtr.reg > 0)
                    spill_list |= 1<<parts.covPtr.reg;
            }
            if (tmu.format.size == 4) {
                // if depth or AA enabled, we'll run out of 1 or 2 registers
                if (parts.z.reg > 0)
                    spill_list |= 1<<parts.z.reg;
                if (parts.covPtr.reg > 0)   
                    spill_list |= 1<<parts.covPtr.reg;
            }
        }
    }

    Spill spill(registerFile(), *this, spill_list);

    const bool multiTexture = mTextureMachine.activeUnits > 1;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT; i++) {
        const texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (tmu.format_idx == 0)
            continue;

        pointer_t& txPtr = parts.coords[i].ptr;
        pixel_t& texel = parts.texel[i];
            
        // repeat...
        if ((tmu.swrap == GGL_NEEDS_WRAP_11) &&
            (tmu.twrap == GGL_NEEDS_WRAP_11))
        { // 1:1 textures
            comment("fetch texel");
            texel.setTo(regs.obtain(), &tmu.format);
            load(txPtr, texel, WRITE_BACK);
        } else {
            Scratch scratches(registerFile());
            reg_t& s = parts.coords[i].s;
            reg_t& t = parts.coords[i].t;
            if ((mOptLevel&1)==0) {
                comment("reload s/t (multitexture or linear filtering)");
                s.reg = scratches.obtain();
                t.reg = scratches.obtain();
                CONTEXT_LOAD(s.reg, generated_vars.texture[i].spill[0]);
                CONTEXT_LOAD(t.reg, generated_vars.texture[i].spill[1]);
            }

            comment("compute repeat/clamp");
            int u       = scratches.obtain();
            int v       = scratches.obtain();
            int width   = scratches.obtain();
            int height  = scratches.obtain();
            int U = 0;
            int V = 0;

            CONTEXT_LOAD(width,  generated_vars.texture[i].width);
            CONTEXT_LOAD(height, generated_vars.texture[i].height);

            int FRAC_BITS = 0;
            if (tmu.linear) {
                // linear interpolation
                if (tmu.format.size == 1) {
                    // for 8-bits textures, we can afford
                    // 7 bits of fractional precision at no
                    // additional cost (we can't do 8 bits
                    // because filter8 uses signed 16 bits muls)
                    FRAC_BITS = 7;
                } else if (tmu.format.size == 2) {
                    // filter16() is internally limited to 4 bits, so:
                    // FRAC_BITS=2 generates less instructions,
                    // FRAC_BITS=3,4,5 creates unpleasant artifacts,
                    // FRAC_BITS=6+ looks good
                    FRAC_BITS = 6;
                } else if (tmu.format.size == 4) {
                    // filter32() is internally limited to 8 bits, so:
                    // FRAC_BITS=4 looks good
                    // FRAC_BITS=5+ looks better, but generates 3 extra ipp
                    FRAC_BITS = 6;
                } else {
                    // for all other cases we use 4 bits.
                    FRAC_BITS = 4;
                }
            }
            wrapping(u, s.reg, width,  tmu.swrap, FRAC_BITS);
            wrapping(v, t.reg, height, tmu.twrap, FRAC_BITS);

            if (tmu.linear) {
                comment("compute linear filtering offsets");
                // pixel size scale
                const int shift = 31 - gglClz(tmu.format.size);
                U = scratches.obtain();
                V = scratches.obtain();

                // sample the texel center
                SUB(AL, 0, u, u, imm(1<<(FRAC_BITS-1)));
                SUB(AL, 0, v, v, imm(1<<(FRAC_BITS-1)));

                // get the fractionnal part of U,V
                AND(AL, 0, U, u, imm((1<<FRAC_BITS)-1));
                AND(AL, 0, V, v, imm((1<<FRAC_BITS)-1));

                // compute width-1 and height-1
                SUB(AL, 0, width,  width,  imm(1));
                SUB(AL, 0, height, height, imm(1));

                // get the integer part of U,V and clamp/wrap
                // and compute offset to the next texel
                if (tmu.swrap == GGL_NEEDS_WRAP_REPEAT) {
                    // u has already been REPEATed
                    MOV(AL, 1, u, reg_imm(u, ASR, FRAC_BITS));
                    MOV(MI, 0, u, width);                    
                    CMP(AL, u, width);
                    MOV(LT, 0, width, imm(1 << shift));
                    if (shift)
                        MOV(GE, 0, width, reg_imm(width, LSL, shift));
                    RSB(GE, 0, width, width, imm(0));
                } else {
                    // u has not been CLAMPed yet
                    // algorithm:
                    // if ((u>>4) >= width)
                    //      u = width<<4
                    //      width = 0
                    // else
                    //      width = 1<<shift
                    // u = u>>4; // get integer part
                    // if (u<0)
                    //      u = 0
                    //      width = 0
                    // generated_vars.rt = width
                    
                    CMP(AL, width, reg_imm(u, ASR, FRAC_BITS));
                    MOV(LE, 0, u, reg_imm(width, LSL, FRAC_BITS));
                    MOV(LE, 0, width, imm(0));
                    MOV(GT, 0, width, imm(1 << shift));
                    MOV(AL, 1, u, reg_imm(u, ASR, FRAC_BITS));
                    MOV(MI, 0, u, imm(0));
                    MOV(MI, 0, width, imm(0));
                }
                CONTEXT_STORE(width, generated_vars.rt);

                const int stride = width;
                CONTEXT_LOAD(stride, generated_vars.texture[i].stride);
                if (tmu.twrap == GGL_NEEDS_WRAP_REPEAT) {
                    // v has already been REPEATed
                    MOV(AL, 1, v, reg_imm(v, ASR, FRAC_BITS));
                    MOV(MI, 0, v, height);
                    CMP(AL, v, height);
                    MOV(LT, 0, height, imm(1 << shift));
                    if (shift)
                        MOV(GE, 0, height, reg_imm(height, LSL, shift));
                    RSB(GE, 0, height, height, imm(0));
                    MUL(AL, 0, height, stride, height);
                } else {
                    // v has not been CLAMPed yet
                    CMP(AL, height, reg_imm(v, ASR, FRAC_BITS));
                    MOV(LE, 0, v, reg_imm(height, LSL, FRAC_BITS));
                    MOV(LE, 0, height, imm(0));
                    if (shift) {
                        MOV(GT, 0, height, reg_imm(stride, LSL, shift));
                    } else {
                        MOV(GT, 0, height, stride);
                    }
                    MOV(AL, 1, v, reg_imm(v, ASR, FRAC_BITS));
                    MOV(MI, 0, v, imm(0));
                    MOV(MI, 0, height, imm(0));
                }
                CONTEXT_STORE(height, generated_vars.lb);
            }
    
            scratches.recycle(width);
            scratches.recycle(height);

            // iterate texture coordinates...
            comment("iterate s,t");
            int dsdx = scratches.obtain();
            int dtdx = scratches.obtain();
            CONTEXT_LOAD(dsdx, generated_vars.texture[i].dsdx);
            CONTEXT_LOAD(dtdx, generated_vars.texture[i].dtdx);
            ADD(AL, 0, s.reg, s.reg, dsdx);
            ADD(AL, 0, t.reg, t.reg, dtdx);
            if ((mOptLevel&1)==0) {
                CONTEXT_STORE(s.reg, generated_vars.texture[i].spill[0]);
                CONTEXT_STORE(t.reg, generated_vars.texture[i].spill[1]);
                scratches.recycle(s.reg);
                scratches.recycle(t.reg);
            }
            scratches.recycle(dsdx);
            scratches.recycle(dtdx);

            // merge base & offset...
            comment("merge base & offset");
            texel.setTo(regs.obtain(), &tmu.format);
            txPtr.setTo(texel.reg, tmu.bits);
            int stride = scratches.obtain();
            CONTEXT_LOAD(stride,    generated_vars.texture[i].stride);
            CONTEXT_LOAD(txPtr.reg, generated_vars.texture[i].data);
            SMLABB(AL, u, v, stride, u);    // u+v*stride 
            base_offset(txPtr, txPtr, u);

            // load texel
            if (!tmu.linear) {
                comment("fetch texel");
                load(txPtr, texel, 0);
            } else {
                // recycle registers we don't need anymore
                scratches.recycle(u);
                scratches.recycle(v);
                scratches.recycle(stride);

                comment("fetch texel, bilinear");
                switch (tmu.format.size) {
                case 1:  filter8(parts, texel, tmu, U, V, txPtr, FRAC_BITS); break;
                case 2: filter16(parts, texel, tmu, U, V, txPtr, FRAC_BITS); break;
                case 3: filter24(parts, texel, tmu, U, V, txPtr, FRAC_BITS); break;
                case 4: filter32(parts, texel, tmu, U, V, txPtr, FRAC_BITS); break;
                }
            }            
        }
    }
}

void GGLAssembler::build_iterate_texture_coordinates(
    const fragment_parts_t& parts)
{
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT; i++) {
        const texture_unit_t& tmu = mTextureMachine.tmu[i];
        if (tmu.format_idx == 0)
            continue;

        if ((tmu.swrap == GGL_NEEDS_WRAP_11) &&
            (tmu.twrap == GGL_NEEDS_WRAP_11))
        { // 1:1 textures
            const pointer_t& txPtr = parts.coords[i].ptr;
            ADD(AL, 0, txPtr.reg, txPtr.reg, imm(txPtr.size>>3));
        } else {
            Scratch scratches(registerFile());
            int s = parts.coords[i].s.reg;
            int t = parts.coords[i].t.reg;
            if ((mOptLevel&1)==0) {
                s = scratches.obtain();
                t = scratches.obtain();
                CONTEXT_LOAD(s, generated_vars.texture[i].spill[0]);
                CONTEXT_LOAD(t, generated_vars.texture[i].spill[1]);
            }
            int dsdx = scratches.obtain();
            int dtdx = scratches.obtain();
            CONTEXT_LOAD(dsdx, generated_vars.texture[i].dsdx);
            CONTEXT_LOAD(dtdx, generated_vars.texture[i].dtdx);
            ADD(AL, 0, s, s, dsdx);
            ADD(AL, 0, t, t, dtdx);
            if ((mOptLevel&1)==0) {
                CONTEXT_STORE(s, generated_vars.texture[i].spill[0]);
                CONTEXT_STORE(t, generated_vars.texture[i].spill[1]);
            }
        }
    }
}

void GGLAssembler::filter8(
        const fragment_parts_t& parts,
        pixel_t& texel, const texture_unit_t& tmu,
        int U, int V, pointer_t& txPtr,
        int FRAC_BITS)
{
    if (tmu.format.components != GGL_ALPHA &&
        tmu.format.components != GGL_LUMINANCE)
    {
        // this is a packed format, and we don't support
        // linear filtering (it's probably RGB 332)
        // Should not happen with OpenGL|ES
        LDRB(AL, texel.reg, txPtr.reg);
        return;
    }

    // ------------------------
    // about ~22 cycles / pixel
    Scratch scratches(registerFile());

    int pixel= scratches.obtain();
    int d    = scratches.obtain();
    int u    = scratches.obtain();
    int k    = scratches.obtain();
    int rt   = scratches.obtain();
    int lb   = scratches.obtain();

    // RB -> U * V

    CONTEXT_LOAD(rt, generated_vars.rt);
    CONTEXT_LOAD(lb, generated_vars.lb);

    int offset = pixel;
    ADD(AL, 0, offset, lb, rt);
    LDRB(AL, pixel, txPtr.reg, reg_scale_pre(offset));
    SMULBB(AL, u, U, V);
    SMULBB(AL, d, pixel, u);
    RSB(AL, 0, k, u, imm(1<<(FRAC_BITS*2)));
    
    // LB -> (1-U) * V
    RSB(AL, 0, U, U, imm(1<<FRAC_BITS));
    LDRB(AL, pixel, txPtr.reg, reg_scale_pre(lb));
    SMULBB(AL, u, U, V);
    SMLABB(AL, d, pixel, u, d);
    SUB(AL, 0, k, k, u);
    
    // LT -> (1-U)*(1-V)
    RSB(AL, 0, V, V, imm(1<<FRAC_BITS));
    LDRB(AL, pixel, txPtr.reg);
    SMULBB(AL, u, U, V);
    SMLABB(AL, d, pixel, u, d);

    // RT -> U*(1-V)
    LDRB(AL, pixel, txPtr.reg, reg_scale_pre(rt));
    SUB(AL, 0, u, k, u);
    SMLABB(AL, texel.reg, pixel, u, d);
    
    for (int i=0 ; i<4 ; i++) {
        if (!texel.format.c[i].h) continue;
        texel.format.c[i].h = FRAC_BITS*2+8;
        texel.format.c[i].l = FRAC_BITS*2; // keeping 8 bits in enough
    }
    texel.format.size = 4;
    texel.format.bitsPerPixel = 32;
    texel.flags |= CLEAR_LO;
}

void GGLAssembler::filter16(
        const fragment_parts_t& parts,
        pixel_t& texel, const texture_unit_t& tmu,
        int U, int V, pointer_t& txPtr,
        int FRAC_BITS)
{    
    // compute the mask
    // XXX: it would be nice if the mask below could be computed
    // automatically.
    uint32_t mask = 0;
    int shift = 0;
    int prec = 0;
    switch (tmu.format_idx) {
        case GGL_PIXEL_FORMAT_RGB_565:
            // source: 00000ggg.ggg00000 | rrrrr000.000bbbbb
            // result: gggggggg.gggrrrrr | rrrrr0bb.bbbbbbbb
            mask = 0x07E0F81F;
            shift = 16;
            prec = 5;
            break;
        case GGL_PIXEL_FORMAT_RGBA_4444:
            // 0000,1111,0000,1111 | 0000,1111,0000,1111
            mask = 0x0F0F0F0F;
            shift = 12;
            prec = 4;
            break;
        case GGL_PIXEL_FORMAT_LA_88:
            // 0000,0000,1111,1111 | 0000,0000,1111,1111
            // AALL -> 00AA | 00LL
            mask = 0x00FF00FF;
            shift = 8;
            prec = 8;
            break;
        default:
            // unsupported format, do something sensical...
            LOGE("Unsupported 16-bits texture format (%d)", tmu.format_idx);
            LDRH(AL, texel.reg, txPtr.reg);
            return;
    }

    const int adjust = FRAC_BITS*2 - prec;
    const int round  = 0;

    // update the texel format
    texel.format.size = 4;
    texel.format.bitsPerPixel = 32;
    texel.flags |= CLEAR_HI|CLEAR_LO;
    for (int i=0 ; i<4 ; i++) {
        if (!texel.format.c[i].h) continue;
        const uint32_t offset = (mask & tmu.format.mask(i)) ? 0 : shift;
        texel.format.c[i].h = tmu.format.c[i].h + offset + prec;
        texel.format.c[i].l = texel.format.c[i].h - (tmu.format.bits(i) + prec);
    }

    // ------------------------
    // about ~40 cycles / pixel
    Scratch scratches(registerFile());

    int pixel= scratches.obtain();
    int d    = scratches.obtain();
    int u    = scratches.obtain();
    int k    = scratches.obtain();

    // RB -> U * V
    int offset = pixel;
    CONTEXT_LOAD(offset, generated_vars.rt);
    CONTEXT_LOAD(u, generated_vars.lb);
    ADD(AL, 0, offset, offset, u);

    LDRH(AL, pixel, txPtr.reg, reg_pre(offset));
    SMULBB(AL, u, U, V);
    ORR(AL, 0, pixel, pixel, reg_imm(pixel, LSL, shift));
    build_and_immediate(pixel, pixel, mask, 32);
    if (adjust) {
        if (round)
            ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MUL(AL, 0, d, pixel, u);
    RSB(AL, 0, k, u, imm(1<<prec));
    
    // LB -> (1-U) * V
    CONTEXT_LOAD(offset, generated_vars.lb);
    RSB(AL, 0, U, U, imm(1<<FRAC_BITS));
    LDRH(AL, pixel, txPtr.reg, reg_pre(offset));
    SMULBB(AL, u, U, V);
    ORR(AL, 0, pixel, pixel, reg_imm(pixel, LSL, shift));
    build_and_immediate(pixel, pixel, mask, 32);
    if (adjust) {
        if (round)
            ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MLA(AL, 0, d, pixel, u, d);
    SUB(AL, 0, k, k, u);
    
    // LT -> (1-U)*(1-V)
    RSB(AL, 0, V, V, imm(1<<FRAC_BITS));
    LDRH(AL, pixel, txPtr.reg);
    SMULBB(AL, u, U, V);
    ORR(AL, 0, pixel, pixel, reg_imm(pixel, LSL, shift));
    build_and_immediate(pixel, pixel, mask, 32);
    if (adjust) {
        if (round)
            ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MLA(AL, 0, d, pixel, u, d);

    // RT -> U*(1-V)            
    CONTEXT_LOAD(offset, generated_vars.rt);
    LDRH(AL, pixel, txPtr.reg, reg_pre(offset));
    SUB(AL, 0, u, k, u);
    ORR(AL, 0, pixel, pixel, reg_imm(pixel, LSL, shift));
    build_and_immediate(pixel, pixel, mask, 32);
    MLA(AL, 0, texel.reg, pixel, u, d);
}

void GGLAssembler::filter24(
        const fragment_parts_t& parts,
        pixel_t& texel, const texture_unit_t& tmu,
        int U, int V, pointer_t& txPtr,
        int FRAC_BITS)
{
    // not supported yet (currently disabled)
    load(txPtr, texel, 0);
}

#if __ARM_ARCH__ >= 6
// ARMv6 version, using UXTB16, and scheduled for Cortex-A8 pipeline
void GGLAssembler::filter32(
        const fragment_parts_t& parts,
        pixel_t& texel, const texture_unit_t& tmu,
        int U, int V, pointer_t& txPtr,
        int FRAC_BITS)
{
    const int adjust = FRAC_BITS*2 - 8;
    const int round  = 0;
    const int prescale = 16 - adjust;

    Scratch scratches(registerFile());
    
    int pixel= scratches.obtain();
    int dh   = scratches.obtain();
    int u    = scratches.obtain();
    int k    = scratches.obtain();

    int temp = scratches.obtain();
    int dl   = scratches.obtain();

    int offsetrt = scratches.obtain();
    int offsetlb = scratches.obtain();

    int pixellb = offsetlb;

    // RB -> U * V
    CONTEXT_LOAD(offsetrt, generated_vars.rt);
    CONTEXT_LOAD(offsetlb, generated_vars.lb);
    if(!round) {
        MOV(AL, 0, U, reg_imm(U, LSL, prescale));
    }
    ADD(AL, 0, u, offsetrt, offsetlb);

    LDR(AL, pixel, txPtr.reg, reg_scale_pre(u));
    if (round) {
        SMULBB(AL, u, U, V);
        RSB(AL, 0, U, U, imm(1<<FRAC_BITS));
    } else {
        SMULWB(AL, u, U, V);
        RSB(AL, 0, U, U, imm(1<<(FRAC_BITS+prescale)));
    }
    UXTB16(AL, temp, pixel, 0);
    if (round) {
        ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    LDR(AL, pixellb, txPtr.reg, reg_scale_pre(offsetlb));
    MUL(AL, 0, dh, temp, u);
    UXTB16(AL, temp, pixel, 8);
    MUL(AL, 0, dl, temp, u);
    RSB(AL, 0, k, u, imm(0x100));

    // LB -> (1-U) * V
    if (round) {
        SMULBB(AL, u, U, V);
    } else {
        SMULWB(AL, u, U, V);
    }
    UXTB16(AL, temp, pixellb, 0);
    if (round) {
        ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MLA(AL, 0, dh, temp, u, dh);    
    UXTB16(AL, temp, pixellb, 8);
    MLA(AL, 0, dl, temp, u, dl);
    SUB(AL, 0, k, k, u);

    // LT -> (1-U)*(1-V)
    RSB(AL, 0, V, V, imm(1<<FRAC_BITS));
    LDR(AL, pixel, txPtr.reg);
    if (round) {
        SMULBB(AL, u, U, V);
    } else {
        SMULWB(AL, u, U, V);
    }
    UXTB16(AL, temp, pixel, 0);
    if (round) {
        ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MLA(AL, 0, dh, temp, u, dh);    
    UXTB16(AL, temp, pixel, 8);
    MLA(AL, 0, dl, temp, u, dl);

    // RT -> U*(1-V)            
    LDR(AL, pixel, txPtr.reg, reg_scale_pre(offsetrt));
    SUB(AL, 0, u, k, u);
    UXTB16(AL, temp, pixel, 0);
    MLA(AL, 0, dh, temp, u, dh);    
    UXTB16(AL, temp, pixel, 8);
    MLA(AL, 0, dl, temp, u, dl);

    UXTB16(AL, dh, dh, 8);
    UXTB16(AL, dl, dl, 8);
    ORR(AL, 0, texel.reg, dh, reg_imm(dl, LSL, 8));
}
#else
void GGLAssembler::filter32(
        const fragment_parts_t& parts,
        pixel_t& texel, const texture_unit_t& tmu,
        int U, int V, pointer_t& txPtr,
        int FRAC_BITS)
{
    const int adjust = FRAC_BITS*2 - 8;
    const int round  = 0;

    // ------------------------
    // about ~38 cycles / pixel
    Scratch scratches(registerFile());
    
    int pixel= scratches.obtain();
    int dh   = scratches.obtain();
    int u    = scratches.obtain();
    int k    = scratches.obtain();

    int temp = scratches.obtain();
    int dl   = scratches.obtain();
    int mask = scratches.obtain();

    MOV(AL, 0, mask, imm(0xFF));
    ORR(AL, 0, mask, mask, imm(0xFF0000));

    // RB -> U * V
    int offset = pixel;
    CONTEXT_LOAD(offset, generated_vars.rt);
    CONTEXT_LOAD(u, generated_vars.lb);
    ADD(AL, 0, offset, offset, u);

    LDR(AL, pixel, txPtr.reg, reg_scale_pre(offset));
    SMULBB(AL, u, U, V);
    AND(AL, 0, temp, mask, pixel);
    if (adjust) {
        if (round)
            ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MUL(AL, 0, dh, temp, u);
    AND(AL, 0, temp, mask, reg_imm(pixel, LSR, 8));
    MUL(AL, 0, dl, temp, u);
    RSB(AL, 0, k, u, imm(0x100));

    // LB -> (1-U) * V
    CONTEXT_LOAD(offset, generated_vars.lb);
    RSB(AL, 0, U, U, imm(1<<FRAC_BITS));
    LDR(AL, pixel, txPtr.reg, reg_scale_pre(offset));
    SMULBB(AL, u, U, V);
    AND(AL, 0, temp, mask, pixel);
    if (adjust) {
        if (round)
            ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MLA(AL, 0, dh, temp, u, dh);    
    AND(AL, 0, temp, mask, reg_imm(pixel, LSR, 8));
    MLA(AL, 0, dl, temp, u, dl);
    SUB(AL, 0, k, k, u);

    // LT -> (1-U)*(1-V)
    RSB(AL, 0, V, V, imm(1<<FRAC_BITS));
    LDR(AL, pixel, txPtr.reg);
    SMULBB(AL, u, U, V);
    AND(AL, 0, temp, mask, pixel);
    if (adjust) {
        if (round)
            ADD(AL, 0, u, u, imm(1<<(adjust-1)));
        MOV(AL, 0, u, reg_imm(u, LSR, adjust));
    }
    MLA(AL, 0, dh, temp, u, dh);    
    AND(AL, 0, temp, mask, reg_imm(pixel, LSR, 8));
    MLA(AL, 0, dl, temp, u, dl);

    // RT -> U*(1-V)            
    CONTEXT_LOAD(offset, generated_vars.rt);
    LDR(AL, pixel, txPtr.reg, reg_scale_pre(offset));
    SUB(AL, 0, u, k, u);
    AND(AL, 0, temp, mask, pixel);
    MLA(AL, 0, dh, temp, u, dh);    
    AND(AL, 0, temp, mask, reg_imm(pixel, LSR, 8));
    MLA(AL, 0, dl, temp, u, dl);

    AND(AL, 0, dh, mask, reg_imm(dh, LSR, 8));
    AND(AL, 0, dl, dl, reg_imm(mask, LSL, 8));
    ORR(AL, 0, texel.reg, dh, dl);
}
#endif

void GGLAssembler::build_texture_environment(
        component_t& fragment,
        const fragment_parts_t& parts,
        int component,
        Scratch& regs)
{
    const uint32_t component_mask = 1<<component;
    const bool multiTexture = mTextureMachine.activeUnits > 1;
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; i++) {
        texture_unit_t& tmu = mTextureMachine.tmu[i];

        if (tmu.mask & component_mask) {
            // replace or modulate with this texture
            if ((tmu.replaced & component_mask) == 0) {
                // not replaced by a later tmu...

                Scratch scratches(registerFile());
                pixel_t texel(parts.texel[i]);
                if (multiTexture && 
                    tmu.swrap == GGL_NEEDS_WRAP_11 &&
                    tmu.twrap == GGL_NEEDS_WRAP_11)
                {
                    texel.reg = scratches.obtain();
                    texel.flags |= CORRUPTIBLE;
                    comment("fetch texel (multitexture 1:1)");
                    load(parts.coords[i].ptr, texel, WRITE_BACK);
                 }

                component_t incoming(fragment);
                modify(fragment, regs);
                
                switch (tmu.env) {
                case GGL_REPLACE:
                    extract(fragment, texel, component);
                    break;
                case GGL_MODULATE:
                    modulate(fragment, incoming, texel, component);
                    break;
                case GGL_DECAL:
                    decal(fragment, incoming, texel, component);
                    break;
                case GGL_BLEND:
                    blend(fragment, incoming, texel, component, i);
                    break;
                case GGL_ADD:
                    add(fragment, incoming, texel, component);
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::wrapping(
            int d,
            int coord, int size,
            int tx_wrap, int tx_linear)
{
    // notes:
    // if tx_linear is set, we need 4 extra bits of precision on the result
    // SMULL/UMULL is 3 cycles
    Scratch scratches(registerFile());
    int c = coord;
    if (tx_wrap == GGL_NEEDS_WRAP_REPEAT) {
        // UMULL takes 4 cycles (interlocked), and we can get away with
        // 2 cycles using SMULWB, but we're loosing 16 bits of precision
        // out of 32 (this is not a problem because the iterator keeps
        // its full precision)
        // UMULL(AL, 0, size, d, c, size);
        // note: we can't use SMULTB because it's signed.
        MOV(AL, 0, d, reg_imm(c, LSR, 16-tx_linear));
        SMULWB(AL, d, d, size);
    } else if (tx_wrap == GGL_NEEDS_WRAP_CLAMP_TO_EDGE) {
        if (tx_linear) {
            // 1 cycle
            MOV(AL, 0, d, reg_imm(coord, ASR, 16-tx_linear));
        } else {
            // 4 cycles (common case)
            MOV(AL, 0, d, reg_imm(coord, ASR, 16));
            BIC(AL, 0, d, d, reg_imm(d, ASR, 31));
            CMP(AL, d, size);
            SUB(GE, 0, d, size, imm(1));
        }
    }
}

// ---------------------------------------------------------------------------

void GGLAssembler::modulate(
        component_t& dest, 
        const component_t& incoming,
        const pixel_t& incomingTexel, int component)
{
    Scratch locals(registerFile());
    integer_t texel(locals.obtain(), 32, CORRUPTIBLE);            
    extract(texel, incomingTexel, component);

    const int Nt = texel.size();
        // Nt should always be less than 10 bits because it comes
        // from the TMU.

    int Ni = incoming.size();
        // Ni could be big because it comes from previous MODULATEs

    if (Nt == 1) {
        // texel acts as a bit-mask
        // dest = incoming & ((texel << incoming.h)-texel)
        RSB(AL, 0, dest.reg, texel.reg, reg_imm(texel.reg, LSL, incoming.h));
        AND(AL, 0, dest.reg, dest.reg, incoming.reg);
        dest.l = incoming.l;
        dest.h = incoming.h;
        dest.flags |= (incoming.flags & CLEAR_LO);
    } else if (Ni == 1) {
        MOV(AL, 0, dest.reg, reg_imm(incoming.reg, LSL, 31-incoming.h));
        AND(AL, 0, dest.reg, texel.reg, reg_imm(dest.reg, ASR, 31));
        dest.l = 0;
        dest.h = Nt;
    } else {
        int inReg = incoming.reg;
        int shift = incoming.l;
        if ((Nt + Ni) > 32) {
            // we will overflow, reduce the precision of Ni to 8 bits
            // (Note Nt cannot be more than 10 bits which happens with 
            // 565 textures and GGL_LINEAR)
            shift += Ni-8;
            Ni = 8;
        }

        // modulate by the component with the lowest precision
        if (Nt >= Ni) {
            if (shift) {
                // XXX: we should be able to avoid this shift
                // when shift==16 && Nt<16 && Ni<16, in which
                // we could use SMULBT below.
                MOV(AL, 0, dest.reg, reg_imm(inReg, LSR, shift));
                inReg = dest.reg;
                shift = 0;
            }
            // operation:           (Cf*Ct)/((1<<Ni)-1)
            // approximated with:   Cf*(Ct + Ct>>(Ni-1))>>Ni
            // this operation doesn't change texel's size
            ADD(AL, 0, dest.reg, inReg, reg_imm(inReg, LSR, Ni-1));
            if (Nt<16 && Ni<16) SMULBB(AL, dest.reg, texel.reg, dest.reg);
            else                MUL(AL, 0, dest.reg, texel.reg, dest.reg);
            dest.l = Ni;
            dest.h = Nt + Ni;            
        } else {
            if (shift && (shift != 16)) {
                // if shift==16, we can use 16-bits mul instructions later
                MOV(AL, 0, dest.reg, reg_imm(inReg, LSR, shift));
                inReg = dest.reg;
                shift = 0;
            }
            // operation:           (Cf*Ct)/((1<<Nt)-1)
            // approximated with:   Ct*(Cf + Cf>>(Nt-1))>>Nt
            // this operation doesn't change incoming's size
            Scratch scratches(registerFile());
            int t = (texel.flags & CORRUPTIBLE) ? texel.reg : dest.reg;
            if (t == inReg)
                t = scratches.obtain();
            ADD(AL, 0, t, texel.reg, reg_imm(texel.reg, LSR, Nt-1));
            if (Nt<16 && Ni<16) {
                if (shift==16)  SMULBT(AL, dest.reg, t, inReg);
                else            SMULBB(AL, dest.reg, t, inReg);
            } else              MUL(AL, 0, dest.reg, t, inReg);
            dest.l = Nt;
            dest.h = Nt + Ni;
        }

        // low bits are not valid
        dest.flags |= CLEAR_LO;

        // no need to keep more than 8 bits/component
        if (dest.size() > 8)
            dest.l = dest.h-8;
    }
}

void GGLAssembler::decal(
        component_t& dest, 
        const component_t& incoming,
        const pixel_t& incomingTexel, int component)
{
    // RGBA:
    // Cv = Cf*(1 - At) + Ct*At = Cf + (Ct - Cf)*At
    // Av = Af
    Scratch locals(registerFile());
    integer_t texel(locals.obtain(), 32, CORRUPTIBLE);            
    integer_t factor(locals.obtain(), 32, CORRUPTIBLE);
    extract(texel, incomingTexel, component);
    extract(factor, incomingTexel, GGLFormat::ALPHA);

    // no need to keep more than 8-bits for decal 
    int Ni = incoming.size();
    int shift = incoming.l;
    if (Ni > 8) {
        shift += Ni-8;
        Ni = 8;
    }
    integer_t incomingNorm(incoming.reg, Ni, incoming.flags);
    if (shift) {
        MOV(AL, 0, dest.reg, reg_imm(incomingNorm.reg, LSR, shift));
        incomingNorm.reg = dest.reg;
        incomingNorm.flags |= CORRUPTIBLE;
    }
    ADD(AL, 0, factor.reg, factor.reg, reg_imm(factor.reg, LSR, factor.s-1));
    build_blendOneMinusFF(dest, factor, incomingNorm, texel);
}

void GGLAssembler::blend(
        component_t& dest, 
        const component_t& incoming,
        const pixel_t& incomingTexel, int component, int tmu)
{
    // RGBA:
    // Cv = (1 - Ct)*Cf + Ct*Cc = Cf + (Cc - Cf)*Ct
    // Av = At*Af

    if (component == GGLFormat::ALPHA) {
        modulate(dest, incoming, incomingTexel, component);
        return;
    }
    
    Scratch locals(registerFile());
    integer_t color(locals.obtain(), 8, CORRUPTIBLE);            
    integer_t factor(locals.obtain(), 32, CORRUPTIBLE);
    LDRB(AL, color.reg, mBuilderContext.Rctx,
            immed12_pre(GGL_OFFSETOF(state.texture[tmu].env_color[component])));
    extract(factor, incomingTexel, component);

    // no need to keep more than 8-bits for blend 
    int Ni = incoming.size();
    int shift = incoming.l;
    if (Ni > 8) {
        shift += Ni-8;
        Ni = 8;
    }
    integer_t incomingNorm(incoming.reg, Ni, incoming.flags);
    if (shift) {
        MOV(AL, 0, dest.reg, reg_imm(incomingNorm.reg, LSR, shift));
        incomingNorm.reg = dest.reg;
        incomingNorm.flags |= CORRUPTIBLE;
    }
    ADD(AL, 0, factor.reg, factor.reg, reg_imm(factor.reg, LSR, factor.s-1));
    build_blendOneMinusFF(dest, factor, incomingNorm, color);
}

void GGLAssembler::add(
        component_t& dest, 
        const component_t& incoming,
        const pixel_t& incomingTexel, int component)
{
    // RGBA:
    // Cv = Cf + Ct;
    Scratch locals(registerFile());
    
    component_t incomingTemp(incoming);

    // use "dest" as a temporary for extracting the texel, unless "dest"
    // overlaps "incoming".
    integer_t texel(dest.reg, 32, CORRUPTIBLE);
    if (dest.reg == incomingTemp.reg)
        texel.reg = locals.obtain();
    extract(texel, incomingTexel, component);

    if (texel.s < incomingTemp.size()) {
        expand(texel, texel, incomingTemp.size());
    } else if (texel.s > incomingTemp.size()) {
        if (incomingTemp.flags & CORRUPTIBLE) {
            expand(incomingTemp, incomingTemp, texel.s);
        } else {
            incomingTemp.reg = locals.obtain();
            expand(incomingTemp, incoming, texel.s);
        }
    }

    if (incomingTemp.l) {
        ADD(AL, 0, dest.reg, texel.reg,
                reg_imm(incomingTemp.reg, LSR, incomingTemp.l));
    } else {
        ADD(AL, 0, dest.reg, texel.reg, incomingTemp.reg);
    }
    dest.l = 0;
    dest.h = texel.size();
    component_sat(dest);
}

// ----------------------------------------------------------------------------

}; // namespace android

