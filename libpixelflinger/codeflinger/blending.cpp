/* libs/pixelflinger/codeflinger/blending.cpp
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

#define LOG_TAG "pixelflinger-code"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <android-base/macros.h>
#include <log/log.h>

#include "GGLAssembler.h"

namespace android {

void GGLAssembler::build_fog(
                        component_t& temp,      // incomming fragment / output
                        int component,
                        Scratch& regs)
{
   if (mInfo[component].fog) {
        Scratch scratches(registerFile());
        comment("fog");

        integer_t fragment(temp.reg, temp.h, temp.flags);
        if (!(temp.flags & CORRUPTIBLE)) {
            temp.reg = regs.obtain();
            temp.flags |= CORRUPTIBLE;
        }

        integer_t fogColor(scratches.obtain(), 8, CORRUPTIBLE); 
        LDRB(AL, fogColor.reg, mBuilderContext.Rctx,
                immed12_pre(GGL_OFFSETOF(state.fog.color[component])));

        integer_t factor(scratches.obtain(), 16, CORRUPTIBLE);
        CONTEXT_LOAD(factor.reg, generated_vars.f);

        // clamp fog factor (TODO: see if there is a way to guarantee
        // we won't overflow, when setting the iterators)
        BIC(AL, 0, factor.reg, factor.reg, reg_imm(factor.reg, ASR, 31));
        CMP(AL, factor.reg, imm( 0x10000 ));
        MOV(HS, 0, factor.reg, imm( 0x10000 ));

        build_blendFOneMinusF(temp, factor, fragment, fogColor);
    }
}

void GGLAssembler::build_blending(
                        component_t& temp,      // incomming fragment / output
                        const pixel_t& pixel,   // framebuffer
                        int component,
                        Scratch& regs)
{
   if (!mInfo[component].blend)
        return;
        
    int fs = component==GGLFormat::ALPHA ? mBlendSrcA : mBlendSrc;
    int fd = component==GGLFormat::ALPHA ? mBlendDstA : mBlendDst;
    if (fs==GGL_SRC_ALPHA_SATURATE && component==GGLFormat::ALPHA)
        fs = GGL_ONE;
    const int blending = blending_codes(fs, fd);
    if (!temp.size()) {
        // here, blending will produce something which doesn't depend on
        // that component (eg: GL_ZERO:GL_*), so the register has not been
        // allocated yet. Will never be used as a source.
        temp = component_t(regs.obtain(), CORRUPTIBLE);
    }

    // we are doing real blending...
    // fb:          extracted dst
    // fragment:    extracted src
    // temp:        component_t(fragment) and result

    // scoped register allocator
    Scratch scratches(registerFile());
    comment("blending");

    // we can optimize these cases a bit...
    // (1) saturation is not needed
    // (2) we can use only one multiply instead of 2
    // (3) we can reduce the register pressure
    //      R = S*f + D*(1-f) = (S-D)*f + D
    //      R = S*(1-f) + D*f = (D-S)*f + S

    const bool same_factor_opt1 =
        (fs==GGL_DST_COLOR && fd==GGL_ONE_MINUS_DST_COLOR) ||
        (fs==GGL_SRC_COLOR && fd==GGL_ONE_MINUS_SRC_COLOR) ||
        (fs==GGL_DST_ALPHA && fd==GGL_ONE_MINUS_DST_ALPHA) ||
        (fs==GGL_SRC_ALPHA && fd==GGL_ONE_MINUS_SRC_ALPHA);

    const bool same_factor_opt2 =
        (fs==GGL_ONE_MINUS_DST_COLOR && fd==GGL_DST_COLOR) ||
        (fs==GGL_ONE_MINUS_SRC_COLOR && fd==GGL_SRC_COLOR) || 
        (fs==GGL_ONE_MINUS_DST_ALPHA && fd==GGL_DST_ALPHA) ||
        (fs==GGL_ONE_MINUS_SRC_ALPHA && fd==GGL_SRC_ALPHA);


    // XXX: we could also optimize these cases:
    // R = S*f + D*f = (S+D)*f
    // R = S*(1-f) + D*(1-f) = (S+D)*(1-f)
    // R = S*D + D*S = 2*S*D


    // see if we need to extract 'component' from the destination (fb)
    integer_t fb;
    if (blending & (BLEND_DST|FACTOR_DST)) { 
        fb.setTo(scratches.obtain(), 32); 
        extract(fb, pixel, component);
        if (mDithering) {
            // XXX: maybe what we should do instead, is simply
            // expand fb -or- fragment to the larger of the two
            if (fb.size() < temp.size()) {
                // for now we expand 'fb' to min(fragment, 8)
                int new_size = temp.size() < 8 ? temp.size() : 8;
                expand(fb, fb, new_size);
            }
        }
    }


    // convert input fragment to integer_t
    if (temp.l && (temp.flags & CORRUPTIBLE)) {
        MOV(AL, 0, temp.reg, reg_imm(temp.reg, LSR, temp.l));
        temp.h -= temp.l;
        temp.l = 0;
    }
    integer_t fragment(temp.reg, temp.size(), temp.flags);

    // if not done yet, convert input fragment to integer_t
    if (temp.l) {
        // here we know temp is not CORRUPTIBLE
        fragment.reg = scratches.obtain();
        MOV(AL, 0, fragment.reg, reg_imm(temp.reg, LSR, temp.l));
        fragment.flags |= CORRUPTIBLE;
    }

    if (!(temp.flags & CORRUPTIBLE)) {
        // temp is not corruptible, but since it's the destination it
        // will be modified, so we need to allocate a new register.
        temp.reg = regs.obtain();
        temp.flags &= ~CORRUPTIBLE;
        fragment.flags &= ~CORRUPTIBLE;
    }

    if ((blending & BLEND_SRC) && !same_factor_opt1) {
        // source (fragment) is needed for the blending stage
        // so it's not CORRUPTIBLE (unless we're doing same_factor_opt1)
        fragment.flags &= ~CORRUPTIBLE;
    }


    if (same_factor_opt1) {
        //  R = S*f + D*(1-f) = (S-D)*f + D
        integer_t factor;
        build_blend_factor(factor, fs, 
                component, pixel, fragment, fb, scratches);
        // fb is always corruptible from this point
        fb.flags |= CORRUPTIBLE;
        build_blendFOneMinusF(temp, factor, fragment, fb);
    } else if (same_factor_opt2) {
        //  R = S*(1-f) + D*f = (D-S)*f + S
        integer_t factor;
        // fb is always corrruptible here
        fb.flags |= CORRUPTIBLE;
        build_blend_factor(factor, fd,
                component, pixel, fragment, fb, scratches);
        build_blendOneMinusFF(temp, factor, fragment, fb);
    } else {
        integer_t src_factor;
        integer_t dst_factor;

        // if destination (fb) is not needed for the blending stage, 
        // then it can be marked as CORRUPTIBLE
        if (!(blending & BLEND_DST)) {
            fb.flags |= CORRUPTIBLE;
        }

        // XXX: try to mark some registers as CORRUPTIBLE
        // in most case we could make those corruptible
        // when we're processing the last component
        // but not always, for instance
        //    when fragment is constant and not reloaded
        //    when fb is needed for logic-ops or masking
        //    when a register is aliased (for instance with mAlphaSource)

        // blend away...
        if (fs==GGL_ZERO) {
            if (fd==GGL_ZERO) {         // R = 0
                // already taken care of
            } else if (fd==GGL_ONE) {   // R = D
                // already taken care of
            } else {                    // R = D*fd
                // compute fd
                build_blend_factor(dst_factor, fd,
                        component, pixel, fragment, fb, scratches);
                mul_factor(temp, fb, dst_factor);
            }
        } else if (fs==GGL_ONE) {
            if (fd==GGL_ZERO) {         // R = S
                // NOP, taken care of
            } else if (fd==GGL_ONE) {   // R = S + D
                component_add(temp, fb, fragment); // args order matters
                component_sat(temp);
            } else {                    // R = S + D*fd
                // compute fd
                build_blend_factor(dst_factor, fd,
                        component, pixel, fragment, fb, scratches);
                mul_factor_add(temp, fb, dst_factor, component_t(fragment));
                component_sat(temp);
            }
        } else {
            // compute fs
            build_blend_factor(src_factor, fs, 
                    component, pixel, fragment, fb, scratches);
            if (fd==GGL_ZERO) {         // R = S*fs
                mul_factor(temp, fragment, src_factor);
            } else if (fd==GGL_ONE) {   // R = S*fs + D
                mul_factor_add(temp, fragment, src_factor, component_t(fb));
                component_sat(temp);
            } else {                    // R = S*fs + D*fd
                mul_factor(temp, fragment, src_factor);
                if (scratches.isUsed(src_factor.reg))
                    scratches.recycle(src_factor.reg);
                // compute fd
                build_blend_factor(dst_factor, fd,
                        component, pixel, fragment, fb, scratches);
                mul_factor_add(temp, fb, dst_factor, temp);
                if (!same_factor_opt1 && !same_factor_opt2) {
                    component_sat(temp);
                }
            }
        }
    }

    // now we can be corrupted (it's the dest)
    temp.flags |= CORRUPTIBLE;
}

void GGLAssembler::build_blend_factor(
        integer_t& factor, int f, int component,
        const pixel_t& dst_pixel,
        integer_t& fragment,
        integer_t& fb,
        Scratch& scratches)
{
    integer_t src_alpha(fragment);

    // src_factor/dst_factor won't be used after blending,
    // so it's fine to mark them as CORRUPTIBLE (if not aliased)
    factor.flags |= CORRUPTIBLE;

    switch(f) {
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
        if (component==GGLFormat::ALPHA && !isAlphaSourceNeeded()) {
            // we're processing alpha, so we already have
            // src-alpha in fragment, and we need src-alpha just this time.
        } else {
           // alpha-src will be needed for other components
            if (!mBlendFactorCached || mBlendFactorCached==f) {
                src_alpha = mAlphaSource;
                factor = mAlphaSource;
                factor.flags &= ~CORRUPTIBLE;           
                // we already computed the blend factor before, nothing to do.
                if (mBlendFactorCached)
                    return;
                // this is the first time, make sure to compute the blend
                // factor properly.
                mBlendFactorCached = f;
                break;
            } else {
                // we have a cached alpha blend factor, but we want another one,
                // this should really not happen because by construction,
                // we cannot have BOTH source and destination
                // blend factors use ALPHA *and* ONE_MINUS_ALPHA (because
                // the blending stage uses the f/(1-f) optimization
                
                // for completeness, we handle this case though. Since there
                // are only 2 choices, this meens we want "the other one"
                // (1-factor)
                factor = mAlphaSource;
                factor.flags &= ~CORRUPTIBLE;           
                RSB(AL, 0, factor.reg, factor.reg, imm((1<<factor.s)));
                mBlendFactorCached = f;
                return;
            }                
        }
        FALLTHROUGH_INTENDED;
    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
    case GGL_SRC_ALPHA_SATURATE:
        // help us find out what register we can use for the blend-factor
        // CORRUPTIBLE registers are chosen first, or a new one is allocated.
        if (fragment.flags & CORRUPTIBLE) {
            factor.setTo(fragment.reg, 32, CORRUPTIBLE);
            fragment.flags &= ~CORRUPTIBLE;
        } else if (fb.flags & CORRUPTIBLE) {
            factor.setTo(fb.reg, 32, CORRUPTIBLE);
            fb.flags &= ~CORRUPTIBLE;
        } else {
            factor.setTo(scratches.obtain(), 32, CORRUPTIBLE);
        } 
        break;
    }

    // XXX: doesn't work if size==1

    switch(f) {
    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
        factor.s = fb.s;
        ADD(AL, 0, factor.reg, fb.reg, reg_imm(fb.reg, LSR, fb.s-1));
        break;
    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:
        factor.s = fragment.s;
        ADD(AL, 0, factor.reg, fragment.reg,
            reg_imm(fragment.reg, LSR, fragment.s-1));
        break;
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
        factor.s = src_alpha.s;
        ADD(AL, 0, factor.reg, src_alpha.reg,
                reg_imm(src_alpha.reg, LSR, src_alpha.s-1));
        break;
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
        // XXX: should be precomputed
        extract(factor, dst_pixel, GGLFormat::ALPHA);
        ADD(AL, 0, factor.reg, factor.reg,
                reg_imm(factor.reg, LSR, factor.s-1));
        break;
    case GGL_SRC_ALPHA_SATURATE:
        // XXX: should be precomputed
        // XXX: f = min(As, 1-Ad)
        // btw, we're guaranteed that Ad's size is <= 8, because
        // it's extracted from the framebuffer
        break;
    }

    switch(f) {
    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_ONE_MINUS_SRC_ALPHA:
        RSB(AL, 0, factor.reg, factor.reg, imm((1<<factor.s)));
    }
    
    // don't need more than 8-bits for the blend factor
    // and this will prevent overflows in the multiplies later
    if (factor.s > 8) {
        MOV(AL, 0, factor.reg, reg_imm(factor.reg, LSR, factor.s-8));
        factor.s = 8;
    }
}

int GGLAssembler::blending_codes(int fs, int fd)
{
    int blending = 0;
    switch(fs) {
    case GGL_ONE:
        blending |= BLEND_SRC;
        break;

    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
        blending |= FACTOR_DST|BLEND_SRC;
        break;
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
        // no need to extract 'component' from the destination
        // for the blend factor, because we need ALPHA only.
        blending |= BLEND_SRC;
        break;

    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:    
        blending |= FACTOR_SRC|BLEND_SRC;
        break;
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
    case GGL_SRC_ALPHA_SATURATE:
        blending |= FACTOR_SRC|BLEND_SRC;
        break;
    }
    switch(fd) {
    case GGL_ONE:
        blending |= BLEND_DST;
        break;

    case GGL_ONE_MINUS_DST_COLOR:
    case GGL_DST_COLOR:
        blending |= FACTOR_DST|BLEND_DST;
        break;
    case GGL_ONE_MINUS_DST_ALPHA:
    case GGL_DST_ALPHA:
        blending |= FACTOR_DST|BLEND_DST;
        break;

    case GGL_ONE_MINUS_SRC_COLOR:
    case GGL_SRC_COLOR:    
        blending |= FACTOR_SRC|BLEND_DST;
        break;
    case GGL_ONE_MINUS_SRC_ALPHA:
    case GGL_SRC_ALPHA:
        // no need to extract 'component' from the source
        // for the blend factor, because we need ALPHA only.
        blending |= BLEND_DST;
        break;
    }
    return blending;
}

// ---------------------------------------------------------------------------

void GGLAssembler::build_blendFOneMinusF(
        component_t& temp,
        const integer_t& factor, 
        const integer_t& fragment,
        const integer_t& fb)
{
    //  R = S*f + D*(1-f) = (S-D)*f + D
    Scratch scratches(registerFile());
    // compute S-D
    integer_t diff(fragment.flags & CORRUPTIBLE ?
            fragment.reg : scratches.obtain(), fb.size(), CORRUPTIBLE);
    const int shift = fragment.size() - fb.size();
    if (shift>0)        RSB(AL, 0, diff.reg, fb.reg, reg_imm(fragment.reg, LSR, shift));
    else if (shift<0)   RSB(AL, 0, diff.reg, fb.reg, reg_imm(fragment.reg, LSL,-shift));
    else                RSB(AL, 0, diff.reg, fb.reg, fragment.reg);
    mul_factor_add(temp, diff, factor, component_t(fb));
}

void GGLAssembler::build_blendOneMinusFF(
        component_t& temp,
        const integer_t& factor, 
        const integer_t& fragment,
        const integer_t& fb)
{
    //  R = S*f + D*(1-f) = (S-D)*f + D
    Scratch scratches(registerFile());
    // compute D-S
    integer_t diff(fb.flags & CORRUPTIBLE ?
            fb.reg : scratches.obtain(), fb.size(), CORRUPTIBLE);
    const int shift = fragment.size() - fb.size();
    if (shift>0)        SUB(AL, 0, diff.reg, fb.reg, reg_imm(fragment.reg, LSR, shift));
    else if (shift<0)   SUB(AL, 0, diff.reg, fb.reg, reg_imm(fragment.reg, LSL,-shift));
    else                SUB(AL, 0, diff.reg, fb.reg, fragment.reg);
    mul_factor_add(temp, diff, factor, component_t(fragment));
}

// ---------------------------------------------------------------------------

void GGLAssembler::mul_factor(  component_t& d,
                                const integer_t& v,
                                const integer_t& f)
{
    int vs = v.size();
    int fs = f.size();
    int ms = vs+fs;

    // XXX: we could have special cases for 1 bit mul

    // all this code below to use the best multiply instruction
    // wrt the parameters size. We take advantage of the fact
    // that the 16-bits multiplies allow a 16-bit shift
    // The trick is that we just make sure that we have at least 8-bits
    // per component (which is enough for a 8 bits display).

    int xy;
    int vshift = 0;
    int fshift = 0;
    int smulw = 0;

    if (vs<16) {
        if (fs<16) {
            xy = xyBB;
        } else if (GGL_BETWEEN(fs, 24, 31)) {
            ms -= 16;
            xy = xyTB;
        } else {
            // eg: 15 * 18  ->  15 * 15
            fshift = fs - 15;
            ms -= fshift;
            xy = xyBB;
        }
    } else if (GGL_BETWEEN(vs, 24, 31)) {
        if (fs<16) {
            ms -= 16;
            xy = xyTB;
        } else if (GGL_BETWEEN(fs, 24, 31)) {
            ms -= 32;
            xy = xyTT;
        } else {
            // eg: 24 * 18  ->  8 * 18
            fshift = fs - 15;
            ms -= 16 + fshift;
            xy = xyTB;
        }
    } else {
        if (fs<16) {
            // eg: 18 * 15  ->  15 * 15
            vshift = vs - 15;
            ms -= vshift;
            xy = xyBB;
        } else if (GGL_BETWEEN(fs, 24, 31)) {
            // eg: 18 * 24  ->  15 * 8
            vshift = vs - 15;
            ms -= 16 + vshift;
            xy = xyBT;
        } else {
            // eg: 18 * 18  ->  (15 * 18)>>16
            fshift = fs - 15;
            ms -= 16 + fshift;
            xy = yB;    //XXX SMULWB
            smulw = 1;
        }
    }

    ALOGE_IF(ms>=32, "mul_factor overflow vs=%d, fs=%d", vs, fs);

    int vreg = v.reg;
    int freg = f.reg;
    if (vshift) {
        MOV(AL, 0, d.reg, reg_imm(vreg, LSR, vshift));
        vreg = d.reg;
    }
    if (fshift) {
        MOV(AL, 0, d.reg, reg_imm(vreg, LSR, fshift));
        freg = d.reg;
    }
    if (smulw)  SMULW(AL, xy, d.reg, vreg, freg);
    else        SMUL(AL, xy, d.reg, vreg, freg);


    d.h = ms;
    if (mDithering) {
        d.l = 0; 
    } else {
        d.l = fs; 
        d.flags |= CLEAR_LO;
    }
}

void GGLAssembler::mul_factor_add(  component_t& d,
                                    const integer_t& v,
                                    const integer_t& f,
                                    const component_t& a)
{
    // XXX: we could have special cases for 1 bit mul
    Scratch scratches(registerFile());

    int vs = v.size();
    int fs = f.size();
    int as = a.h;
    int ms = vs+fs;

    ALOGE_IF(ms>=32, "mul_factor_add overflow vs=%d, fs=%d, as=%d", vs, fs, as);

    integer_t add(a.reg, a.h, a.flags);

    // 'a' is a component_t but it is guaranteed to have
    // its high bits set to 0. However in the dithering case,
    // we can't get away with truncating the potentially bad bits
    // so extraction is needed.

   if ((mDithering) && (a.size() < ms)) {
        // we need to expand a
        if (!(a.flags & CORRUPTIBLE)) {
            // ... but it's not corruptible, so we need to pick a
            // temporary register.
            // Try to uses the destination register first (it's likely
            // to be usable, unless it aliases an input).
            if (d.reg!=a.reg && d.reg!=v.reg && d.reg!=f.reg) {
                add.reg = d.reg;
            } else {
                add.reg = scratches.obtain();
            }
        }
        expand(add, a, ms); // extracts and expands
        as = ms;
    }

    if (ms == as) {
        if (vs<16 && fs<16) SMLABB(AL, d.reg, v.reg, f.reg, add.reg);
        else                MLA(AL, 0, d.reg, v.reg, f.reg, add.reg);
    } else {
        int temp = d.reg;
        if (temp == add.reg) {
            // the mul will modify add.reg, we need an intermediary reg
            if (v.flags & CORRUPTIBLE)      temp = v.reg;
            else if (f.flags & CORRUPTIBLE) temp = f.reg;
            else                            temp = scratches.obtain();
        }

        if (vs<16 && fs<16) SMULBB(AL, temp, v.reg, f.reg);
        else                MUL(AL, 0, temp, v.reg, f.reg);

        if (ms>as) {
            ADD(AL, 0, d.reg, temp, reg_imm(add.reg, LSL, ms-as));
        } else if (ms<as) {
            // not sure if we should expand the mul instead?
            ADD(AL, 0, d.reg, temp, reg_imm(add.reg, LSR, as-ms));
        }
    }

    d.h = ms;
    if (mDithering) {
        d.l = a.l; 
    } else {
        d.l = fs>a.l ? fs : a.l;
        d.flags |= CLEAR_LO;
    }
}

void GGLAssembler::component_add(component_t& d,
        const integer_t& dst, const integer_t& src)
{
    // here we're guaranteed that fragment.size() >= fb.size()
    const int shift = src.size() - dst.size();
    if (!shift) {
        ADD(AL, 0, d.reg, src.reg, dst.reg);
    } else {
        ADD(AL, 0, d.reg, src.reg, reg_imm(dst.reg, LSL, shift));
    }

    d.h = src.size();
    if (mDithering) {
        d.l = 0;
    } else {
        d.l = shift;
        d.flags |= CLEAR_LO;
    }
}

void GGLAssembler::component_sat(const component_t& v)
{
    const int one = ((1<<v.size())-1)<<v.l;
    CMP(AL, v.reg, imm( 1<<v.h ));
    if (isValidImmediate(one)) {
        MOV(HS, 0, v.reg, imm( one ));
    } else if (isValidImmediate(~one)) {
        MVN(HS, 0, v.reg, imm( ~one ));
    } else {
        MOV(HS, 0, v.reg, imm( 1<<v.h ));
        SUB(HS, 0, v.reg, v.reg, imm( 1<<v.l ));
    }
}

// ----------------------------------------------------------------------------

}; // namespace android

