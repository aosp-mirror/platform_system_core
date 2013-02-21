/* libs/pixelflinger/codeflinger/GGLAssembler.h
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


#ifndef ANDROID_GGLASSEMBLER_H
#define ANDROID_GGLASSEMBLER_H

#include <stdint.h>
#include <sys/types.h>

#include <private/pixelflinger/ggl_context.h>

#include "ARMAssemblerProxy.h"


namespace android {

// ----------------------------------------------------------------------------

#define CONTEXT_ADDR_LOAD(REG, FIELD) \
    ADDR_LDR(AL, REG, mBuilderContext.Rctx, immed12_pre(GGL_OFFSETOF(FIELD)))

#define CONTEXT_ADDR_STORE(REG, FIELD) \
    ADDR_STR(AL, REG, mBuilderContext.Rctx, immed12_pre(GGL_OFFSETOF(FIELD)))

#define CONTEXT_LOAD(REG, FIELD) \
    LDR(AL, REG, mBuilderContext.Rctx, immed12_pre(GGL_OFFSETOF(FIELD)))

#define CONTEXT_STORE(REG, FIELD) \
    STR(AL, REG, mBuilderContext.Rctx, immed12_pre(GGL_OFFSETOF(FIELD)))


class RegisterAllocator
{
public:
    class RegisterFile;
    
                    RegisterAllocator(int arch);
    RegisterFile&   registerFile();
    int             reserveReg(int reg);
    int             obtainReg();
    void            recycleReg(int reg);
    void            reset();

    class RegisterFile
    {
    public:
                            RegisterFile(int arch);
                            RegisterFile(const RegisterFile& rhs, int arch);
                            ~RegisterFile();

                void        reset();

                bool operator == (const RegisterFile& rhs) const;
                bool operator != (const RegisterFile& rhs) const {
                    return !operator == (rhs);
                }

                int         reserve(int reg);
                void        reserveSeveral(uint32_t regMask);

                void        recycle(int reg);
                void        recycleSeveral(uint32_t regMask);

                int         obtain();
        inline  int         isUsed(int reg) const;

                bool        hasFreeRegs() const;
                int         countFreeRegs() const;                

                uint32_t    touched() const;
        inline  uint32_t    status() const { return mStatus; }
        
        enum {
            OUT_OF_REGISTERS = 0x1
        };

    private:
        uint32_t    mRegs;
        uint32_t    mTouched;
        uint32_t    mStatus;
        int         mArch;
        uint32_t    mRegisterOffset;    // lets reg alloc use 2..17 for mips
                                        // while arm uses 0..15
    };
 
    class Scratch
    {
    public:
            Scratch(RegisterFile& regFile)
                : mRegFile(regFile), mScratch(0) { 
            }
            ~Scratch() {
                mRegFile.recycleSeveral(mScratch);
            }
        int obtain() { 
            int reg = mRegFile.obtain();
            mScratch |= 1<<reg;
            return reg;
        }
        void recycle(int reg) {
            mRegFile.recycle(reg);
            mScratch &= ~(1<<reg);
        }
        bool isUsed(int reg) {
            return (mScratch & (1<<reg));
        }
        int countFreeRegs() {
            return mRegFile.countFreeRegs();
        }
    private:
        RegisterFile&   mRegFile;
        uint32_t        mScratch;
    };

    class Spill
    {
    public:
        Spill(RegisterFile& regFile, ARMAssemblerInterface& gen, uint32_t reglist)
            : mRegFile(regFile), mGen(gen), mRegList(reglist), mCount(0)
        {
            if (reglist) {
                int count = 0;
                while (reglist) {
                    count++;
                    reglist &= ~(1 << (31 - __builtin_clz(reglist)));
                }
                if (count == 1) {
                    int reg = 31 - __builtin_clz(mRegList);
                    mGen.STR(mGen.AL, reg, mGen.SP, mGen.immed12_pre(-4, 1));
                } else {
                    mGen.STM(mGen.AL, mGen.DB, mGen.SP, 1, mRegList);
                }
                mRegFile.recycleSeveral(mRegList);
                mCount = count;
            }
        }
        ~Spill() {
            if (mRegList) {
                if (mCount == 1) {
                    int reg = 31 - __builtin_clz(mRegList);
                    mGen.LDR(mGen.AL, reg, mGen.SP, mGen.immed12_post(4));
                } else {
                    mGen.LDM(mGen.AL, mGen.IA, mGen.SP, 1, mRegList);
                }
                mRegFile.reserveSeveral(mRegList);
            }
        }
    private:
        RegisterFile&           mRegFile;
        ARMAssemblerInterface&  mGen;
        uint32_t                mRegList;
        int                     mCount;
    };
    
private:
    RegisterFile    mRegs;
};

// ----------------------------------------------------------------------------

class GGLAssembler : public ARMAssemblerProxy, public RegisterAllocator
{
public:

                    GGLAssembler(ARMAssemblerInterface* target);
        virtual     ~GGLAssembler();

    uint32_t*   base() const { return 0; } // XXX
    uint32_t*   pc() const { return 0; } // XXX

    void        reset(int opt_level);

    virtual void    prolog();
    virtual void    epilog(uint32_t touched);

        // generate scanline code for given needs
    int         scanline(const needs_t& needs, context_t const* c);
    int         scanline_core(const needs_t& needs, context_t const* c);

        enum {
            CLEAR_LO    = 0x0001,
            CLEAR_HI    = 0x0002,
            CORRUPTIBLE = 0x0004,
            FIRST       = 0x0008
        };

        enum { //load/store flags
            WRITE_BACK  = 0x0001
        };

        struct reg_t {
            reg_t() : reg(-1), flags(0) {
            }
            reg_t(int r, int f=0)
                : reg(r), flags(f) {
            }
            void setTo(int r, int f=0) {
                reg=r; flags=f;
            }
            int         reg;
            uint16_t    flags;
        };

        struct integer_t : public reg_t {
            integer_t() : reg_t(), s(0) {
            }
            integer_t(int r, int sz=32, int f=0)
                : reg_t(r, f), s(sz) {
            }
            void setTo(int r, int sz=32, int f=0) {
                reg_t::setTo(r, f); s=sz;
            }
            int8_t s;
            inline int size() const { return s; }
        };
        
        struct pixel_t : public reg_t {
            pixel_t() : reg_t() {
                memset(&format, 0, sizeof(GGLFormat));
            }
            pixel_t(int r, const GGLFormat* fmt, int f=0)
                : reg_t(r, f), format(*fmt) {
            }
            void setTo(int r, const GGLFormat* fmt, int f=0) {
                reg_t::setTo(r, f); format = *fmt;
            }
            GGLFormat format;
            inline int hi(int c) const { return format.c[c].h; }
            inline int low(int c) const { return format.c[c].l; }
            inline int mask(int c) const { return ((1<<size(c))-1) << low(c); }
            inline int size() const { return format.size*8; }
            inline int size(int c) const { return component_size(c); }
            inline int component_size(int c) const { return hi(c) - low(c); }
        };

        struct component_t : public reg_t {
            component_t() : reg_t(), h(0), l(0) {
            }
            component_t(int r, int f=0)
                : reg_t(r, f), h(0), l(0) {
            }
            component_t(int r, int lo, int hi, int f=0)
                : reg_t(r, f), h(hi), l(lo) {
            }
            explicit component_t(const integer_t& rhs)
                : reg_t(rhs.reg, rhs.flags), h(rhs.s), l(0) {
            }
            explicit component_t(const pixel_t& rhs, int component) {
                setTo(  rhs.reg, 
                        rhs.format.c[component].l,
                        rhs.format.c[component].h,
                        rhs.flags|CLEAR_LO|CLEAR_HI);
            }
            void setTo(int r, int lo=0, int hi=0, int f=0) {
                reg_t::setTo(r, f); h=hi; l=lo;
            }
            int8_t h;
            int8_t l;
            inline int size() const { return h-l; }
        };

        struct pointer_t : public reg_t {
            pointer_t() : reg_t(), size(0) {
            }
            pointer_t(int r, int s, int f=0)
                : reg_t(r, f), size(s) {
            }
            void setTo(int r, int s, int f=0) {
                reg_t::setTo(r, f); size=s;
            }
            int8_t size;
        };


private:
    struct tex_coord_t {
        reg_t       s;
        reg_t       t;
        pointer_t   ptr;
    };

    struct fragment_parts_t {
        uint32_t    packed  : 1;
        uint32_t    reload  : 2;
        uint32_t    iterated_packed  : 1;
        pixel_t     iterated;
        pointer_t   cbPtr;
        pointer_t   covPtr;
        reg_t       count;
        reg_t       argb[4];
        reg_t       argb_dx[4];
        reg_t       z;
        reg_t       dither;
        pixel_t     texel[GGL_TEXTURE_UNIT_COUNT];
        tex_coord_t coords[GGL_TEXTURE_UNIT_COUNT];
    };
    
    struct texture_unit_t {
        int         format_idx;
        GGLFormat   format;
        int         bits;
        int         swrap;
        int         twrap;
        int         env;
        int         pot;
        int         linear;
        uint8_t     mask;
        uint8_t     replaced;
    };

    struct texture_machine_t {
        texture_unit_t  tmu[GGL_TEXTURE_UNIT_COUNT];
        uint8_t         mask;
        uint8_t         replaced;
        uint8_t         directTexture;
        uint8_t         activeUnits;
    };

    struct component_info_t {
        bool    masked      : 1;
        bool    inDest      : 1;
        bool    needed      : 1;
        bool    replaced    : 1;
        bool    iterated    : 1;
        bool    smooth      : 1;
        bool    blend       : 1;
        bool    fog         : 1;
    };

    struct builder_context_t {
        context_t const*    c;
        needs_t             needs;
        int                 Rctx;
    };

    template <typename T>
    void modify(T& r, Scratch& regs)
    {
        if (!(r.flags & CORRUPTIBLE)) {
            r.reg = regs.obtain();
            r.flags |= CORRUPTIBLE;
        }
    }

    // helpers
    void    base_offset(const pointer_t& d, const pointer_t& b, const reg_t& o);

    // texture environement
    void    modulate(   component_t& dest,
                        const component_t& incoming,
                        const pixel_t& texel, int component);

    void    decal(  component_t& dest,
                    const component_t& incoming,
                    const pixel_t& texel, int component);

    void    blend(  component_t& dest,
                    const component_t& incoming,
                    const pixel_t& texel, int component, int tmu);

    void    add(  component_t& dest,
                    const component_t& incoming,
                    const pixel_t& texel, int component);

    // load/store stuff
    void    store(const pointer_t& addr, const pixel_t& src, uint32_t flags=0);
    void    load(const pointer_t& addr, const pixel_t& dest, uint32_t flags=0);
    void    extract(integer_t& d, const pixel_t& s, int component);    
    void    extract(component_t& d, const pixel_t& s, int component);    
    void    extract(integer_t& d, int s, int h, int l, int bits=32);
    void    expand(integer_t& d, const integer_t& s, int dbits);
    void    expand(integer_t& d, const component_t& s, int dbits);
    void    expand(component_t& d, const component_t& s, int dbits);
    void    downshift(pixel_t& d, int component, component_t s, const reg_t& dither);


    void    mul_factor( component_t& d,
                        const integer_t& v,
                        const integer_t& f);

    void    mul_factor_add( component_t& d,
                            const integer_t& v,
                            const integer_t& f,
                            const component_t& a);

    void    component_add(  component_t& d,
                            const integer_t& dst,
                            const integer_t& src);

    void    component_sat(  const component_t& v);


    void    build_scanline_prolog(  fragment_parts_t& parts,
                                    const needs_t& needs);

    void    build_smooth_shade(const fragment_parts_t& parts);

    void    build_component(    pixel_t& pixel,
                                const fragment_parts_t& parts,
                                int component,
                                Scratch& global_scratches);
                                
    void    build_incoming_component(
                                component_t& temp,
                                int dst_size,
                                const fragment_parts_t& parts,
                                int component,
                                Scratch& scratches,
                                Scratch& global_scratches);

    void    init_iterated_color(fragment_parts_t& parts, const reg_t& x);

    void    build_iterated_color(   component_t& fragment,
                                    const fragment_parts_t& parts,
                                    int component,
                                    Scratch& regs);

    void    decodeLogicOpNeeds(const needs_t& needs);
    
    void    decodeTMUNeeds(const needs_t& needs, context_t const* c);

    void    init_textures(  tex_coord_t* coords,
                            const reg_t& x,
                            const reg_t& y);

    void    build_textures( fragment_parts_t& parts,
                            Scratch& regs);

    void    filter8(   const fragment_parts_t& parts,
                        pixel_t& texel, const texture_unit_t& tmu,
                        int U, int V, pointer_t& txPtr,
                        int FRAC_BITS);

    void    filter16(   const fragment_parts_t& parts,
                        pixel_t& texel, const texture_unit_t& tmu,
                        int U, int V, pointer_t& txPtr,
                        int FRAC_BITS);

    void    filter24(   const fragment_parts_t& parts,
                        pixel_t& texel, const texture_unit_t& tmu,
                        int U, int V, pointer_t& txPtr,
                        int FRAC_BITS);

    void    filter32(   const fragment_parts_t& parts,
                        pixel_t& texel, const texture_unit_t& tmu,
                        int U, int V, pointer_t& txPtr,
                        int FRAC_BITS);

    void    build_texture_environment(  component_t& fragment,
                                        const fragment_parts_t& parts,
                                        int component,
                                        Scratch& regs);

    void    wrapping(   int d,
                        int coord, int size,
                        int tx_wrap, int tx_linear);

    void    build_fog(  component_t& temp,
                        int component,
                        Scratch& parent_scratches);

    void    build_blending(     component_t& in_out,
                                const pixel_t& pixel,
                                int component,
                                Scratch& parent_scratches);

    void    build_blend_factor(
                integer_t& factor, int f, int component,
                const pixel_t& dst_pixel,
                integer_t& fragment,
                integer_t& fb,
                Scratch& scratches);

    void    build_blendFOneMinusF(  component_t& temp,
                                    const integer_t& factor, 
                                    const integer_t& fragment,
                                    const integer_t& fb);

    void    build_blendOneMinusFF(  component_t& temp,
                                    const integer_t& factor, 
                                    const integer_t& fragment,
                                    const integer_t& fb);

    void build_coverage_application(component_t& fragment,
                                    const fragment_parts_t& parts,
                                    Scratch& regs);

    void build_alpha_test(component_t& fragment, const fragment_parts_t& parts);

    enum { Z_TEST=1, Z_WRITE=2 }; 
    void build_depth_test(const fragment_parts_t& parts, uint32_t mask);
    void build_iterate_z(const fragment_parts_t& parts);
    void build_iterate_f(const fragment_parts_t& parts);
    void build_iterate_texture_coordinates(const fragment_parts_t& parts);

    void build_logic_op(pixel_t& pixel, Scratch& regs);

    void build_masking(pixel_t& pixel, Scratch& regs);

    void build_and_immediate(int d, int s, uint32_t mask, int bits);

    bool    isAlphaSourceNeeded() const;

    enum {
        FACTOR_SRC=1, FACTOR_DST=2, BLEND_SRC=4, BLEND_DST=8 
    };
    
    enum {
        LOGIC_OP=1, LOGIC_OP_SRC=2, LOGIC_OP_DST=4
    };

    static int blending_codes(int fs, int fd);

    builder_context_t   mBuilderContext;
    texture_machine_t   mTextureMachine;
    component_info_t    mInfo[4];
    int                 mBlending;
    int                 mMasking;
    int                 mAllMasked;
    int                 mLogicOp;
    int                 mAlphaTest;
    int                 mAA;
    int                 mDithering;
    int                 mDepthTest;

    int             mSmooth;
    int             mFog;
    pixel_t         mDstPixel;
    
    GGLFormat       mCbFormat;
    
    int             mBlendFactorCached;
    integer_t       mAlphaSource;
    
    int             mBaseRegister;
    
    int             mBlendSrc;
    int             mBlendDst;
    int             mBlendSrcA;
    int             mBlendDstA;
    
    int             mOptLevel;
};

// ----------------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_GGLASSEMBLER_H
