/* libs/pixelflinger/pixelflinger.cpp
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


#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/time.h>

#include <pixelflinger/pixelflinger.h>
#include <private/pixelflinger/ggl_context.h>

#include "buffer.h"
#include "clear.h"
#include "picker.h"
#include "raster.h"
#include "scanline.h"
#include "trap.h"

#include "codeflinger/GGLAssembler.h"
#include "codeflinger/CodeCache.h"

#include <stdio.h> 


namespace android {

// ----------------------------------------------------------------------------

// 8x8 Bayer dither matrix
static const uint8_t gDitherMatrix[GGL_DITHER_SIZE] = {
     0, 32,  8, 40,  2, 34, 10, 42,
    48, 16, 56, 24, 50, 18, 58, 26,
    12, 44,  4, 36, 14, 46,  6, 38,
    60, 28, 52, 20, 62, 30, 54, 22,
     3, 35, 11, 43,  1, 33,  9, 41,
    51, 19, 59, 27, 49, 17, 57, 25,
    15, 47,  7, 39, 13, 45,  5, 37,
    63, 31, 55, 23, 61, 29, 53, 21
};

static void ggl_init_procs(context_t* c);
static void ggl_set_scissor(context_t* c);

static void ggl_enable_blending(context_t* c, int enable);
static void ggl_enable_scissor_test(context_t* c, int enable);
static void ggl_enable_alpha_test(context_t* c, int enable);
static void ggl_enable_logic_op(context_t* c, int enable);
static void ggl_enable_dither(context_t* c, int enable);
static void ggl_enable_stencil_test(context_t* c, int enable);
static void ggl_enable_depth_test(context_t* c, int enable);
static void ggl_enable_aa(context_t* c, int enable);
static void ggl_enable_point_aa_nice(context_t* c, int enable);
static void ggl_enable_texture2d(context_t* c, int enable);
static void ggl_enable_w_lerp(context_t* c, int enable);
static void ggl_enable_fog(context_t* c, int enable);

static inline int min(int a, int b) CONST;
static inline int min(int a, int b) {
    return a < b ? a : b;
}

static inline int max(int a, int b) CONST;
static inline int max(int a, int b) {
    return a < b ? b : a;
}

// ----------------------------------------------------------------------------

void ggl_error(context_t* c, GGLenum error)
{
    if (c->error == GGL_NO_ERROR)
        c->error = error;
}

// ----------------------------------------------------------------------------

static void ggl_bindTexture(void* con, const GGLSurface* surface)
{
    GGL_CONTEXT(c, con);
    if (surface->format != c->activeTMU->surface.format)
        ggl_state_changed(c, GGL_TMU_STATE);    
    ggl_set_surface(c, &(c->activeTMU->surface), surface);
}


static void ggl_bindTextureLod(void* con, GGLuint tmu,const GGLSurface* surface)
{
    GGL_CONTEXT(c, con);
    // All LODs must have the same format
    ggl_set_surface(c, &c->state.texture[tmu].surface, surface);
}

static void ggl_colorBuffer(void* con, const GGLSurface* surface)
{
    GGL_CONTEXT(c, con);
    if (surface->format != c->state.buffers.color.format)
        ggl_state_changed(c, GGL_CB_STATE);

    if (surface->width > c->state.buffers.coverageBufferSize) {
        // allocate the coverage factor buffer
        free(c->state.buffers.coverage);
        c->state.buffers.coverage = (int16_t*)malloc(surface->width * 2);
        c->state.buffers.coverageBufferSize =
                c->state.buffers.coverage ? surface->width : 0;
    }
    ggl_set_surface(c, &(c->state.buffers.color), surface);
    if (c->state.buffers.read.format == 0) {
        ggl_set_surface(c, &(c->state.buffers.read), surface);
    }
    ggl_set_scissor(c);
}

static void ggl_readBuffer(void* con, const GGLSurface* surface)
{
    GGL_CONTEXT(c, con);
    ggl_set_surface(c, &(c->state.buffers.read), surface);
}

static void ggl_depthBuffer(void* con, const GGLSurface* surface)
{
    GGL_CONTEXT(c, con);
    if (surface->format == GGL_PIXEL_FORMAT_Z_16) {
        ggl_set_surface(c, &(c->state.buffers.depth), surface);
    } else {
        c->state.buffers.depth.format = GGL_PIXEL_FORMAT_NONE;
        ggl_enable_depth_test(c, 0);
    }
}

static void ggl_scissor(void* con, GGLint x, GGLint y,
        GGLsizei width, GGLsizei height)
{
    GGL_CONTEXT(c, con);
    c->state.scissor.user_left = x;
    c->state.scissor.user_top = y;
    c->state.scissor.user_right = x + width;
    c->state.scissor.user_bottom = y + height;
    ggl_set_scissor(c);
}

// ----------------------------------------------------------------------------

static void enable_disable(context_t* c, GGLenum name, int en)
{
    switch (name) {
    case GGL_BLEND:             ggl_enable_blending(c, en);      break;
    case GGL_SCISSOR_TEST:      ggl_enable_scissor_test(c, en);  break;
    case GGL_ALPHA_TEST:        ggl_enable_alpha_test(c, en);    break;
    case GGL_COLOR_LOGIC_OP:    ggl_enable_logic_op(c, en);      break;
    case GGL_DITHER:            ggl_enable_dither(c, en);        break;
    case GGL_STENCIL_TEST:      ggl_enable_stencil_test(c, en);  break;
    case GGL_DEPTH_TEST:        ggl_enable_depth_test(c, en);    break;
    case GGL_AA:                ggl_enable_aa(c, en);            break;
    case GGL_TEXTURE_2D:        ggl_enable_texture2d(c, en);     break;
    case GGL_W_LERP:            ggl_enable_w_lerp(c, en);        break;
    case GGL_FOG:               ggl_enable_fog(c, en);           break;
    case GGL_POINT_SMOOTH_NICE: ggl_enable_point_aa_nice(c, en); break;
    }
}

static void ggl_enable(void* con, GGLenum name)
{
    GGL_CONTEXT(c, con);
    enable_disable(c, name, 1);
}

static void ggl_disable(void* con, GGLenum name)
{
    GGL_CONTEXT(c, con);
    enable_disable(c, name, 0);
}

static void ggl_enableDisable(void* con, GGLenum name, GGLboolean en)
{
    GGL_CONTEXT(c, con);
    enable_disable(c, name, en ? 1 : 0);
}

// ----------------------------------------------------------------------------

static void ggl_shadeModel(void* con, GGLenum mode)
{
    GGL_CONTEXT(c, con);
    switch (mode) {
    case GGL_FLAT:
        if (c->state.enables & GGL_ENABLE_SMOOTH) {
            c->state.enables &= ~GGL_ENABLE_SMOOTH;
            ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
        }
        break;
    case GGL_SMOOTH:
        if (!(c->state.enables & GGL_ENABLE_SMOOTH)) {
            c->state.enables |= GGL_ENABLE_SMOOTH;
            ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
        }
        break;
    default:
        ggl_error(c, GGL_INVALID_ENUM);
    }
}

static void ggl_color4xv(void* con, const GGLclampx* color)
{
    GGL_CONTEXT(c, con);
	c->shade.r0 = gglFixedToIteratedColor(color[0]);
	c->shade.g0 = gglFixedToIteratedColor(color[1]);
	c->shade.b0 = gglFixedToIteratedColor(color[2]);
	c->shade.a0 = gglFixedToIteratedColor(color[3]);
}

static void ggl_colorGrad12xv(void* con, const GGLcolor* grad)
{
    GGL_CONTEXT(c, con);
    // it is very important to round the iterated value here because
    // the rasterizer doesn't clamp them, therefore the iterated value
    //must absolutely be correct.
    // GGLColor is encoded as 8.16 value
    const int32_t round = 0x8000;
	c->shade.r0   = grad[ 0] + round;
	c->shade.drdx = grad[ 1];
	c->shade.drdy = grad[ 2];
	c->shade.g0   = grad[ 3] + round;
	c->shade.dgdx = grad[ 4];
	c->shade.dgdy = grad[ 5];
	c->shade.b0   = grad[ 6] + round;
	c->shade.dbdx = grad[ 7];
	c->shade.dbdy = grad[ 8];
	c->shade.a0   = grad[ 9] + round;
	c->shade.dadx = grad[10];
	c->shade.dady = grad[11];
}

static void ggl_zGrad3xv(void* con, const GGLfixed32* grad)
{
    GGL_CONTEXT(c, con);
    // z iterators are encoded as 0.32 fixed point and the z-buffer
    // holds 16 bits, the rounding value is 0x8000.
    const uint32_t round = 0x8000;
	c->shade.z0   = grad[0] + round;
	c->shade.dzdx = grad[1];
	c->shade.dzdy = grad[2];
}

static void ggl_wGrad3xv(void* con, const GGLfixed* grad)
{
    GGL_CONTEXT(c, con);
	c->shade.w0   = grad[0];
	c->shade.dwdx = grad[1];
	c->shade.dwdy = grad[2];
}

// ----------------------------------------------------------------------------

static void ggl_fogGrad3xv(void* con, const GGLfixed* grad)
{
    GGL_CONTEXT(c, con);
	c->shade.f0     = grad[0];
	c->shade.dfdx   = grad[1];
	c->shade.dfdy   = grad[2];
}

static void ggl_fogColor3xv(void* con, const GGLclampx* color)
{
    GGL_CONTEXT(c, con);
    const int32_t r = gglClampx(color[0]);
    const int32_t g = gglClampx(color[1]);
    const int32_t b = gglClampx(color[2]);
    c->state.fog.color[GGLFormat::ALPHA]= 0xFF; // unused
	c->state.fog.color[GGLFormat::RED]  = (r - (r>>8))>>8;
	c->state.fog.color[GGLFormat::GREEN]= (g - (g>>8))>>8;
	c->state.fog.color[GGLFormat::BLUE] = (b - (b>>8))>>8;
}

static void ggl_enable_fog(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_FOG)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_FOG;
        else        c->state.enables &= ~GGL_ENABLE_FOG;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

// ----------------------------------------------------------------------------

static void ggl_blendFunc(void* con, GGLenum src, GGLenum dst)
{
    GGL_CONTEXT(c, con);
    c->state.blend.src = src;
    c->state.blend.src_alpha = src;
    c->state.blend.dst = dst;
    c->state.blend.dst_alpha = dst;
    c->state.blend.alpha_separate = 0;
    if (c->state.enables & GGL_ENABLE_BLENDING) {
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

static void ggl_blendFuncSeparate(void* con,
        GGLenum src, GGLenum dst,
        GGLenum srcAlpha, GGLenum dstAplha)
{
    GGL_CONTEXT(c, con);
    c->state.blend.src = src;
    c->state.blend.src_alpha = srcAlpha;
    c->state.blend.dst = dst;
    c->state.blend.dst_alpha = dstAplha;
    c->state.blend.alpha_separate = 1;
    if (c->state.enables & GGL_ENABLE_BLENDING) {
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

// ----------------------------------------------------------------------------

static void ggl_texEnvi(void* con,	GGLenum target,
							GGLenum pname,
							GGLint param)
{
    GGL_CONTEXT(c, con);
    if (target != GGL_TEXTURE_ENV || pname != GGL_TEXTURE_ENV_MODE) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
    switch (param) {
    case GGL_REPLACE:
    case GGL_MODULATE:
    case GGL_DECAL:
    case GGL_BLEND:
    case GGL_ADD:
        if (c->activeTMU->env != param) {
            c->activeTMU->env = param;
            ggl_state_changed(c, GGL_TMU_STATE);
        }
        break;
    default:
        ggl_error(c, GGL_INVALID_ENUM);
    }
}

static void ggl_texEnvxv(void* con, GGLenum target,
        GGLenum pname, const GGLfixed* params)
{
    GGL_CONTEXT(c, con);
    if (target != GGL_TEXTURE_ENV) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
    switch (pname) {
    case GGL_TEXTURE_ENV_MODE:
        ggl_texEnvi(con, target, pname, params[0]);
        break;
    case GGL_TEXTURE_ENV_COLOR: {
        uint8_t* const color = c->activeTMU->env_color;
        const GGLclampx r = gglClampx(params[0]);
        const GGLclampx g = gglClampx(params[1]);
        const GGLclampx b = gglClampx(params[2]);
        const GGLclampx a = gglClampx(params[3]);
        color[0] = (a-(a>>8))>>8;
        color[1] = (r-(r>>8))>>8;
        color[2] = (g-(g>>8))>>8;
        color[3] = (b-(b>>8))>>8;
        break;
    }
    default:
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
}


static void ggl_texParameteri(void* con,
        GGLenum target,
        GGLenum pname,
        GGLint param)
{
    GGL_CONTEXT(c, con);
    if (target != GGL_TEXTURE_2D) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }

    if (param == GGL_CLAMP_TO_EDGE)
        param = GGL_CLAMP;

    uint16_t* what = 0;
    switch (pname) {
    case GGL_TEXTURE_WRAP_S:
        if ((param == GGL_CLAMP) ||
            (param == GGL_REPEAT)) {
            what = &c->activeTMU->s_wrap;
        }
        break;
    case GGL_TEXTURE_WRAP_T:
        if ((param == GGL_CLAMP) ||
            (param == GGL_REPEAT)) {
            what = &c->activeTMU->t_wrap;
        }
        break;
    case GGL_TEXTURE_MIN_FILTER:
        if ((param == GGL_NEAREST) ||
            (param == GGL_NEAREST_MIPMAP_NEAREST) ||
            (param == GGL_NEAREST_MIPMAP_LINEAR)) {
            what = &c->activeTMU->min_filter;
            param = GGL_NEAREST;
        }
        if ((param == GGL_LINEAR) ||
            (param == GGL_LINEAR_MIPMAP_NEAREST) ||
            (param == GGL_LINEAR_MIPMAP_LINEAR)) {
            what = &c->activeTMU->min_filter;
            param = GGL_LINEAR;
        }
        break;
    case GGL_TEXTURE_MAG_FILTER:
        if ((param == GGL_NEAREST) ||
            (param == GGL_LINEAR)) {
            what = &c->activeTMU->mag_filter;
        }
        break;
    }
    
    if (!what) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
    
    if (*what != param) {
        *what = param;
        ggl_state_changed(c, GGL_TMU_STATE);
    }
}

static void ggl_texCoordGradScale8xv(void* con, GGLint tmu, const int32_t* grad)
{
    GGL_CONTEXT(c, con);
    texture_t& u = c->state.texture[tmu];
	u.shade.is0   = grad[0];
	u.shade.idsdx = grad[1];
	u.shade.idsdy = grad[2];
	u.shade.it0   = grad[3];
	u.shade.idtdx = grad[4];
	u.shade.idtdy = grad[5];
    u.shade.sscale= grad[6];
    u.shade.tscale= grad[7];
}

static void ggl_texCoord2x(void* con, GGLfixed s, GGLfixed t)
{
    GGL_CONTEXT(c, con);
	c->activeTMU->shade.is0 = s;
	c->activeTMU->shade.it0 = t;
    c->activeTMU->shade.sscale= 0;
    c->activeTMU->shade.tscale= 0;
}

static void ggl_texCoord2i(void* con, GGLint s, GGLint t)
{
    ggl_texCoord2x(con, s<<16, t<<16);
}

static void ggl_texGeni(void* con, GGLenum coord, GGLenum pname, GGLint param)
{
    GGL_CONTEXT(c, con);
    if (pname != GGL_TEXTURE_GEN_MODE) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }

    uint32_t* coord_ptr = 0;
    if (coord == GGL_S)         coord_ptr = &(c->activeTMU->s_coord);
    else if (coord == GGL_T)    coord_ptr = &(c->activeTMU->t_coord);

    if (coord_ptr) {
        if (*coord_ptr != uint32_t(param)) {
            *coord_ptr = uint32_t(param);
            ggl_state_changed(c, GGL_TMU_STATE);
        }
    } else {
        ggl_error(c, GGL_INVALID_ENUM);
    }
}

static void ggl_activeTexture(void* con, GGLuint tmu)
{
    GGL_CONTEXT(c, con);
    if (tmu >= GGLuint(GGL_TEXTURE_UNIT_COUNT)) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
    c->activeTMUIndex = tmu;
    c->activeTMU = &(c->state.texture[tmu]);
}

// ----------------------------------------------------------------------------

static void ggl_colorMask(void* con, GGLboolean r,
                                     GGLboolean g,
                                     GGLboolean b,
                                     GGLboolean a)
{
    GGL_CONTEXT(c, con);
    int mask = 0;
    if (a)  mask |= 1 << GGLFormat::ALPHA;
    if (r)  mask |= 1 << GGLFormat::RED;
    if (g)  mask |= 1 << GGLFormat::GREEN;
    if (b)  mask |= 1 << GGLFormat::BLUE;
    if (c->state.mask.color != mask) {
        c->state.mask.color = mask;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

static void ggl_depthMask(void* con, GGLboolean flag)
{
    GGL_CONTEXT(c, con);
    if (c->state.mask.depth != flag?1:0) {
        c->state.mask.depth = flag?1:0;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

static void ggl_stencilMask(void* con, GGLuint mask)
{
    GGL_CONTEXT(c, con);
    if (c->state.mask.stencil != mask) {
        c->state.mask.stencil = mask;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

// ----------------------------------------------------------------------------

static void ggl_alphaFuncx(void* con, GGLenum func, GGLclampx ref)
{
    GGL_CONTEXT(c, con);
    if ((func < GGL_NEVER) || (func > GGL_ALWAYS)) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
    c->state.alpha_test.ref = gglFixedToIteratedColor(gglClampx(ref));
    if (c->state.alpha_test.func != func) {
        c->state.alpha_test.func = func;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

// ----------------------------------------------------------------------------

static void ggl_depthFunc(void* con, GGLenum func)
{
    GGL_CONTEXT(c, con);
    if ((func < GGL_NEVER) || (func > GGL_ALWAYS)) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
    if (c->state.depth_test.func != func) {
        c->state.depth_test.func = func;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

// ----------------------------------------------------------------------------

static void ggl_logicOp(void* con, GGLenum opcode)
{
    GGL_CONTEXT(c, con);
    if ((opcode < GGL_CLEAR) || (opcode > GGL_SET)) {
        ggl_error(c, GGL_INVALID_ENUM);
        return;
    }
    if (c->state.logic_op.opcode != opcode) {
        c->state.logic_op.opcode = opcode;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}


// ----------------------------------------------------------------------------

void ggl_set_scissor(context_t* c)
{
    if (c->state.enables & GGL_ENABLE_SCISSOR_TEST) {
        const int32_t l = c->state.scissor.user_left;
        const int32_t t = c->state.scissor.user_top;
        const int32_t r = c->state.scissor.user_right;
        const int32_t b = c->state.scissor.user_bottom;
        c->state.scissor.left   = max(0, l);
        c->state.scissor.right  = min(c->state.buffers.color.width, r);
        c->state.scissor.top    = max(0, t);
        c->state.scissor.bottom = min(c->state.buffers.color.height, b);
    } else {
        c->state.scissor.left   = 0;
        c->state.scissor.top    = 0;
        c->state.scissor.right  = c->state.buffers.color.width;
        c->state.scissor.bottom = c->state.buffers.color.height;
    }
}

void ggl_enable_blending(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_BLENDING)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_BLENDING;
        else        c->state.enables &= ~GGL_ENABLE_BLENDING;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_scissor_test(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_SCISSOR_TEST)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_SCISSOR_TEST;
        else        c->state.enables &= ~GGL_ENABLE_SCISSOR_TEST;
        ggl_set_scissor(c);
    }
}

void ggl_enable_alpha_test(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_ALPHA_TEST)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_ALPHA_TEST;
        else        c->state.enables &= ~GGL_ENABLE_ALPHA_TEST;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_logic_op(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_LOGIC_OP)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_LOGIC_OP;
        else        c->state.enables &= ~GGL_ENABLE_LOGIC_OP;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_dither(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_DITHER)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_DITHER;
        else        c->state.enables &= ~GGL_ENABLE_DITHER;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_stencil_test(context_t* /*c*/, int /*enable*/)
{
}

void ggl_enable_depth_test(context_t* c, int enable)
{
    if (c->state.buffers.depth.format == 0)
        enable = 0;
    const int e = (c->state.enables & GGL_ENABLE_DEPTH_TEST)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_DEPTH_TEST;
        else        c->state.enables &= ~GGL_ENABLE_DEPTH_TEST;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_aa(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_AA)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_AA;
        else        c->state.enables &= ~GGL_ENABLE_AA;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_point_aa_nice(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_POINT_AA_NICE)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_POINT_AA_NICE;
        else        c->state.enables &= ~GGL_ENABLE_POINT_AA_NICE;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_w_lerp(context_t* c, int enable)
{
    const int e = (c->state.enables & GGL_ENABLE_W)?1:0;
    if (e != enable) {
        if (enable) c->state.enables |= GGL_ENABLE_W;
        else        c->state.enables &= ~GGL_ENABLE_W;
        ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE);
    }
}

void ggl_enable_texture2d(context_t* c, int enable)
{
    if (c->activeTMU->enable != enable) {
        const uint32_t tmu = c->activeTMUIndex;
        c->activeTMU->enable = enable;
        const uint32_t mask = 1UL << tmu;
        if (enable)                 c->state.enabled_tmu |= mask;
        else                        c->state.enabled_tmu &= ~mask;
        if (c->state.enabled_tmu)   c->state.enables |= GGL_ENABLE_TMUS;
        else                        c->state.enables &= ~GGL_ENABLE_TMUS;
        ggl_state_changed(c, GGL_TMU_STATE);
    }
}

        
// ----------------------------------------------------------------------------

int64_t ggl_system_time()
{
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return int64_t(t.tv_sec)*1000000000LL + t.tv_nsec;
}

// ----------------------------------------------------------------------------

void ggl_init_procs(context_t* c)
{
    GGLContext& procs = *(GGLContext*)c;
    GGL_INIT_PROC(procs, scissor);
    GGL_INIT_PROC(procs, activeTexture);
    GGL_INIT_PROC(procs, bindTexture);
    GGL_INIT_PROC(procs, bindTextureLod);
    GGL_INIT_PROC(procs, colorBuffer);
    GGL_INIT_PROC(procs, readBuffer);
    GGL_INIT_PROC(procs, depthBuffer);
    GGL_INIT_PROC(procs, enable);
    GGL_INIT_PROC(procs, disable);
    GGL_INIT_PROC(procs, enableDisable);
    GGL_INIT_PROC(procs, shadeModel);
    GGL_INIT_PROC(procs, color4xv);
    GGL_INIT_PROC(procs, colorGrad12xv);
    GGL_INIT_PROC(procs, zGrad3xv);
    GGL_INIT_PROC(procs, wGrad3xv);
    GGL_INIT_PROC(procs, fogGrad3xv);
    GGL_INIT_PROC(procs, fogColor3xv);
    GGL_INIT_PROC(procs, blendFunc);
    GGL_INIT_PROC(procs, blendFuncSeparate);
    GGL_INIT_PROC(procs, texEnvi);
    GGL_INIT_PROC(procs, texEnvxv);
    GGL_INIT_PROC(procs, texParameteri);
    GGL_INIT_PROC(procs, texCoord2i);
    GGL_INIT_PROC(procs, texCoord2x);
    GGL_INIT_PROC(procs, texCoordGradScale8xv);
    GGL_INIT_PROC(procs, texGeni);
    GGL_INIT_PROC(procs, colorMask);
    GGL_INIT_PROC(procs, depthMask);
    GGL_INIT_PROC(procs, stencilMask);
    GGL_INIT_PROC(procs, alphaFuncx);
    GGL_INIT_PROC(procs, depthFunc);
    GGL_INIT_PROC(procs, logicOp);
    ggl_init_clear(c);
}

void ggl_init_context(context_t* c)
{
    memset(c, 0, sizeof(context_t));
    ggl_init_procs(c);
    ggl_init_trap(c);
    ggl_init_scanline(c);
    ggl_init_texture(c);
    ggl_init_picker(c);
    ggl_init_raster(c);
    c->formats = gglGetPixelFormatTable();
    c->state.blend.src = GGL_ONE;
    c->state.blend.dst = GGL_ZERO;
    c->state.blend.src_alpha = GGL_ONE;
    c->state.blend.dst_alpha = GGL_ZERO;
    c->state.mask.color = 0xF;
    c->state.mask.depth = 0;
    c->state.mask.stencil = 0xFFFFFFFF;
    c->state.logic_op.opcode = GGL_COPY;
    c->state.alpha_test.func = GGL_ALWAYS;
    c->state.depth_test.func = GGL_LESS;
    c->state.depth_test.clearValue = FIXED_ONE;
    c->shade.w0 = FIXED_ONE;
    memcpy(c->ditherMatrix, gDitherMatrix, sizeof(gDitherMatrix));
}

void ggl_uninit_context(context_t* c)
{
    ggl_uninit_scanline(c);
}

// ----------------------------------------------------------------------------
}; // namespace android
// ----------------------------------------------------------------------------



using namespace android;

ssize_t gglInit(GGLContext** context)
{
    void* const base = malloc(sizeof(context_t) + 32);
	if (base) {
        // always align the context on cache lines
        context_t *c = (context_t *)((ptrdiff_t(base)+31) & ~0x1FL);
        ggl_init_context(c);
        c->base = base;
		*context = (GGLContext*)c;
	} else {
		return -1;
	}
	return 0;
}

ssize_t gglUninit(GGLContext* con)
{
    GGL_CONTEXT(c, (void*)con);
    ggl_uninit_context(c);
	free(c->base);
	return 0;
}

