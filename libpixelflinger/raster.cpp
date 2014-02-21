/* libs/pixelflinger/raster.cpp
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



#include <string.h>

#include "raster.h"
#include "trap.h"

namespace android {

static void ggl_rasterPos2x(void* con, GGLfixed x, GGLfixed y);
static void ggl_rasterPos2i(void* con, GGLint x, GGLint y);
static void ggl_copyPixels(void* con, GGLint xs, GGLint ys,
        GGLsizei width, GGLsizei height, GGLenum type);

void ggl_init_raster(context_t* c)
{
    GGLContext& procs = *(GGLContext*)c;
    GGL_INIT_PROC(procs, copyPixels);
    GGL_INIT_PROC(procs, rasterPos2x);
    GGL_INIT_PROC(procs, rasterPos2i);
}

void ggl_rasterPos2x(void* con, GGLfixed x, GGLfixed y)
{
    GGL_CONTEXT(c, con);
    // raster pos should be processed just like glVertex
    c->state.raster.x = x;
    c->state.raster.y = y;
}

void ggl_rasterPos2i(void* con, GGLint x, GGLint y)
{
    ggl_rasterPos2x(con, gglIntToFixed(x), gglIntToFixed(y));
}

void ggl_copyPixels(void* con, GGLint xs, GGLint ys,
        GGLsizei width, GGLsizei height, GGLenum /*type*/)
{
    GGL_CONTEXT(c, con);

    // color-buffer
    surface_t* cb = &(c->state.buffers.color);

    // undefined behaviour if we try to copy from outside the surface
    if (uint32_t(xs) > cb->width)
        return;
    if (uint32_t(ys) > cb->height)
        return;
    if (uint32_t(xs + width) > cb->width)
        return;
    if (uint32_t(ys + height) > cb->height)
        return;

    // copy to current raster position
    GGLint xd = gglFixedToIntRound(c->state.raster.x);
    GGLint yd = gglFixedToIntRound(c->state.raster.y);

    // clip to scissor
    if (xd < GGLint(c->state.scissor.left)) {
        GGLint offset = GGLint(c->state.scissor.left) - xd;
        xd = GGLint(c->state.scissor.left);
        xs += offset;
        width -= offset;
    }
    if (yd < GGLint(c->state.scissor.top)) {
        GGLint offset = GGLint(c->state.scissor.top) - yd;
        yd = GGLint(c->state.scissor.top);
        ys += offset;
        height -= offset;
    }
    if ((xd + width) > GGLint(c->state.scissor.right)) {
        width = GGLint(c->state.scissor.right) - xd;
    }
    if ((yd + height) > GGLint(c->state.scissor.bottom)) {
        height = GGLint(c->state.scissor.bottom) - yd;
    }

    if (width<=0 || height<=0) {
        return; // nothing to copy
    }

    if (xs==xd && ys==yd) {
        // nothing to do, but be careful, this might not be true when we support
        // gglPixelTransfer, gglPixelMap and gglPixelZoom
        return;
    }

    const GGLFormat* fp = &(c->formats[cb->format]);
    uint8_t* src = reinterpret_cast<uint8_t*>(cb->data)
            + (xs + (cb->stride * ys)) * fp->size;
    uint8_t* dst = reinterpret_cast<uint8_t*>(cb->data)
            + (xd + (cb->stride * yd)) * fp->size;
    const size_t bpr = cb->stride * fp->size;
    const size_t rowsize = width * fp->size;
    size_t yc = height;

    if (ys < yd) {
        // bottom to top
        src += height * bpr;
        dst += height * bpr;
        do {
            dst -= bpr;
            src -= bpr;
            memcpy(dst, src, rowsize);
        } while (--yc);
    } else {
        if (ys == yd) {
            // might be right to left
            do {
                memmove(dst, src, rowsize);
                dst += bpr;
                src += bpr;
            } while (--yc);
        } else {
            // top to bottom
            do {
                memcpy(dst, src, rowsize);
                dst += bpr;
                src += bpr;
            } while (--yc);
        }
    }
}

}; // namespace android

using namespace android;

GGLint gglBitBlit(GGLContext* con, int tmu, GGLint crop[4], GGLint where[4])
{
    GGL_CONTEXT(c, (void*)con);

     GGLint x = where[0];
     GGLint y = where[1];
     GGLint w = where[2];
     GGLint h = where[3];

    // exclsively enable this tmu
    const GGLSurface& cbSurface = c->state.buffers.color.s;
    c->procs.activeTexture(c, tmu);
    c->procs.disable(c, GGL_W_LERP);

    uint32_t tmus = 1UL<<tmu;
    if (c->state.enabled_tmu != tmus) {
        c->activeTMU->enable = 1;
        c->state.enabled_tmu = tmus;
        c->state.enables |= GGL_ENABLE_TMUS;
        ggl_state_changed(c, GGL_TMU_STATE);
    }

    const GGLint Wcr = crop[2];
    const GGLint Hcr = crop[3];
    if ((w == Wcr) && (h == Hcr)) {
        c->procs.texGeni(c, GGL_S, GGL_TEXTURE_GEN_MODE, GGL_ONE_TO_ONE);
        c->procs.texGeni(c, GGL_T, GGL_TEXTURE_GEN_MODE, GGL_ONE_TO_ONE);
        const GGLint Ucr = crop[0];
        const GGLint Vcr = crop[1];
        const GGLint s0  = Ucr - x;
        const GGLint t0  = Vcr - y;
        c->procs.texCoord2i(c, s0, t0);
        c->procs.recti(c, x, y, x+w, y+h);
    } else {
        int32_t texcoords[8];
        x = gglIntToFixed(x);
        y = gglIntToFixed(y); 
    
        // we CLAMP here, which works with premultiplied (s,t)
        c->procs.texParameteri(c, GGL_TEXTURE_2D, GGL_TEXTURE_WRAP_S, GGL_CLAMP);
        c->procs.texParameteri(c, GGL_TEXTURE_2D, GGL_TEXTURE_WRAP_T, GGL_CLAMP);
        c->procs.texGeni(c, GGL_S, GGL_TEXTURE_GEN_MODE, GGL_AUTOMATIC);
        c->procs.texGeni(c, GGL_T, GGL_TEXTURE_GEN_MODE, GGL_AUTOMATIC);
    
        const GGLint Ucr = crop[0] << 16;
        const GGLint Vcr = crop[1] << 16;
        const GGLint Wcr = crop[2] << 16;
        const GGLint Hcr = crop[3] << 16;
    
        // computes texture coordinates (pre-multiplied)
        int32_t dsdx = Wcr / w;   // dsdx = ((Wcr/w)/Wt)*Wt
        int32_t dtdy = Hcr / h;   // dtdy = ((Hcr/h)/Ht)*Ht
        int32_t s0   = Ucr - gglMulx(dsdx, x); // s0 = Ucr - x * dsdx
        int32_t t0   = Vcr - gglMulx(dtdy, y); // t0 = Vcr - y * dtdy
        texcoords[0] = s0;
        texcoords[1] = dsdx;
        texcoords[2] = 0;
        texcoords[3] = t0;
        texcoords[4] = 0;
        texcoords[5] = dtdy;
        texcoords[6] = 0;
        texcoords[7] = 0;
        c->procs.texCoordGradScale8xv(c, tmu, texcoords);
        c->procs.recti(c, 
                gglFixedToIntRound(x),
                gglFixedToIntRound(y),
                gglFixedToIntRound(x)+w,
                gglFixedToIntRound(y)+h);
    }
    return 0;
}

