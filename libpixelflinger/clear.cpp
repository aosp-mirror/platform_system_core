/* libs/pixelflinger/clear.cpp
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

#include <cutils/memory.h>

#include "clear.h"
#include "buffer.h"

namespace android {

// ----------------------------------------------------------------------------

static void ggl_clear(void* c, GGLbitfield mask);
static void ggl_clearColorx(void* c,
        GGLclampx r, GGLclampx g, GGLclampx b, GGLclampx a);        
static void ggl_clearDepthx(void* c, GGLclampx depth);
static void ggl_clearStencil(void* c, GGLint s);

// ----------------------------------------------------------------------------

void ggl_init_clear(context_t* c)
{
    GGLContext& procs = *(GGLContext*)c;
    GGL_INIT_PROC(procs, clear);
    GGL_INIT_PROC(procs, clearColorx);
    GGL_INIT_PROC(procs, clearDepthx);
    GGL_INIT_PROC(procs, clearStencil);
    c->state.clear.dirty =  GGL_STENCIL_BUFFER_BIT |
                            GGL_COLOR_BUFFER_BIT |
                            GGL_DEPTH_BUFFER_BIT;
    c->state.clear.depth = FIXED_ONE;
}

// ----------------------------------------------------------------------------

static void memset2d(context_t* c, const surface_t& s, uint32_t packed,
        uint32_t l, uint32_t t, uint32_t w, uint32_t h)
{
    const uint32_t size = c->formats[s.format].size;
    const int32_t stride = s.stride * size;
    uint8_t* dst = (uint8_t*)s.data + (l + t*s.stride)*size;
    w *= size;

    if (ggl_likely(int32_t(w) == stride)) {
        // clear the whole thing in one call
        w *= h;
        h = 1;
    }

    switch (size) {
    case 1:
        do {
            memset(dst, packed, w);
            dst += stride;
        } while(--h);
        break;
    case 2:
        do {
            android_memset16((uint16_t*)dst, packed, w);
            dst += stride;
        } while(--h);
        break;
    case 3: // XXX: 24-bit clear.
        break;
    case 4:
        do {
            android_memset32((uint32_t*)dst, packed, w);
            dst += stride;
        } while(--h);
        break;
    }    
}

static inline GGLfixed fixedToZ(GGLfixed z) {
    return GGLfixed(((int64_t(z) << 16) - z) >> 16);
}

static void ggl_clear(void* con, GGLbitfield mask)
{
    GGL_CONTEXT(c, con);

    // XXX: rgba-dithering, rgba-masking
    // XXX: handle all formats of Z and S

    const uint32_t l = c->state.scissor.left;
    const uint32_t t = c->state.scissor.top;
    uint32_t w = c->state.scissor.right - l;
    uint32_t h = c->state.scissor.bottom - t;

    if (!w || !h)
        return;

    // unexsiting buffers have no effect...
    if (c->state.buffers.color.format == 0)
        mask &= ~GGL_COLOR_BUFFER_BIT;

    if (c->state.buffers.depth.format == 0)
        mask &= ~GGL_DEPTH_BUFFER_BIT;

    if (c->state.buffers.stencil.format == 0)
        mask &= ~GGL_STENCIL_BUFFER_BIT;

    if (mask & GGL_COLOR_BUFFER_BIT) {
        if (c->state.clear.dirty & GGL_COLOR_BUFFER_BIT) {
            c->state.clear.dirty &= ~GGL_COLOR_BUFFER_BIT;

            uint32_t colorPacked = ggl_pack_color(c,
                    c->state.buffers.color.format,
                    gglFixedToIteratedColor(c->state.clear.r),
                    gglFixedToIteratedColor(c->state.clear.g),
                    gglFixedToIteratedColor(c->state.clear.b),
                    gglFixedToIteratedColor(c->state.clear.a));

            c->state.clear.colorPacked = GGL_HOST_TO_RGBA(colorPacked);
        }
        const uint32_t packed = c->state.clear.colorPacked;
        memset2d(c, c->state.buffers.color, packed, l, t, w, h);
    }
    if (mask & GGL_DEPTH_BUFFER_BIT) {
        if (c->state.clear.dirty & GGL_DEPTH_BUFFER_BIT) {
            c->state.clear.dirty &= ~GGL_DEPTH_BUFFER_BIT;
            uint32_t depth = fixedToZ(c->state.clear.depth);
            c->state.clear.depthPacked = (depth<<16)|depth;
        }
        const uint32_t packed = c->state.clear.depthPacked;
        memset2d(c, c->state.buffers.depth, packed, l, t, w, h);
    }

    // XXX: do stencil buffer
}

static void ggl_clearColorx(void* con,
        GGLclampx r, GGLclampx g, GGLclampx b, GGLclampx a)
{
    GGL_CONTEXT(c, con);
    c->state.clear.r = gglClampx(r);
    c->state.clear.g = gglClampx(g);
    c->state.clear.b = gglClampx(b);
    c->state.clear.a = gglClampx(a);
    c->state.clear.dirty |= GGL_COLOR_BUFFER_BIT;
}

static void ggl_clearDepthx(void* con, GGLclampx depth)
{
    GGL_CONTEXT(c, con);
    c->state.clear.depth = gglClampx(depth);
    c->state.clear.dirty |= GGL_DEPTH_BUFFER_BIT;
}

static void ggl_clearStencil(void* con, GGLint s)
{
    GGL_CONTEXT(c, con);
    c->state.clear.stencil = s;
    c->state.clear.dirty |= GGL_STENCIL_BUFFER_BIT;
}

}; // namespace android
