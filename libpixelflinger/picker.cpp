/* libs/pixelflinger/picker.cpp
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


#include <stdio.h>

#include "buffer.h"
#include "scanline.h"
#include "picker.h"

namespace android {

// ----------------------------------------------------------------------------

void ggl_init_picker(context_t* /*c*/)
{
}

void ggl_pick(context_t* c)
{
    if (ggl_likely(!c->dirty))
        return;
        
    // compute needs, see if they changed...
    const uint32_t enables = c->state.enables;
    needs_t new_needs(c->state.needs);

    if (c->dirty & GGL_CB_STATE) {
        new_needs.n &= ~GGL_NEEDS_CB_FORMAT_MASK;
        new_needs.n |= GGL_BUILD_NEEDS(c->state.buffers.color.format, CB_FORMAT);
        if (enables & GGL_ENABLE_BLENDING)
            c->dirty |= GGL_PIXEL_PIPELINE_STATE;
    }

    if (c->dirty & GGL_PIXEL_PIPELINE_STATE) {
        uint32_t n = GGL_BUILD_NEEDS(c->state.buffers.color.format, CB_FORMAT);
        uint32_t p = 0;
        if (enables & GGL_ENABLE_BLENDING) {
            uint32_t src = c->state.blend.src;
            uint32_t dst = c->state.blend.dst;
            uint32_t src_alpha = c->state.blend.src_alpha;
            uint32_t dst_alpha = c->state.blend.dst_alpha;
            const GGLFormat& cbf = c->formats[ c->state.buffers.color.format ];
            if (!cbf.c[GGLFormat::ALPHA].h) {
                if ((src == GGL_ONE_MINUS_DST_ALPHA) ||
                    (src == GGL_DST_ALPHA)) {
                    src = GGL_ONE;
                }
                if ((src_alpha == GGL_ONE_MINUS_DST_ALPHA) ||
                    (src_alpha == GGL_DST_ALPHA)) {
                    src_alpha = GGL_ONE;
                }
                if ((dst == GGL_ONE_MINUS_DST_ALPHA) ||
                    (dst == GGL_DST_ALPHA)) {
                    dst = GGL_ONE;
                }
                if ((dst_alpha == GGL_ONE_MINUS_DST_ALPHA) ||
                    (dst_alpha == GGL_DST_ALPHA)) {
                    dst_alpha = GGL_ONE;
                }
            }

            src       = ggl_blendfactor_to_needs(src);
            dst       = ggl_blendfactor_to_needs(dst);
            src_alpha = ggl_blendfactor_to_needs(src_alpha);
            dst_alpha = ggl_blendfactor_to_needs(dst_alpha);
                    
            n |= GGL_BUILD_NEEDS( src, BLEND_SRC );
            n |= GGL_BUILD_NEEDS( dst, BLEND_DST );
            if (c->state.blend.alpha_separate) {
                n |= GGL_BUILD_NEEDS( src_alpha, BLEND_SRCA );
                n |= GGL_BUILD_NEEDS( dst_alpha, BLEND_DSTA );
            } else {
                n |= GGL_BUILD_NEEDS( src, BLEND_SRCA );
                n |= GGL_BUILD_NEEDS( dst, BLEND_DSTA );
            }
        } else {
            n |= GGL_BUILD_NEEDS( GGL_ONE,  BLEND_SRC );
            n |= GGL_BUILD_NEEDS( GGL_ZERO, BLEND_DST );
            n |= GGL_BUILD_NEEDS( GGL_ONE,  BLEND_SRCA );
            n |= GGL_BUILD_NEEDS( GGL_ZERO, BLEND_DSTA );
        }


        n |= GGL_BUILD_NEEDS(c->state.mask.color^0xF,               MASK_ARGB);
        n |= GGL_BUILD_NEEDS((enables & GGL_ENABLE_SMOOTH)  ?1:0,   SHADE);
        if (enables & GGL_ENABLE_TMUS) {
            n |= GGL_BUILD_NEEDS((enables & GGL_ENABLE_W)       ?1:0,   W);
        }
        p |= GGL_BUILD_NEEDS((enables & GGL_ENABLE_DITHER)  ?1:0,   P_DITHER);
        p |= GGL_BUILD_NEEDS((enables & GGL_ENABLE_AA)      ?1:0,   P_AA);
        p |= GGL_BUILD_NEEDS((enables & GGL_ENABLE_FOG)     ?1:0,   P_FOG);

        if (enables & GGL_ENABLE_LOGIC_OP) {
            n |= GGL_BUILD_NEEDS(c->state.logic_op.opcode, LOGIC_OP);
        } else {
            n |= GGL_BUILD_NEEDS(GGL_COPY, LOGIC_OP);
        }

        if (enables & GGL_ENABLE_ALPHA_TEST) {
            p |= GGL_BUILD_NEEDS(c->state.alpha_test.func, P_ALPHA_TEST);
        } else {
            p |= GGL_BUILD_NEEDS(GGL_ALWAYS, P_ALPHA_TEST);
        }

        if (enables & GGL_ENABLE_DEPTH_TEST) {
            p |= GGL_BUILD_NEEDS(c->state.depth_test.func, P_DEPTH_TEST);
            p |= GGL_BUILD_NEEDS(c->state.mask.depth&1, P_MASK_Z);
        } else {
            p |= GGL_BUILD_NEEDS(GGL_ALWAYS, P_DEPTH_TEST);
            // writing to the z-buffer is always disabled if depth-test
            // is disabled.
        }
        new_needs.n = n;
        new_needs.p = p;
    }

    if (c->dirty & GGL_TMU_STATE) {
        int idx = 0;
        for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
            const texture_t& tx = c->state.texture[i];
            if (tx.enable) {
                uint32_t t = 0;
                t |= GGL_BUILD_NEEDS(tx.surface.format, T_FORMAT);
                t |= GGL_BUILD_NEEDS(ggl_env_to_needs(tx.env), T_ENV);
                t |= GGL_BUILD_NEEDS(0, T_POT);       // XXX: not used yet
                if (tx.s_coord==GGL_ONE_TO_ONE && tx.t_coord==GGL_ONE_TO_ONE) {
                    // we encode 1-to-1 into the wrap mode
                    t |= GGL_BUILD_NEEDS(GGL_NEEDS_WRAP_11, T_S_WRAP);
                    t |= GGL_BUILD_NEEDS(GGL_NEEDS_WRAP_11, T_T_WRAP);
                } else {
                    t |= GGL_BUILD_NEEDS(ggl_wrap_to_needs(tx.s_wrap), T_S_WRAP);
                    t |= GGL_BUILD_NEEDS(ggl_wrap_to_needs(tx.t_wrap), T_T_WRAP);
                }
                if (tx.mag_filter == GGL_LINEAR) {
                    t |= GGL_BUILD_NEEDS(1, T_LINEAR);
                }
                if (tx.min_filter == GGL_LINEAR) {
                    t |= GGL_BUILD_NEEDS(1, T_LINEAR);
                }
                new_needs.t[idx++] = t;
            } else {
                new_needs.t[i] = 0;
            }
        }
    }

    if (new_needs != c->state.needs) {
        c->state.needs = new_needs;
        ggl_pick_texture(c);
        ggl_pick_cb(c);
        ggl_pick_scanline(c);
    }
    c->dirty = 0;
}

// ----------------------------------------------------------------------------
}; // namespace android

