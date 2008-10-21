/* libs/pixelflinger/buffer.h
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


#ifndef ANDROID_GGL_TEXTURE_H
#define ANDROID_GGL_TEXTURE_H

#include <private/pixelflinger/ggl_context.h>

namespace android {

void ggl_init_texture(context_t* c);

void ggl_set_surface(context_t* c, surface_t* dst, const GGLSurface* src);

void ggl_pick_texture(context_t* c);
void ggl_pick_cb(context_t* c);

uint32_t ggl_expand(uint32_t v, int sbits, int dbits);
uint32_t ggl_pack_color(context_t* c, int32_t format,
            GGLcolor r, GGLcolor g, GGLcolor b, GGLcolor a);

}; // namespace android

#endif // ANDROID_GGL_TEXTURE_H
