/* libs/pixelflinger/raster.h
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


#ifndef ANDROID_GGL_RASTER_H
#define ANDROID_GGL_RASTER_H

#include <private/pixelflinger/ggl_context.h>

namespace android {

void ggl_init_raster(context_t* c);

void gglCopyPixels(void* c, GGLint x, GGLint y, GGLsizei width, GGLsizei height, GGLenum type);
void gglRasterPos2d(void* c, GGLint x, GGLint y);

}; // namespace android

#endif // ANDROID_GGL_RASTER_H
