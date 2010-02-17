/* libs/pixelflinger/format.cpp
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
#include <pixelflinger/format.h>

namespace android {

static GGLFormat const gPixelFormatInfos[] =
{   //          Alpha    Red     Green   Blue
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  4, 32, {{32,24,   8, 0,  16, 8,  24,16 }}, GGL_RGBA },   // PIXEL_FORMAT_RGBA_8888
    {  4, 24, {{ 0, 0,   8, 0,  16, 8,  24,16 }}, GGL_RGB  },   // PIXEL_FORMAT_RGBX_8888
    {  3, 24, {{ 0, 0,   8, 0,  16, 8,  24,16 }}, GGL_RGB  },   // PIXEL_FORMAT_RGB_888
    {  2, 16, {{ 0, 0,  16,11,  11, 5,   5, 0 }}, GGL_RGB  },   // PIXEL_FORMAT_RGB_565
    {  4, 32, {{32,24,  24,16,  16, 8,   8, 0 }}, GGL_RGBA },   // PIXEL_FORMAT_BGRA_8888
    {  2, 16, {{ 1, 0,  16,11,  11, 6,   6, 1 }}, GGL_RGBA },   // PIXEL_FORMAT_RGBA_5551
    {  2, 16, {{ 4, 0,  16,12,  12, 8,   8, 4 }}, GGL_RGBA },   // PIXEL_FORMAT_RGBA_4444
    {  1,  8, {{ 8, 0,   0, 0,   0, 0,   0, 0 }}, GGL_ALPHA},   // PIXEL_FORMAT_A8
    {  1,  8, {{ 0, 0,   8, 0,   8, 0,   8, 0 }}, GGL_LUMINANCE},//PIXEL_FORMAT_L8
    {  2, 16, {{16, 8,   8, 0,   8, 0,   8, 0 }}, GGL_LUMINANCE_ALPHA},// PIXEL_FORMAT_LA_88
    {  1,  8, {{ 0, 0,   8, 5,   5, 2,   2, 0 }}, GGL_RGB  },   // PIXEL_FORMAT_RGB_332
    
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE

    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    
    {  2, 16, {{  0, 0, 16, 0,   0, 0,   0, 0 }}, GGL_DEPTH_COMPONENT},
    {  1,  8, {{  8, 0,  0, 0,   0, 0,   0, 0 }}, GGL_STENCIL_INDEX  },
    {  4, 24, {{  0, 0, 24, 0,   0, 0,   0, 0 }}, GGL_DEPTH_COMPONENT},
    {  4,  8, {{ 32,24,  0, 0,   0, 0,   0, 0 }}, GGL_STENCIL_INDEX  },

    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE

    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE
    {  0,  0, {{ 0, 0,   0, 0,   0, 0,   0, 0 }},        0 },   // PIXEL_FORMAT_NONE

};

}; // namespace android


const GGLFormat* gglGetPixelFormatTable(size_t* numEntries)
{
    if (numEntries) {
        *numEntries = sizeof(android::gPixelFormatInfos)/sizeof(GGLFormat);
    }
    return android::gPixelFormatInfos;
}
