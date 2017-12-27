#ifndef SYSTEM_CORE_GRAPHICS_BASE_H_
#define SYSTEM_CORE_GRAPHICS_BASE_H_

#include "graphics-base-v1.0.h"
#include "graphics-base-v1.1.h"

/* Legacy formats not in the HAL definitions. */
typedef enum {
    HAL_PIXEL_FORMAT_YCBCR_422_888 = 39,   // 0x27
    HAL_PIXEL_FORMAT_YCBCR_444_888 = 40,   // 0x28
    HAL_PIXEL_FORMAT_FLEX_RGB_888 = 41,    // 0x29
    HAL_PIXEL_FORMAT_FLEX_RGBA_8888 = 42,  // 0x2A
} android_pixel_format_legacy_t;

#endif  // SYSTEM_CORE_GRAPHICS_BASE_H_
