/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LIBADFHWC_ADFHWC_H_
#define _LIBADFHWC_ADFHWC_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <video/adf.h>

#include <hardware/hwcomposer.h>

struct adf_hwc_helper;

struct adf_hwc_event_callbacks {
    /**
     * Called on vsync (required)
     */
    void (*vsync)(void *data, int disp, uint64_t timestamp);
    /**
     * Called on hotplug (required)
     */
    void (*hotplug)(void *data, int disp, bool connected);
    /**
     * Called on hardware-custom ADF events (optional)
     */
    void (*custom_event)(void *data, int disp, struct adf_event *event);
};

/**
 * Converts HAL pixel formats to equivalent ADF/DRM format FourCCs.
 */
static inline uint32_t adf_fourcc_for_hal_pixel_format(int format)
{
    switch (format) {
    case HAL_PIXEL_FORMAT_RGBA_8888:
        return DRM_FORMAT_RGBA8888;
    case HAL_PIXEL_FORMAT_RGBX_8888:
        return DRM_FORMAT_RGBX8888;
    case HAL_PIXEL_FORMAT_RGB_888:
        return DRM_FORMAT_RGB888;
    case HAL_PIXEL_FORMAT_RGB_565:
        return DRM_FORMAT_RGB565;
    case HAL_PIXEL_FORMAT_BGRA_8888:
        return DRM_FORMAT_BGRA8888;
    case HAL_PIXEL_FORMAT_YV12:
        return DRM_FORMAT_YVU420;
    case HAL_PIXEL_FORMAT_YCbCr_422_SP:
        return DRM_FORMAT_NV16;
    case HAL_PIXEL_FORMAT_YCrCb_420_SP:
        return DRM_FORMAT_NV21;
    case HAL_PIXEL_FORMAT_YCbCr_422_I:
        return DRM_FORMAT_YUYV;
    default:
        return 0;
    }
}

/**
 * Converts HAL display types to equivalent ADF interface flags.
 */
static inline uint32_t adf_hwc_interface_flag_for_disp(int disp)
{
    switch (disp) {
    case HWC_DISPLAY_PRIMARY:
        return ADF_INTF_FLAG_PRIMARY;
    case HWC_DISPLAY_EXTERNAL:
        return ADF_INTF_FLAG_EXTERNAL;
    default:
        return 0;
    }
}

__BEGIN_DECLS

/**
 * Create a HWC helper for the specified ADF interfaces.
 *
 * intf_fds must be indexed by HWC display type: e.g.,
 * intf_fds[HWC_DISPLAY_PRIMARY] is the fd for the primary display
 * interface.  n_intfs must be >= 1.
 *
 * The caller retains ownership of the fds in intf_fds and must close()
 * them when they are no longer needed.
 *
 * On error, returns -errno.
 */
int adf_hwc_open(int *intf_fds, size_t n_intfs,
        const struct adf_hwc_event_callbacks *event_cb, void *event_cb_data,
        struct adf_hwc_helper **dev);

/**
 * Destroys a HWC helper.
 */
void adf_hwc_close(struct adf_hwc_helper *dev);

/**
 * Generic implementations of common HWC ops.
 *
 * The HWC should not point its ops directly at these helpers.  Instead, the HWC
 * should provide stub ops which call these helpers after converting the
 * hwc_composer_device_1* to a struct adf_hwc_helper*.
 */
int adf_eventControl(struct adf_hwc_helper *dev, int disp, int event,
        int enabled);
int adf_blank(struct adf_hwc_helper *dev, int disp, int blank);
int adf_query_display_types_supported(struct adf_hwc_helper *dev, int *value);
int adf_getDisplayConfigs(struct adf_hwc_helper *dev, int disp,
        uint32_t *configs, size_t *numConfigs);
int adf_getDisplayAttributes(struct adf_hwc_helper *dev, int disp,
        uint32_t config, const uint32_t *attributes, int32_t *values);

__END_DECLS

#endif /* _LIBADFHWC_ADFHWC_H_ */
