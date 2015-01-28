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

#include <fcntl.h>
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <sys/resource.h>

#include <adf/adf.h>
#include <adfhwc/adfhwc.h>

#include <cutils/log.h>
#include <utils/Vector.h>

struct adf_hwc_helper {
    adf_hwc_event_callbacks const *event_cb;
    void *event_cb_data;

    pthread_t event_thread;

    android::Vector<int> intf_fds;
    android::Vector<drm_mode_modeinfo> display_configs;
};

template<typename T> inline T min(T a, T b) { return (a < b) ? a : b; }

int adf_eventControl(struct adf_hwc_helper *dev, int disp, int event,
        int enabled)
{
    if (enabled != !!enabled)
        return -EINVAL;

    if ((size_t)disp >= dev->intf_fds.size())
        return -EINVAL;

    switch (event) {
    case HWC_EVENT_VSYNC:
        return adf_set_event(dev->intf_fds[disp], ADF_EVENT_VSYNC, enabled);
    }

    return -EINVAL;
}

static inline int32_t dpi(uint16_t res, uint16_t size_mm)
{
    if (size_mm)
        return 1000 * (res * 25.4f) / size_mm;
    return 0;
}

int adf_blank(struct adf_hwc_helper *dev, int disp, int blank)
{
    if ((size_t)disp >= dev->intf_fds.size())
        return -EINVAL;

    uint8_t dpms_mode = blank ? DRM_MODE_DPMS_OFF : DRM_MODE_DPMS_ON;
    return adf_interface_blank(dev->intf_fds[disp], dpms_mode);
}

int adf_query_display_types_supported(struct adf_hwc_helper *dev, int *value)
{
    *value = 0;
    if (dev->intf_fds.size() > 0)
        *value |= HWC_DISPLAY_PRIMARY_BIT;
    if (dev->intf_fds.size() > 1)
        *value |= HWC_DISPLAY_EXTERNAL_BIT;

    return 0;
}

int adf_getDisplayConfigs(struct adf_hwc_helper *dev, int disp,
        uint32_t *configs, size_t *numConfigs)
{
    if ((size_t)disp >= dev->intf_fds.size())
        return -EINVAL;

    adf_interface_data data;
    int err = adf_get_interface_data(dev->intf_fds[disp], &data);
    if (err < 0) {
        ALOGE("failed to get ADF interface data: %s", strerror(err));
        return err;
    }

    if (!data.hotplug_detect)
        return -ENODEV;

    android::Vector<drm_mode_modeinfo *> unique_configs;
    unique_configs.push_back(&data.current_mode);
    for (size_t i = 0; i < data.n_available_modes; i++)
        if (memcmp(&data.available_modes[i], &data.current_mode,
                sizeof(data.current_mode)))
            unique_configs.push_back(&data.available_modes[i]);

    for (size_t i = 0; i < min(*numConfigs, unique_configs.size()); i++) {
        configs[i] = dev->display_configs.size();
        dev->display_configs.push_back(*unique_configs[i]);
    }
    *numConfigs = unique_configs.size();

    adf_free_interface_data(&data);
    return 0;
}

static int32_t adf_display_attribute(const adf_interface_data &data,
        const drm_mode_modeinfo &mode, const uint32_t attribute)
{
    switch (attribute) {
    case HWC_DISPLAY_VSYNC_PERIOD:
        if (mode.vrefresh)
            return 1000000000 / mode.vrefresh;
        return 0;

    case HWC_DISPLAY_WIDTH:
        return mode.hdisplay;

    case HWC_DISPLAY_HEIGHT:
        return mode.vdisplay;

    case HWC_DISPLAY_DPI_X:
        return dpi(mode.hdisplay, data.width_mm);

    case HWC_DISPLAY_DPI_Y:
        return dpi(mode.vdisplay, data.height_mm);

    default:
        ALOGE("unknown display attribute %u", attribute);
        return -EINVAL;
    }
}

int adf_getDisplayAttributes(struct adf_hwc_helper *dev, int disp,
        uint32_t config, const uint32_t *attributes, int32_t *values)
{
    if ((size_t)disp >= dev->intf_fds.size())
        return -EINVAL;

    if (config >= dev->display_configs.size())
        return -EINVAL;

    adf_interface_data data;
    int err = adf_get_interface_data(dev->intf_fds[disp], &data);
    if (err < 0) {
        ALOGE("failed to get ADF interface data: %s", strerror(err));
        return err;
    }

    for (int i = 0; attributes[i] != HWC_DISPLAY_NO_ATTRIBUTE; i++)
        values[i] = adf_display_attribute(data, dev->display_configs[config],
                attributes[i]);

    adf_free_interface_data(&data);
    return 0;
}

static void handle_adf_event(struct adf_hwc_helper *dev, int disp)
{
    adf_event *event;
    int err = adf_read_event(dev->intf_fds[disp], &event);
    if (err < 0) {
        ALOGE("error reading event from display %d: %s", disp, strerror(err));
        return;
    }

    void *vsync_temp;
    adf_vsync_event *vsync;
    adf_hotplug_event *hotplug;

    switch (event->type) {
    case ADF_EVENT_VSYNC:
        vsync_temp = event;
        vsync = static_cast<adf_vsync_event *>(vsync_temp);
        // casting directly to adf_vsync_event * makes g++ warn about
        // potential alignment issues that don't apply here
        dev->event_cb->vsync(dev->event_cb_data, disp, vsync->timestamp);
        break;
    case ADF_EVENT_HOTPLUG:
        hotplug = reinterpret_cast<adf_hotplug_event *>(event);
        dev->event_cb->hotplug(dev->event_cb_data, disp, hotplug->connected);
        break;
    default:
        if (event->type < ADF_EVENT_DEVICE_CUSTOM)
            ALOGW("unrecognized event type %u", event->type);
        else if (!dev->event_cb || !dev->event_cb->custom_event)
            ALOGW("unhandled event type %u", event->type);
        else
            dev->event_cb->custom_event(dev->event_cb_data, disp, event);
    }
    free(event);
}

static void *adf_event_thread(void *data)
{
    adf_hwc_helper *dev = static_cast<adf_hwc_helper *>(data);

    setpriority(PRIO_PROCESS, 0, HAL_PRIORITY_URGENT_DISPLAY);

    pollfd *fds = new pollfd[dev->intf_fds.size()];
    for (size_t i = 0; i < dev->intf_fds.size(); i++) {
        fds[i].fd = dev->intf_fds[i];
        fds[i].events = POLLIN | POLLPRI;
    }

    while (true) {
        int err = poll(fds, dev->intf_fds.size(), -1);

        if (err > 0) {
            for (size_t i = 0; i < dev->intf_fds.size(); i++)
                if (fds[i].revents & (POLLIN | POLLPRI))
                    handle_adf_event(dev, i);
        }
        else if (err == -1) {
            if (errno == EINTR)
                break;
            ALOGE("error in event thread: %s", strerror(errno));
        }
    }

    delete [] fds;
    return NULL;
}

int adf_hwc_open(int *intf_fds, size_t n_intfs,
        const struct adf_hwc_event_callbacks *event_cb, void *event_cb_data,
        struct adf_hwc_helper **dev)
{
    if (!n_intfs)
        return -EINVAL;

    adf_hwc_helper *dev_ret = new adf_hwc_helper;
    dev_ret->event_cb = event_cb;
    dev_ret->event_cb_data = event_cb_data;

    int ret;

    for (size_t i = 0; i < n_intfs; i++) {
        int dup_intf_fd = dup(intf_fds[i]);
        if (dup_intf_fd < 0) {
            ALOGE("failed to dup interface fd: %s", strerror(errno));
            ret = -errno;
            goto err;
        }

        dev_ret->intf_fds.push_back(dup_intf_fd);

        ret = adf_set_event(dup_intf_fd, ADF_EVENT_HOTPLUG, 1);
        if (ret < 0 && ret != -EINVAL) {
            ALOGE("failed to enable hotplug event on display %zu: %s",
                    i, strerror(errno));
            goto err;
        }
    }

    ret = pthread_create(&dev_ret->event_thread, NULL, adf_event_thread,
            dev_ret);
    if (ret) {
        ALOGE("failed to create event thread: %s", strerror(ret));
        goto err;
    }

    *dev = dev_ret;
    return 0;

err:
    for (size_t i = 0; i < dev_ret->intf_fds.size(); i++)
        close(dev_ret->intf_fds[i]);

    delete dev_ret;
    return ret;
}

void adf_hwc_close(struct adf_hwc_helper *dev)
{
    pthread_kill(dev->event_thread, SIGTERM);
    pthread_join(dev->event_thread, NULL);

    for (size_t i = 0; i < dev->intf_fds.size(); i++)
        close(dev->intf_fds[i]);

    delete dev;
}
