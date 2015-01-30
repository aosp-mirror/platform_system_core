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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>

#include <sys/ioctl.h>

#include <adf/adf.h>

#define ADF_BASE_PATH "/dev/"

static ssize_t adf_find_nodes(const char *pattern, adf_id_t **ids)
{
    DIR *dir;
    struct dirent *dirent;
    size_t n = 0;
    ssize_t ret;
    adf_id_t *ids_ret = NULL;

    dir = opendir(ADF_BASE_PATH);
    if (!dir)
        return -errno;

    errno = 0;
    while ((dirent = readdir(dir))) {
        adf_id_t id;
        int matched = sscanf(dirent->d_name, pattern, &id);

        if (matched < 0) {
            ret = -errno;
            goto done;
        } else if (matched != 1) {
            continue;
        }

        adf_id_t *new_ids = realloc(ids_ret, (n + 1) * sizeof(ids_ret[0]));
        if (!new_ids) {
            ret = -ENOMEM;
            goto done;
        }

        ids_ret = new_ids;
        ids_ret[n] = id;
        n++;
    }
    if (errno)
        ret = -errno;
    else
        ret = n;

done:
    closedir(dir);
    if (ret < 0)
        free(ids_ret);
    else
        *ids = ids_ret;
    return ret;
}

ssize_t adf_devices(adf_id_t **ids)
{
    return adf_find_nodes("adf%u", ids);
}

int adf_device_open(adf_id_t id, int flags, struct adf_device *dev)
{
    char filename[64];
    int err;

    dev->id = id;

    snprintf(filename, sizeof(filename), ADF_BASE_PATH "adf%u", id);
    dev->fd = open(filename, flags);
    if (dev->fd < 0)
        return -errno;

    return 0;
}

void adf_device_close(struct adf_device *dev)
{
    if (dev->fd >= 0)
        close(dev->fd);
}

int adf_get_device_data(struct adf_device *dev, struct adf_device_data *data)
{
    int err;
    int ret = 0;

    memset(data, 0, sizeof(*data));

    err = ioctl(dev->fd, ADF_GET_DEVICE_DATA, data);
    if (err < 0)
        return -ENOMEM;

    if (data->n_attachments) {
        data->attachments = malloc(sizeof(data->attachments[0]) *
                data->n_attachments);
        if (!data->attachments)
            return -ENOMEM;
    }

    if (data->n_allowed_attachments) {
        data->allowed_attachments =
                malloc(sizeof(data->allowed_attachments[0]) *
                        data->n_allowed_attachments);
        if (!data->allowed_attachments) {
            ret = -ENOMEM;
            goto done;
        }
    }

    if (data->custom_data_size) {
        data->custom_data = malloc(data->custom_data_size);
        if (!data->custom_data) {
            ret = -ENOMEM;
            goto done;
        }
    }

    err = ioctl(dev->fd, ADF_GET_DEVICE_DATA, data);
    if (err < 0)
        ret = -errno;

done:
    if (ret < 0)
        adf_free_device_data(data);
    return ret;
}

void adf_free_device_data(struct adf_device_data *data)
{
    free(data->attachments);
    free(data->allowed_attachments);
    free(data->custom_data);
}

int adf_device_post(struct adf_device *dev,
        adf_id_t *interfaces, size_t n_interfaces,
        struct adf_buffer_config *bufs, size_t n_bufs,
        void *custom_data, size_t custom_data_size)
{
    int err;
    struct adf_post_config data;

    memset(&data, 0, sizeof(data));
    data.interfaces = interfaces;
    data.n_interfaces = n_interfaces;
    data.bufs = bufs;
    data.n_bufs = n_bufs;
    data.custom_data = custom_data;
    data.custom_data_size = custom_data_size;

    err = ioctl(dev->fd, ADF_POST_CONFIG, &data);
    if (err < 0)
        return -errno;

    return (int)data.complete_fence;
}

static int adf_device_attachment(struct adf_device *dev,
        adf_id_t overlay_engine, adf_id_t interface, bool attach)
{
    int err;
    struct adf_attachment_config data;

    memset(&data, 0, sizeof(data));
    data.overlay_engine = overlay_engine;
    data.interface = interface;

    err = ioctl(dev->fd, attach ? ADF_ATTACH : ADF_DETACH, &data);
    if (err < 0)
        return -errno;

    return 0;
}

int adf_device_attach(struct adf_device *dev, adf_id_t overlay_engine,
                      adf_id_t interface)
{
   return adf_device_attachment(dev, overlay_engine, interface, true);
}

int adf_device_detach(struct adf_device *dev, adf_id_t overlay_engine,
                      adf_id_t interface)
{
   return adf_device_attachment(dev, overlay_engine, interface, false);
}

ssize_t adf_interfaces(struct adf_device *dev, adf_id_t **interfaces)
{
    char pattern[64];

    snprintf(pattern, sizeof(pattern), "adf-interface%u.%%u", dev->id);
    return adf_find_nodes(pattern, interfaces);
}

ssize_t adf_interfaces_for_overlay_engine(struct adf_device *dev,
        adf_id_t overlay_engine, adf_id_t **interfaces)
{
    struct adf_device_data data;
    ssize_t n = 0;
    ssize_t ret;
    adf_id_t *ids_ret = NULL;

    ret = adf_get_device_data(dev, &data);
    if (ret < 0)
        return ret;

    size_t i;
    for (i = 0; i < data.n_allowed_attachments; i++) {
        if (data.allowed_attachments[i].overlay_engine != overlay_engine)
            continue;

        adf_id_t *new_ids = realloc(ids_ret, (n + 1) * sizeof(ids_ret[0]));
        if (!new_ids) {
            ret = -ENOMEM;
            goto done;
        }

        ids_ret = new_ids;
        ids_ret[n] = data.allowed_attachments[i].interface;
        n++;
    }

    ret = n;

done:
    adf_free_device_data(&data);
    if (ret < 0)
        free(ids_ret);
    else
        *interfaces = ids_ret;
    return ret;
}

static ssize_t adf_interfaces_filter(struct adf_device *dev,
        adf_id_t *in, size_t n_in, adf_id_t **out,
        bool (*filter)(struct adf_interface_data *data, __u32 match),
        __u32 match)
{
    size_t n = 0;
    ssize_t ret;
    adf_id_t *ids_ret = NULL;

    size_t i;
    for (i = 0; i < n_in; i++) {
        int fd = adf_interface_open(dev, in[i], O_RDONLY);
        if (fd < 0) {
            ret = fd;
            goto done;
        }

        struct adf_interface_data data;
        ret = adf_get_interface_data(fd, &data);
        close(fd);
        if (ret < 0)
            goto done;

        if (!filter(&data, match))
            continue;

        adf_id_t *new_ids = realloc(ids_ret, (n + 1) * sizeof(ids_ret[0]));
        if (!new_ids) {
            ret = -ENOMEM;
            goto done;
        }

        ids_ret = new_ids;
        ids_ret[n] = in[i];
        n++;
    }

    ret = n;

done:
    if (ret < 0)
        free(ids_ret);
    else
        *out = ids_ret;
    return ret;
}

static bool adf_interface_type_filter(struct adf_interface_data *data,
        __u32 type)
{
    return data->type == (enum adf_interface_type)type;
}

ssize_t adf_interfaces_filter_by_type(struct adf_device *dev,
        enum adf_interface_type type,
        adf_id_t *in, size_t n_in, adf_id_t **out)
{
    return adf_interfaces_filter(dev, in, n_in, out, adf_interface_type_filter,
            type);
}

static bool adf_interface_flags_filter(struct adf_interface_data *data,
        __u32 flag)
{
    return !!(data->flags & flag);
}

ssize_t adf_interfaces_filter_by_flag(struct adf_device *dev, __u32 flag,
        adf_id_t *in, size_t n_in, adf_id_t **out)
{
    return adf_interfaces_filter(dev, in, n_in, out, adf_interface_flags_filter,
            flag);
}

int adf_interface_open(struct adf_device *dev, adf_id_t id, int flags)
{
    char filename[64];

    snprintf(filename, sizeof(filename), ADF_BASE_PATH "adf-interface%u.%u",
            dev->id, id);

    int fd = open(filename, flags);
    if (fd < 0)
        return -errno;
    return fd;
}

int adf_get_interface_data(int fd, struct adf_interface_data *data)
{
    int err;
    int ret = 0;

    memset(data, 0, sizeof(*data));

    err = ioctl(fd, ADF_GET_INTERFACE_DATA, data);
    if (err < 0)
        return -errno;

    if (data->n_available_modes) {
        data->available_modes = malloc(sizeof(data->available_modes[0]) *
                data->n_available_modes);
        if (!data->available_modes)
            return -ENOMEM;
    }

    if (data->custom_data_size) {
        data->custom_data = malloc(data->custom_data_size);
        if (!data->custom_data) {
            ret = -ENOMEM;
            goto done;
        }
    }

    err = ioctl(fd, ADF_GET_INTERFACE_DATA, data);
    if (err < 0)
        ret = -errno;

done:
    if (ret < 0)
        adf_free_interface_data(data);
    return ret;
}

void adf_free_interface_data(struct adf_interface_data *data)
{
    free(data->available_modes);
    free(data->custom_data);
}

int adf_interface_blank(int fd, __u8 mode)
{
    int err = ioctl(fd, ADF_BLANK, mode);
    if (err < 0)
        return -errno;
    return 0;
}

int adf_interface_set_mode(int fd, struct drm_mode_modeinfo *mode)
{
    int err = ioctl(fd, ADF_SET_MODE, mode);
    if (err < 0)
        return -errno;
    return 0;
}

int adf_interface_simple_buffer_alloc(int fd, __u32 w, __u32 h,
        __u32 format, __u32 *offset, __u32 *pitch)
{
    int err;
    struct adf_simple_buffer_alloc data;

    memset(&data, 0, sizeof(data));
    data.w = w;
    data.h = h;
    data.format = format;

    err = ioctl(fd, ADF_SIMPLE_BUFFER_ALLOC, &data);
    if (err < 0)
        return -errno;

    *offset = data.offset;
    *pitch = data.pitch;
    return (int)data.fd;
}

int adf_interface_simple_post(int fd, __u32 overlay_engine,
        __u32 w, __u32 h, __u32 format, int buf_fd, __u32 offset,
        __u32 pitch, int acquire_fence)
{
    int ret;
    struct adf_simple_post_config data;

    memset(&data, 0, sizeof(data));
    data.buf.overlay_engine = overlay_engine;
    data.buf.w = w;
    data.buf.h = h;
    data.buf.format = format;
    data.buf.fd[0] = buf_fd;
    data.buf.offset[0] = offset;
    data.buf.pitch[0] = pitch;
    data.buf.n_planes = 1;
    data.buf.acquire_fence = acquire_fence;

    ret = ioctl(fd, ADF_SIMPLE_POST_CONFIG, &data);
    if (ret < 0)
        return -errno;

    return (int)data.complete_fence;
}

ssize_t adf_overlay_engines(struct adf_device *dev, adf_id_t **overlay_engines)
{
    char pattern[64];

    snprintf(pattern, sizeof(pattern), "adf-overlay-engine%u.%%u", dev->id);
    return adf_find_nodes(pattern, overlay_engines);
}

ssize_t adf_overlay_engines_for_interface(struct adf_device *dev,
        adf_id_t interface, adf_id_t **overlay_engines)
{
    struct adf_device_data data;
    ssize_t n = 0;
    ssize_t ret;
    adf_id_t *ids_ret = NULL;

    ret = adf_get_device_data(dev, &data);
    if (ret < 0)
        return ret;

    size_t i;
    for (i = 0; i < data.n_allowed_attachments; i++) {
        if (data.allowed_attachments[i].interface != interface)
            continue;

        adf_id_t *new_ids = realloc(ids_ret, (n + 1) * sizeof(ids_ret[0]));
        if (!new_ids) {
            ret = -ENOMEM;
            goto done;
        }

        ids_ret = new_ids;
        ids_ret[n] = data.allowed_attachments[i].overlay_engine;
        n++;
    }

    ret = n;

done:
    adf_free_device_data(&data);
    if (ret < 0)
        free(ids_ret);
    else
        *overlay_engines = ids_ret;
    return ret;
}

static ssize_t adf_overlay_engines_filter(struct adf_device *dev,
        adf_id_t *in, size_t n_in, adf_id_t **out,
        bool (*filter)(struct adf_overlay_engine_data *data, void *cookie),
        void *cookie)
{
    size_t n = 0;
    ssize_t ret;
    adf_id_t *ids_ret = NULL;

    size_t i;
    for (i = 0; i < n_in; i++) {
        int fd = adf_overlay_engine_open(dev, in[i], O_RDONLY);
        if (fd < 0) {
            ret = fd;
            goto done;
        }

        struct adf_overlay_engine_data data;
        ret = adf_get_overlay_engine_data(fd, &data);
        close(fd);
        if (ret < 0)
            goto done;

        if (!filter(&data, cookie))
            continue;

        adf_id_t *new_ids = realloc(ids_ret, (n + 1) * sizeof(ids_ret[0]));
        if (!new_ids) {
            ret = -ENOMEM;
            goto done;
        }

        ids_ret = new_ids;
        ids_ret[n] = in[i];
        n++;
    }

    ret = n;

done:
    if (ret < 0)
        free(ids_ret);
    else
        *out = ids_ret;
    return ret;
}

struct format_filter_cookie {
    const __u32 *formats;
    size_t n_formats;
};

static bool adf_overlay_engine_format_filter(
        struct adf_overlay_engine_data *data, void *cookie)
{
    struct format_filter_cookie *c = cookie;
    size_t i;
    for (i = 0; i < data->n_supported_formats; i++) {
        size_t j;
        for (j = 0; j < c->n_formats; j++)
            if (data->supported_formats[i] == c->formats[j])
                return true;
    }
    return false;
}

ssize_t adf_overlay_engines_filter_by_format(struct adf_device *dev,
        const __u32 *formats, size_t n_formats, adf_id_t *in, size_t n_in,
        adf_id_t **out)
{
    struct format_filter_cookie cookie = { formats, n_formats };
    return adf_overlay_engines_filter(dev, in, n_in, out,
            adf_overlay_engine_format_filter, &cookie);
}

int adf_overlay_engine_open(struct adf_device *dev, adf_id_t id, int flags)
{
    char filename[64];

    snprintf(filename, sizeof(filename),
            ADF_BASE_PATH "adf-overlay-engine%u.%u", dev->id, id);

    int fd = open(filename, flags);
    if (fd < 0)
        return -errno;
    return fd;
}

int adf_get_overlay_engine_data(int fd, struct adf_overlay_engine_data *data)
{
    int err;
    int ret = 0;

    memset(data, 0, sizeof(*data));

    err = ioctl(fd, ADF_GET_OVERLAY_ENGINE_DATA, data);
    if (err < 0)
        return -errno;

    if (data->n_supported_formats) {
        data->supported_formats = malloc(sizeof(data->supported_formats[0]) *
              data->n_supported_formats);
        if (!data->supported_formats)
            return -ENOMEM;
    }

    if (data->custom_data_size) {
      data->custom_data = malloc(data->custom_data_size);
      if (!data->custom_data) {
          ret = -ENOMEM;
          goto done;
      }
    }

    err = ioctl(fd, ADF_GET_OVERLAY_ENGINE_DATA, data);
    if (err < 0)
        ret = -errno;

done:
    if (ret < 0)
        adf_free_overlay_engine_data(data);
    return ret;
}

void adf_free_overlay_engine_data(struct adf_overlay_engine_data *data)
{
    free(data->supported_formats);
    free(data->custom_data);
}

bool adf_overlay_engine_supports_format(int fd, __u32 format)
{
    struct adf_overlay_engine_data data;
    bool ret = false;
    size_t i;

    int err = adf_get_overlay_engine_data(fd, &data);
    if (err < 0)
        return false;

    for (i = 0; i < data.n_supported_formats; i++) {
        if (data.supported_formats[i] == format) {
            ret = true;
            break;
        }
    }

    adf_free_overlay_engine_data(&data);
    return ret;
}

int adf_set_event(int fd, enum adf_event_type type, bool enabled)
{
    struct adf_set_event data;

    data.type = type;
    data.enabled = enabled;

    int err = ioctl(fd, ADF_SET_EVENT, &data);
    if (err < 0)
        return -errno;
    return 0;
}

int adf_read_event(int fd, struct adf_event **event)
{
    struct adf_event header;
    struct {
        struct adf_event base;
        uint8_t data[0];
    } *event_ret;
    size_t data_size;
    int ret = 0;

    int err = read(fd, &header, sizeof(header));
    if (err < 0)
        return -errno;
    if ((size_t)err < sizeof(header))
        return -EIO;
    if (header.length < sizeof(header))
        return -EIO;

    event_ret = malloc(header.length);
    if (!event_ret)
        return -ENOMEM;
    data_size = header.length - sizeof(header);

    memcpy(event_ret, &header, sizeof(header));
    ssize_t read_size = read(fd, &event_ret->data, data_size);
    if (read_size < 0) {
        ret = -errno;
        goto done;
    }
    if ((size_t)read_size < data_size) {
        ret = -EIO;
        goto done;
    }

    *event = &event_ret->base;

done:
    if (ret < 0)
        free(event_ret);
    return ret;
}

void adf_format_str(__u32 format, char buf[ADF_FORMAT_STR_SIZE])
{
    buf[0] = format & 0xFF;
    buf[1] = (format >> 8) & 0xFF;
    buf[2] = (format >> 16) & 0xFF;
    buf[3] = (format >> 24) & 0xFF;
    buf[4] = '\0';
}

static bool adf_find_simple_post_overlay_engine(struct adf_device *dev,
        const __u32 *formats, size_t n_formats,
        adf_id_t interface, adf_id_t *overlay_engine)
{
    adf_id_t *engs;
    ssize_t n_engs = adf_overlay_engines_for_interface(dev, interface, &engs);

    if (n_engs <= 0)
        return false;

    adf_id_t *filtered_engs;
    ssize_t n_filtered_engs = adf_overlay_engines_filter_by_format(dev,
            formats, n_formats, engs, n_engs, &filtered_engs);
    free(engs);

    if (n_filtered_engs <= 0)
        return false;

    *overlay_engine = filtered_engs[0];
    free(filtered_engs);
    return true;
}

static const __u32 any_rgb_format[] = {
    DRM_FORMAT_C8,
    DRM_FORMAT_RGB332,
    DRM_FORMAT_BGR233,
    DRM_FORMAT_XRGB1555,
    DRM_FORMAT_XBGR1555,
    DRM_FORMAT_RGBX5551,
    DRM_FORMAT_BGRX5551,
    DRM_FORMAT_ARGB1555,
    DRM_FORMAT_ABGR1555,
    DRM_FORMAT_RGBA5551,
    DRM_FORMAT_BGRA5551,
    DRM_FORMAT_RGB565,
    DRM_FORMAT_BGR565,
    DRM_FORMAT_RGB888,
    DRM_FORMAT_BGR888,
    DRM_FORMAT_XRGB8888,
    DRM_FORMAT_XBGR8888,
    DRM_FORMAT_RGBX8888,
    DRM_FORMAT_BGRX8888,
    DRM_FORMAT_XRGB2101010,
    DRM_FORMAT_XBGR2101010,
    DRM_FORMAT_RGBX1010102,
    DRM_FORMAT_BGRX1010102,
    DRM_FORMAT_ARGB2101010,
    DRM_FORMAT_ABGR2101010,
    DRM_FORMAT_RGBA1010102,
    DRM_FORMAT_BGRA1010102,
    DRM_FORMAT_ARGB8888,
    DRM_FORMAT_ABGR8888,
    DRM_FORMAT_RGBA8888,
    DRM_FORMAT_BGRA8888,
};

int adf_find_simple_post_configuration(struct adf_device *dev,
        const __u32 *formats, size_t n_formats,
        adf_id_t *interface, adf_id_t *overlay_engine)
{
    adf_id_t *intfs = NULL;
    ssize_t n_intfs = adf_interfaces(dev, &intfs);

    if (n_intfs < 0)
        return n_intfs;
    else if (!n_intfs)
        return -ENODEV;

    adf_id_t *primary_intfs;
    ssize_t n_primary_intfs = adf_interfaces_filter_by_flag(dev,
            ADF_INTF_FLAG_PRIMARY, intfs, n_intfs, &primary_intfs);
    free(intfs);

    if (n_primary_intfs < 0)
        return n_primary_intfs;
    else if (!n_primary_intfs)
        return -ENODEV;

    if (!formats) {
        formats = any_rgb_format;
        n_formats = sizeof(any_rgb_format) / sizeof(any_rgb_format[0]);
    }

    bool found = false;
    ssize_t i = 0;
    for (i = 0; i < n_primary_intfs; i++) {
        found = adf_find_simple_post_overlay_engine(dev, formats, n_formats,
                primary_intfs[i], overlay_engine);
        if (found) {
            *interface = primary_intfs[i];
            break;
        }
    }
    free(primary_intfs);

    if (!found)
        return -ENODEV;

    return 0;
}
