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

#ifndef _LIBADF_ADF_H_
#define _LIBADF_ADF_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <video/adf.h>

typedef __u32 adf_id_t;

struct adf_device {
    adf_id_t id;
    int fd;
};

__BEGIN_DECLS

/**
 * Enumerates all ADF devices.
 *
 * Returns the number of ADF devices, and sets ids to a list of device IDs.
 * The caller must free() the returned list of device IDs.
 *
 * On error, returns -errno.
 */
ssize_t adf_devices(adf_id_t **ids);

/**
 * Opens an ADF device.
 *
 * On error, returns -errno.
 */
int adf_device_open(adf_id_t id, int flags, struct adf_device *dev);
/**
 * Closes an ADF device.
 */
void adf_device_close(struct adf_device *dev);
/**
 * Reads the ADF device data.
 *
 * adf_get_device_data() allocates buffers inside data, which the caller
 * must free by calling adf_free_device_data().  On error, returns -errno.
 */
int adf_get_device_data(struct adf_device *dev, struct adf_device_data *data);
/**
 * Frees the device data returned by adf_get_device_data().
 */
void adf_free_device_data(struct adf_device_data *data);

/**
 * Atomically posts a new display configuration to the specified interfaces.
 *
 * Returns a sync fence fd that will fire when the configuration is removed
 * from the screen.  On error, returns -errno.
 */
int adf_device_post(struct adf_device *dev,
        adf_id_t *interfaces, size_t n_interfaces,
        struct adf_buffer_config *bufs, size_t n_bufs,
        void *custom_data, size_t custom_data_size);
/**
 * Atomically posts a new display configuration to the specified interfaces.
 *
 * Compared to adf_device_post(), adf_device_post_v2():
 *
 *  (*) allows the client to choose the kind of sync fence returned
 *      (through complete_fence_type)
 *
 *  (*) stores the returned sync fence fd in a provided buffer, so the client
 *      can distinguish between a permission error (ret = -1) and a successful
 *      call that returns no fence (*complete_fence = -1)
 *
 * On error, returns -errno.
 *
 * On devices without the corresponding kernel support, returns -ENOTTY.
 */
int adf_device_post_v2(struct adf_device *dev,
        adf_id_t *interfaces, __u32 n_interfaces,
        struct adf_buffer_config *bufs, __u32 n_bufs,
        void *custom_data, __u64 custom_data_size,
        enum adf_complete_fence_type complete_fence_type,
        int *complete_fence);

/**
 * Attaches the specified interface and overlay engine.
 */
int adf_device_attach(struct adf_device *dev, adf_id_t overlay_engine,
                      adf_id_t interface);
/**
 * Detaches the specified interface and overlay engine.
 */
int adf_device_detach(struct adf_device *dev, adf_id_t overlay_engine,
                      adf_id_t interface);

/**
 * Enumerates all interfaces belonging to an ADF device.
 *
 * The caller must free() the returned list of interface IDs.
 */
ssize_t adf_interfaces(struct adf_device *dev, adf_id_t **interfaces);

/**
 * Enumerates all interfaces which can be attached to the specified overlay
 * engine.
 *
 * The caller must free() the returned list of interface IDs.
 */
ssize_t adf_interfaces_for_overlay_engine(struct adf_device *dev,
        adf_id_t overlay_engine, adf_id_t **interfaces);
/**
 * Filters a list of interfaces by type.
 *
 * Returns the number of matching interfaces, and sets out to a list of matching
 * interface IDs.  The caller must free() the returned list of interface IDs.
 *
 * On error, returns -errno.
 */
ssize_t adf_interfaces_filter_by_type(struct adf_device *dev,
        enum adf_interface_type type,
        adf_id_t *in, size_t n_in, adf_id_t **out);
/**
 * Filters a list of interfaces by flag.
 *
 * The caller must free() the returned list of interface IDs.
 */
ssize_t adf_interfaces_filter_by_flag(struct adf_device *dev, __u32 flag,
        adf_id_t *in, size_t n_in, adf_id_t **out);

/**
 * Opens an ADF interface.
 *
 * Returns a file descriptor.  The caller must close() the fd when done.
 * On error, returns -errno.
 */
int adf_interface_open(struct adf_device *dev, adf_id_t id, int flags);
/**
 * Reads the interface data.
 *
 * adf_get_interface_data() allocates buffers inside data, which the caller
 * must free by calling adf_free_interface_data().  On error, returns -errno.
 */
int adf_get_interface_data(int fd, struct adf_interface_data *data);
/**
 * Frees the interface data returned by adf_get_interface_data().
 */
void adf_free_interface_data(struct adf_interface_data *data);

/**
 * Sets the interface's DPMS mode.
 */
int adf_interface_blank(int fd, __u8 mode);
/**
 * Sets the interface's display mode.
 */
int adf_interface_set_mode(int fd, struct drm_mode_modeinfo *mode);
/**
 * Allocates a single-plane RGB buffer of the specified size and format.
 *
 * Returns a dma-buf fd.  On error, returns -errno.
 */
int adf_interface_simple_buffer_alloc(int fd, __u32 w, __u32 h,
        __u32 format, __u32 *offset, __u32 *pitch);
/**
 * Posts a single-plane RGB buffer to the display using the specified
 * overlay engine.
 *
 * Returns a sync fence fd that will fire when the buffer is removed
 * from the screen.  On error, returns -errno.
 */
int adf_interface_simple_post(int fd, adf_id_t overlay_engine,
        __u32 w, __u32 h, __u32 format, int buf_fd, __u32 offset,
        __u32 pitch, int acquire_fence);
/**
 * Posts a single-plane RGB buffer to the display using the specified
 * overlay engine.
 *
 * Compared to adf_interface_simple_post(), adf_interface_simple_post_v2():
 *
 *  (*) allows the client to choose the kind of sync fence returned
 *      (through complete_fence_type)
 *
 *  (*) stores the returned sync fence fd in a provided buffer, so the client
 *      can distinguish between a permission error (ret = -1) and a successful
 *      call that returns no fence (*complete_fence = -1)
 *
 * On error, returns -errno.
 *
 * On devices without the corresponding kernel support, returns -ENOTTY.
 */
int adf_interface_simple_post_v2(int fd, adf_id_t overlay_engine,
        __u32 w, __u32 h, __u32 format, int buf_fd, __u32 offset,
        __u32 pitch, int acquire_fence,
        enum adf_complete_fence_type complete_fence_type,
        int *complete_fence);

/**
 * Enumerates all overlay engines belonging to an ADF device.
 *
 * The caller must free() the returned list of overlay engine IDs.
 */
ssize_t adf_overlay_engines(struct adf_device *dev, adf_id_t **overlay_engines);

/**
 * Enumerates all overlay engines which can be attached to the specified
 * interface.
 *
 * The caller must free() the returned list of overlay engine IDs.
 */
ssize_t adf_overlay_engines_for_interface(struct adf_device *dev,
        adf_id_t interface, adf_id_t **overlay_engines);
/**
 * Filters a list of overlay engines by supported buffer format.
 *
 * Returns the overlay engines which support at least one of the specified
 * formats.  The caller must free() the returned list of overlay engine IDs.
 */
ssize_t adf_overlay_engines_filter_by_format(struct adf_device *dev,
        const __u32 *formats, size_t n_formats, adf_id_t *in, size_t n_in,
        adf_id_t **out);

/**
 * Opens an ADF overlay engine.
 *
 * Returns a file descriptor.  The caller must close() the fd when done.
 * On error, returns -errno.
 */
int adf_overlay_engine_open(struct adf_device *dev, adf_id_t id, int flags);
/**
 * Reads the overlay engine data.
 *
 * adf_get_overlay_engine_data() allocates buffers inside data, which the caller
 * must free by calling adf_free_overlay_engine_data().  On error, returns
 * -errno.
 */
int adf_get_overlay_engine_data(int fd, struct adf_overlay_engine_data *data);
/**
 * Frees the overlay engine data returned by adf_get_overlay_engine_data().
 */
void adf_free_overlay_engine_data(struct adf_overlay_engine_data *data);

/**
 * Returns whether the overlay engine supports the specified format.
 */
bool adf_overlay_engine_supports_format(int fd, __u32 format);

/**
 * Subscribes or unsubscribes from the specified hardware event.
 */
int adf_set_event(int fd, enum adf_event_type type, bool enabled);
/**
 * Reads one event from the fd, blocking if needed.
 *
 * The caller must free() the returned buffer.  On error, returns -errno.
 */
int adf_read_event(int fd, struct adf_event **event);

#define ADF_FORMAT_STR_SIZE 5
/**
 * Converts an ADF/DRM fourcc format to its string representation.
 */
void adf_format_str(__u32 format, char buf[ADF_FORMAT_STR_SIZE]);

/**
 * Finds an appropriate interface and overlay engine for a simple post.
 *
 * Specifically, finds the primary interface, and an overlay engine
 * that can be attached to the primary interface and supports one of the
 * specified formats.  The caller may pass a NULL formats list, to indicate that
 * any RGB format is acceptable.
 *
 * On error, returns -errno.
 */
int adf_find_simple_post_configuration(struct adf_device *dev,
        const __u32 *formats, size_t n_formats,
        adf_id_t *interface, adf_id_t *overlay_engine);

__END_DECLS

#endif /* _LIBADF_ADF_H_ */
