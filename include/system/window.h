/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef SYSTEM_CORE_INCLUDE_ANDROID_WINDOW_H
#define SYSTEM_CORE_INCLUDE_ANDROID_WINDOW_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <system/graphics.h>
#include <cutils/native_handle.h>

__BEGIN_DECLS

/*****************************************************************************/

#define ANDROID_NATIVE_MAKE_CONSTANT(a,b,c,d) \
    (((unsigned)(a)<<24)|((unsigned)(b)<<16)|((unsigned)(c)<<8)|(unsigned)(d))

#define ANDROID_NATIVE_WINDOW_MAGIC \
    ANDROID_NATIVE_MAKE_CONSTANT('_','w','n','d')

#define ANDROID_NATIVE_BUFFER_MAGIC \
    ANDROID_NATIVE_MAKE_CONSTANT('_','b','f','r')

// ---------------------------------------------------------------------------

typedef const native_handle_t* buffer_handle_t;

// ---------------------------------------------------------------------------

typedef struct android_native_rect_t
{
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} android_native_rect_t;

// ---------------------------------------------------------------------------

typedef struct android_native_base_t
{
    /* a magic value defined by the actual EGL native type */
    int magic;

    /* the sizeof() of the actual EGL native type */
    int version;

    void* reserved[4];

    /* reference-counting interface */
    void (*incRef)(struct android_native_base_t* base);
    void (*decRef)(struct android_native_base_t* base);
} android_native_base_t;

typedef struct ANativeWindowBuffer
{
#ifdef __cplusplus
    ANativeWindowBuffer() {
        common.magic = ANDROID_NATIVE_BUFFER_MAGIC;
        common.version = sizeof(ANativeWindowBuffer);
        memset(common.reserved, 0, sizeof(common.reserved));
    }

    // Implement the methods that sp<ANativeWindowBuffer> expects so that it
    // can be used to automatically refcount ANativeWindowBuffer's.
    void incStrong(const void* id) const {
        common.incRef(const_cast<android_native_base_t*>(&common));
    }
    void decStrong(const void* id) const {
        common.decRef(const_cast<android_native_base_t*>(&common));
    }
#endif

    struct android_native_base_t common;

    int width;
    int height;
    int stride;
    int format;
    int usage;

    void* reserved[2];

    buffer_handle_t handle;

    void* reserved_proc[8];
} ANativeWindowBuffer_t;

// Old typedef for backwards compatibility.
typedef ANativeWindowBuffer_t android_native_buffer_t;

// ---------------------------------------------------------------------------

/* attributes queriable with query() */
enum {
    NATIVE_WINDOW_WIDTH     = 0,
    NATIVE_WINDOW_HEIGHT,
    NATIVE_WINDOW_FORMAT,

    /* The minimum number of buffers that must remain un-dequeued after a buffer
     * has been queued.  This value applies only if set_buffer_count was used to
     * override the number of buffers and if a buffer has since been queued.
     * Users of the set_buffer_count ANativeWindow method should query this
     * value before calling set_buffer_count.  If it is necessary to have N
     * buffers simultaneously dequeued as part of the steady-state operation,
     * and this query returns M then N+M buffers should be requested via
     * native_window_set_buffer_count.
     *
     * Note that this value does NOT apply until a single buffer has been
     * queued.  In particular this means that it is possible to:
     *
     * 1. Query M = min undequeued buffers
     * 2. Set the buffer count to N + M
     * 3. Dequeue all N + M buffers
     * 4. Cancel M buffers
     * 5. Queue, dequeue, queue, dequeue, ad infinitum
     */
    NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS,

    /* Check whether queueBuffer operations on the ANativeWindow send the buffer
     * to the window compositor.  The query sets the returned 'value' argument
     * to 1 if the ANativeWindow DOES send queued buffers directly to the window
     * compositor and 0 if the buffers do not go directly to the window
     * compositor.
     *
     * This can be used to determine whether protected buffer content should be
     * sent to the ANativeWindow.  Note, however, that a result of 1 does NOT
     * indicate that queued buffers will be protected from applications or users
     * capturing their contents.  If that behavior is desired then some other
     * mechanism (e.g. the GRALLOC_USAGE_PROTECTED flag) should be used in
     * conjunction with this query.
     */
    NATIVE_WINDOW_QUEUES_TO_WINDOW_COMPOSER,

    /* Get the concrete type of a ANativeWindow.  See below for the list of
     * possible return values.
     *
     * This query should not be used outside the Android framework and will
     * likely be removed in the near future.
     */
    NATIVE_WINDOW_CONCRETE_TYPE,
};

/* valid operations for the (*perform)() hook */
enum {
    NATIVE_WINDOW_SET_USAGE  = 0,
    NATIVE_WINDOW_CONNECT,
    NATIVE_WINDOW_DISCONNECT,
    NATIVE_WINDOW_SET_CROP,
    NATIVE_WINDOW_SET_BUFFER_COUNT,
    NATIVE_WINDOW_SET_BUFFERS_GEOMETRY,
    NATIVE_WINDOW_SET_BUFFERS_TRANSFORM,
    NATIVE_WINDOW_SET_BUFFERS_TIMESTAMP,
};

/* parameter for NATIVE_WINDOW_[DIS]CONNECT */
enum {
    NATIVE_WINDOW_API_EGL = 1
};

/* parameter for NATIVE_WINDOW_SET_BUFFERS_TRANSFORM */
enum {
    /* flip source image horizontally */
    NATIVE_WINDOW_TRANSFORM_FLIP_H = HAL_TRANSFORM_FLIP_H ,
    /* flip source image vertically */
    NATIVE_WINDOW_TRANSFORM_FLIP_V = HAL_TRANSFORM_FLIP_V,
    /* rotate source image 90 degrees clock-wise */
    NATIVE_WINDOW_TRANSFORM_ROT_90 = HAL_TRANSFORM_ROT_90,
    /* rotate source image 180 degrees */
    NATIVE_WINDOW_TRANSFORM_ROT_180 = HAL_TRANSFORM_ROT_180,
    /* rotate source image 270 degrees clock-wise */
    NATIVE_WINDOW_TRANSFORM_ROT_270 = HAL_TRANSFORM_ROT_270,
};

/* values returned by the NATIVE_WINDOW_CONCRETE_TYPE query */
enum {
    NATIVE_WINDOW_FRAMEBUFFER,                  // FramebufferNativeWindow
    NATIVE_WINDOW_SURFACE,                      // Surface
    NATIVE_WINDOW_SURFACE_TEXTURE_CLIENT,       // SurfaceTextureClient
};

/* parameter for NATIVE_WINDOW_SET_BUFFERS_TIMESTAMP
 *
 * Special timestamp value to indicate that timestamps should be auto-generated
 * by the native window when queueBuffer is called.  This is equal to INT64_MIN,
 * defined directly to avoid problems with C99/C++ inclusion of stdint.h.
 */
static const int64_t NATIVE_WINDOW_TIMESTAMP_AUTO = (-9223372036854775807LL-1);

struct ANativeWindow
{
#ifdef __cplusplus
    ANativeWindow()
        : flags(0), minSwapInterval(0), maxSwapInterval(0), xdpi(0), ydpi(0)
    {
        common.magic = ANDROID_NATIVE_WINDOW_MAGIC;
        common.version = sizeof(ANativeWindow);
        memset(common.reserved, 0, sizeof(common.reserved));
    }

    // Implement the methods that sp<ANativeWindow> expects so that it
    // can be used to automatically refcount ANativeWindow's.
    void incStrong(const void* id) const {
        common.incRef(const_cast<android_native_base_t*>(&common));
    }
    void decStrong(const void* id) const {
        common.decRef(const_cast<android_native_base_t*>(&common));
    }
#endif

    struct android_native_base_t common;

    /* flags describing some attributes of this surface or its updater */
    const uint32_t flags;

    /* min swap interval supported by this updated */
    const int   minSwapInterval;

    /* max swap interval supported by this updated */
    const int   maxSwapInterval;

    /* horizontal and vertical resolution in DPI */
    const float xdpi;
    const float ydpi;

    /* Some storage reserved for the OEM's driver. */
    intptr_t    oem[4];

    /*
     * Set the swap interval for this surface.
     *
     * Returns 0 on success or -errno on error.
     */
    int     (*setSwapInterval)(struct ANativeWindow* window,
                int interval);

    /*
     * hook called by EGL to acquire a buffer. After this call, the buffer
     * is not locked, so its content cannot be modified.
     * this call may block if no buffers are available.
     *
     * Returns 0 on success or -errno on error.
     */
    int     (*dequeueBuffer)(struct ANativeWindow* window,
                struct ANativeWindowBuffer** buffer);

    /*
     * hook called by EGL to lock a buffer. This MUST be called before modifying
     * the content of a buffer. The buffer must have been acquired with
     * dequeueBuffer first.
     *
     * Returns 0 on success or -errno on error.
     */
    int     (*lockBuffer)(struct ANativeWindow* window,
                struct ANativeWindowBuffer* buffer);
   /*
    * hook called by EGL when modifications to the render buffer are done.
    * This unlocks and post the buffer.
    *
    * Buffers MUST be queued in the same order than they were dequeued.
    *
    * Returns 0 on success or -errno on error.
    */
    int     (*queueBuffer)(struct ANativeWindow* window,
                struct ANativeWindowBuffer* buffer);

    /*
     * hook used to retrieve information about the native window.
     *
     * Returns 0 on success or -errno on error.
     */
    int     (*query)(const struct ANativeWindow* window,
                int what, int* value);

    /*
     * hook used to perform various operations on the surface.
     * (*perform)() is a generic mechanism to add functionality to
     * ANativeWindow while keeping backward binary compatibility.
     *
     * DO NOT CALL THIS HOOK DIRECTLY.  Instead, use the helper functions
     * defined below.
     *
     *  (*perform)() returns -ENOENT if the 'what' parameter is not supported
     *  by the surface's implementation.
     *
     * The valid operations are:
     *     NATIVE_WINDOW_SET_USAGE
     *     NATIVE_WINDOW_CONNECT
     *     NATIVE_WINDOW_DISCONNECT
     *     NATIVE_WINDOW_SET_CROP
     *     NATIVE_WINDOW_SET_BUFFER_COUNT
     *     NATIVE_WINDOW_SET_BUFFERS_GEOMETRY
     *     NATIVE_WINDOW_SET_BUFFERS_TRANSFORM
     *     NATIVE_WINDOW_SET_BUFFERS_TIMESTAMP
     *
     */

    int     (*perform)(struct ANativeWindow* window,
                int operation, ... );

    /*
     * hook used to cancel a buffer that has been dequeued.
     * No synchronization is performed between dequeue() and cancel(), so
     * either external synchronization is needed, or these functions must be
     * called from the same thread.
     */
    int     (*cancelBuffer)(struct ANativeWindow* window,
                struct ANativeWindowBuffer* buffer);


    void* reserved_proc[2];
};

 /* Backwards compatibility: use ANativeWindow (struct ANativeWindow in C).
  * android_native_window_t is deprecated.
  */
typedef struct ANativeWindow ANativeWindow;
typedef struct ANativeWindow android_native_window_t;

/*
 *  native_window_set_usage(..., usage)
 *  Sets the intended usage flags for the next buffers
 *  acquired with (*lockBuffer)() and on.
 *  By default (if this function is never called), a usage of
 *      GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE
 *  is assumed.
 *  Calling this function will usually cause following buffers to be
 *  reallocated.
 */

static inline int native_window_set_usage(
        struct ANativeWindow* window, int usage)
{
    return window->perform(window, NATIVE_WINDOW_SET_USAGE, usage);
}

/*
 * native_window_connect(..., NATIVE_WINDOW_API_EGL)
 * Must be called by EGL when the window is made current.
 * Returns -EINVAL if for some reason the window cannot be connected, which
 * can happen if it's connected to some other API.
 */
static inline int native_window_connect(
        struct ANativeWindow* window, int api)
{
    return window->perform(window, NATIVE_WINDOW_CONNECT, api);
}

/*
 * native_window_disconnect(..., NATIVE_WINDOW_API_EGL)
 * Must be called by EGL when the window is made not current.
 * An error is returned if for instance the window wasn't connected in the
 * first place.
 */
static inline int native_window_disconnect(
        struct ANativeWindow* window, int api)
{
    return window->perform(window, NATIVE_WINDOW_DISCONNECT, api);
}

/*
 * native_window_set_crop(..., crop)
 * Sets which region of the next queued buffers needs to be considered.
 * A buffer's crop region is scaled to match the surface's size.
 *
 * The specified crop region applies to all buffers queued after it is called.
 *
 * if 'crop' is NULL, subsequently queued buffers won't be cropped.
 *
 * An error is returned if for instance the crop region is invalid,
 * out of the buffer's bound or if the window is invalid.
 */
static inline int native_window_set_crop(
        struct ANativeWindow* window,
        android_native_rect_t const * crop)
{
    return window->perform(window, NATIVE_WINDOW_SET_CROP, crop);
}

/*
 * native_window_set_buffer_count(..., count)
 * Sets the number of buffers associated with this native window.
 */
static inline int native_window_set_buffer_count(
        struct ANativeWindow* window,
        size_t bufferCount)
{
    return window->perform(window, NATIVE_WINDOW_SET_BUFFER_COUNT, bufferCount);
}

/*
 * native_window_set_buffers_geometry(..., int w, int h, int format)
 * All buffers dequeued after this call will have the geometry specified.
 * In particular, all buffers will have a fixed-size, independent form the
 * native-window size. They will be appropriately scaled to the window-size
 * upon composition.
 *
 * If all parameters are 0, the normal behavior is restored. That is,
 * dequeued buffers following this call will be sized to the window's size.
 *
 * Calling this function will reset the window crop to a NULL value, which
 * disables cropping of the buffers.
 */
static inline int native_window_set_buffers_geometry(
        struct ANativeWindow* window,
        int w, int h, int format)
{
    return window->perform(window, NATIVE_WINDOW_SET_BUFFERS_GEOMETRY,
            w, h, format);
}

/*
 * native_window_set_buffers_transform(..., int transform)
 * All buffers queued after this call will be displayed transformed according
 * to the transform parameter specified.
 */
static inline int native_window_set_buffers_transform(
        struct ANativeWindow* window,
        int transform)
{
    return window->perform(window, NATIVE_WINDOW_SET_BUFFERS_TRANSFORM,
            transform);
}

/*
 * native_window_set_buffers_timestamp(..., int64_t timestamp)
 * All buffers queued after this call will be associated with the timestamp
 * parameter specified. If the timestamp is set to NATIVE_WINDOW_TIMESTAMP_AUTO
 * (the default), timestamps will be generated automatically when queueBuffer is
 * called. The timestamp is measured in nanoseconds, and is normally monotonically
 * increasing. The timestamp should be unaffected by time-of-day adjustments,
 * and for a camera should be strictly monotonic but for a media player may be
 * reset when the position is set.
 */
static inline int native_window_set_buffers_timestamp(
        struct ANativeWindow* window,
        int64_t timestamp)
{
    return window->perform(window, NATIVE_WINDOW_SET_BUFFERS_TIMESTAMP,
            timestamp);
}

__END_DECLS

#endif /* SYSTEM_CORE_INCLUDE_ANDROID_WINDOW_H */
