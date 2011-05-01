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

#ifndef SYSTEM_CORE_INCLUDE_ANDROID_CAMERA_H
#define SYSTEM_CORE_INCLUDE_ANDROID_CAMERA_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <cutils/native_handle.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>

__BEGIN_DECLS

/**
 * A set of bit masks for specifying how the received preview frames are
 * handled before the previewCallback() call.
 *
 * The least significant 3 bits of an "int" value are used for this purpose:
 *
 * ..... 0 0 0
 *       ^ ^ ^
 *       | | |---------> determine whether the callback is enabled or not
 *       | |-----------> determine whether the callback is one-shot or not
 *       |-------------> determine whether the frame is copied out or not
 *
 * WARNING: When a frame is sent directly without copying, it is the frame
 * receiver's responsiblity to make sure that the frame data won't get
 * corrupted by subsequent preview frames filled by the camera. This flag is
 * recommended only when copying out data brings significant performance price
 * and the handling/processing of the received frame data is always faster than
 * the preview frame rate so that data corruption won't occur.
 *
 * For instance,
 * 1. 0x00 disables the callback. In this case, copy out and one shot bits
 *    are ignored.
 * 2. 0x01 enables a callback without copying out the received frames. A
 *    typical use case is the Camcorder application to avoid making costly
 *    frame copies.
 * 3. 0x05 is enabling a callback with frame copied out repeatedly. A typical
 *    use case is the Camera application.
 * 4. 0x07 is enabling a callback with frame copied out only once. A typical
 *    use case is the Barcode scanner application.
 */

enum {
    CAMERA_FRAME_CALLBACK_FLAG_ENABLE_MASK = 0x01,
    CAMERA_FRAME_CALLBACK_FLAG_ONE_SHOT_MASK = 0x02,
    CAMERA_FRAME_CALLBACK_FLAG_COPY_OUT_MASK = 0x04,
    /** Typical use cases */
    CAMERA_FRAME_CALLBACK_FLAG_NOOP = 0x00,
    CAMERA_FRAME_CALLBACK_FLAG_CAMCORDER = 0x01,
    CAMERA_FRAME_CALLBACK_FLAG_CAMERA = 0x05,
    CAMERA_FRAME_CALLBACK_FLAG_BARCODE_SCANNER = 0x07
};

/** msgType in notifyCallback and dataCallback functions */
enum {
    CAMERA_MSG_ERROR = 0x0001,
    CAMERA_MSG_SHUTTER = 0x0002,
    CAMERA_MSG_FOCUS = 0x0004,
    CAMERA_MSG_ZOOM = 0x0008,
    CAMERA_MSG_PREVIEW_FRAME = 0x0010,
    CAMERA_MSG_VIDEO_FRAME = 0x0020,
    CAMERA_MSG_POSTVIEW_FRAME = 0x0040,
    CAMERA_MSG_RAW_IMAGE = 0x0080,
    CAMERA_MSG_COMPRESSED_IMAGE = 0x0100,
    CAMERA_MSG_RAW_IMAGE_NOTIFY = 0x0200,
    CAMERA_MSG_ALL_MSGS = 0xFFFF
};

/** cmdType in sendCommand functions */
enum {
    CAMERA_CMD_START_SMOOTH_ZOOM = 1,
    CAMERA_CMD_STOP_SMOOTH_ZOOM = 2,
    /** Set the clockwise rotation of preview display (setPreviewDisplay) in
     * degrees. This affects the preview frames and the picture displayed after
     * snapshot. This method is useful for portrait mode applications. Note
     * that preview display of front-facing cameras is flipped horizontally
     * before the rotation, that is, the image is reflected along the central
     * vertical axis of the camera sensor. So the users can see themselves as
     * looking into a mirror.
     *
     * This does not affect the order of byte array of
     * CAMERA_MSG_PREVIEW_FRAME, CAMERA_MSG_VIDEO_FRAME,
     * CAMERA_MSG_POSTVIEW_FRAME, CAMERA_MSG_RAW_IMAGE, or
     * CAMERA_MSG_COMPRESSED_IMAGE. This is not allowed to be set during
     * preview
     */
    CAMERA_CMD_SET_DISPLAY_ORIENTATION = 3,

    /** cmdType to disable/enable shutter sound. In sendCommand passing arg1 =
     * 0 will disable, while passing arg1 = 1 will enable the shutter sound.
     */
    CAMERA_CMD_ENABLE_SHUTTER_SOUND = 4,

    /* cmdType to play recording sound */
    CAMERA_CMD_PLAY_RECORDING_SOUND = 5,
};

/** camera fatal errors */
enum {
    CAMERA_ERROR_UNKNOWN = 1,
    CAMERA_ERROR_SERVER_DIED = 100
};

enum {
    CAMERA_FACING_BACK = 0, /** The facing of the camera is opposite to that of
                 * the screen. */
    CAMERA_FACING_FRONT = 1 /** The facing of the camera is the same as that of
                 * the screen. */
};

__END_DECLS

#endif /* SYSTEM_CORE_INCLUDE_ANDROID_CAMERA_H */
