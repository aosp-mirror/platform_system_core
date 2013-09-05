# Copyright (C) 2013 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
    external/openssl/include \
    $(LOCAL_PATH)/include \
    external/zlib/ \

LOCAL_SRC_FILES := \
    config.c \
    commands.c \
    commands/boot.c \
    commands/flash.c \
    commands/partitions.c \
    commands/virtual_partitions.c \
    fastbootd.c \
    protocol.c \
    socket_client.c \
    transport.c \
    transport_socket.c \
    trigger.c \
    usb_linux_client.c \
    utils.c

LOCAL_MODULE := fastbootd
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
LOCAL_LDFLAGS := -ldl

LOCAL_SHARED_LIBRARIES := \
    libhardware \
    libhardware_legacy

LOCAL_STATIC_LIBRARIES := \
    libsparse_static \
    libc \
    libcutils \
    libz

#LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := \
    external/zlib/

LOCAL_SRC_FILES := \
    commands/partitions.c \
    other/gptedit.c \
    utils.c

LOCAL_MODULE := gptedit
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter

LOCAL_STATIC_LIBRARIES := \
    libsparse_static \
    libc \
    libcutils \
    libz

LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \

LOCAL_STATIC_LIBRARIES := \
    $(EXTRA_STATIC_LIBS) \
    libcutils

LOCAL_SRC_FILES := \
    other/vendor_trigger.c

LOCAL_MODULE := libvendortrigger.default
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter


include $(BUILD_SHARED_LIBRARY)
