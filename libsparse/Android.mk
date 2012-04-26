# Copyright 2010 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

libsparse_src_files := \
        backed_block.c \
        output_file.c \
        sparse.c \
        sparse_crc32.c \
        sparse_err.c \
        sparse_read.c

include $(CLEAR_VARS)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := $(libsparse_src_files)
LOCAL_MODULE := libsparse
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libz
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include external/zlib

include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := $(libsparse_src_files)
LOCAL_MODULE := libsparse
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include external/zlib
LOCAL_SHARED_LIBRARIES := libz

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := $(libsparse_src_files)
LOCAL_MODULE := libsparse
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include external/zlib
LOCAL_STATIC_LIBRARIES := libz

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := simg2img.c \
	sparse_crc32.c
LOCAL_MODULE := simg2img
LOCAL_MODULE_TAGS := debug
LOCAL_STATIC_LIBRARIES := libsparse libz

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := simg2img.c \
	sparse_crc32.c
LOCAL_MODULE := simg2img
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libsparse libz

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := img2simg.c
LOCAL_MODULE := img2simg
LOCAL_MODULE_TAGS := debug
LOCAL_STATIC_LIBRARIES := libsparse libz

include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := img2simg.c
LOCAL_MODULE := img2simg
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libsparse libz

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := simg_dump.py
LOCAL_MODULE_TAGS := debug
LOCAL_SRC_FILES := simg_dump.py
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true

include $(BUILD_PREBUILT)
