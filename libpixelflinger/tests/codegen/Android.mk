LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	codegen.cpp

LOCAL_SHARED_LIBRARIES := \
	libcutils \
    libpixelflinger

LOCAL_MODULE:= test-opengl-codegen

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
