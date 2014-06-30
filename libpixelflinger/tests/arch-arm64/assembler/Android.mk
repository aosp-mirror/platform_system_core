LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    arm64_assembler_test.cpp\
    asm_test_jacket.S

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    libpixelflinger

LOCAL_C_INCLUDES := \
    system/core/libpixelflinger

LOCAL_MODULE:= test-pixelflinger-arm64-assembler-test

LOCAL_MODULE_TAGS := tests

LOCAL_MULTILIB := 64

include $(BUILD_NATIVE_TEST)
