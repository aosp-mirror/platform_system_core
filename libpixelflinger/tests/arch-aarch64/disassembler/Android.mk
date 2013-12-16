LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    aarch64_diassembler_test.cpp \
    ../../../codeflinger/Aarch64Disassembler.cpp

LOCAL_SHARED_LIBRARIES :=

LOCAL_C_INCLUDES := \
    system/core/libpixelflinger/codeflinger

LOCAL_MODULE:= test-pixelflinger-aarch64-disassembler-test

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
