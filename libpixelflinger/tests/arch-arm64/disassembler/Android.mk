LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    arm64_diassembler_test.cpp \
    ../../../codeflinger/Arm64Disassembler.cpp

LOCAL_SHARED_LIBRARIES :=

LOCAL_MODULE:= test-pixelflinger-arm64-disassembler-test

LOCAL_CFLAGS := -Wall -Werror

LOCAL_MODULE_TAGS := tests

LOCAL_MULTILIB := 64

include $(BUILD_NATIVE_TEST)
