LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    mips64_disassembler_test.cpp \
    ../../../codeflinger/mips64_disassem.c

LOCAL_SHARED_LIBRARIES :=

LOCAL_MODULE:= test-pixelflinger-mips64-disassembler-test

LOCAL_MODULE_TAGS := tests

LOCAL_MULTILIB := 64

include $(BUILD_NATIVE_TEST)
