LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    col32cb16blend_test.c \
    ../../../arch-arm64/col32cb16blend.S

LOCAL_CLANG_ASFLAGS_arm64 += -no-integrated-as

LOCAL_SHARED_LIBRARIES :=

LOCAL_C_INCLUDES :=

LOCAL_MODULE:= test-pixelflinger-arm64-col32cb16blend

LOCAL_MODULE_TAGS := tests

LOCAL_MULTILIB := 64

include $(BUILD_NATIVE_TEST)
