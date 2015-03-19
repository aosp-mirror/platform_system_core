LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	gglmul_test.cpp

LOCAL_SHARED_LIBRARIES :=

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../../include

LOCAL_MODULE:= test-pixelflinger-gglmul

LOCAL_MODULE_TAGS := tests

include $(BUILD_NATIVE_TEST)
