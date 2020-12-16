# u-blox modifications
# for android 9 and later
ifeq (1,$(strip $(shell expr $(PLATFORM_VERSION) \>= 9)))
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := dhcptool.c
LOCAL_SHARED_LIBRARIES := libnetutils
LOCAL_MODULE := dhcptool
LOCAL_VENDOR_MODULE:= true
include $(BUILD_EXECUTABLE)
endif
# u-blox modifications
