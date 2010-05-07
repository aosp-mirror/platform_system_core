LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

ifneq ($(TARGET_SIMULATOR),true)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	diskconfig.c \
	diskutils.c \
	write_lst.c \
	config_mbr.c

LOCAL_MODULE := libdiskconfig
LOCAL_SYSTEM_SHARED_LIBRARIES := libcutils liblog libc

include $(BUILD_SHARED_LIBRARY)

endif  # ! TARGET_SIMULATOR
