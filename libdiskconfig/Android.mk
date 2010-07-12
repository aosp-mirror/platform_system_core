LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

ifneq ($(TARGET_SIMULATOR),true)


commonSources := \
	diskconfig.c \
	diskutils.c \
	write_lst.c \
	config_mbr.c

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(commonSources)
LOCAL_MODULE := libdiskconfig
LOCAL_SYSTEM_SHARED_LIBRARIES := libcutils liblog libc
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(commonSources)
LOCAL_MODULE := libdiskconfig_host
LOCAL_SYSTEM_SHARED_LIBRARIES := libcutils
LOCAL_CFLAGS := -O2 -g -W -Wall -Werror -D_LARGEFILE64_SOURCE
include $(BUILD_HOST_STATIC_LIBRARY)



endif  # ! TARGET_SIMULATOR
