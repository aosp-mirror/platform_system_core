LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := sync.c
LOCAL_MODULE := libsync
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Werror
include $(BUILD_SHARED_LIBRARY)

# libsync_recovery is only intended for the recovery binary.
# Future versions of the kernel WILL require an updated libsync, and will break
# anything statically linked against the current libsync.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := sync.c
LOCAL_MODULE := libsync_recovery
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Werror
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := sync.c sync_test.c
LOCAL_MODULE := sync_test
LOCAL_MODULE_TAGS := optional tests
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Werror
include $(BUILD_EXECUTABLE)
