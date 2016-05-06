LOCAL_PATH:= $(call my-dir)

native_loader_common_src_files := \
  native_loader.cpp

native_loader_common_cflags := -Werror -Wall

# Shared library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativeloader

LOCAL_SRC_FILES:= $(native_loader_common_src_files)
LOCAL_SHARED_LIBRARIES := libnativehelper liblog libcutils
LOCAL_STATIC_LIBRARIES := libbase
LOCAL_CLANG := true
LOCAL_CFLAGS := $(native_loader_common_cflags)
LOCAL_CPPFLAGS := -std=gnu++14 -fvisibility=hidden
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
include $(BUILD_SHARED_LIBRARY)

# Shared library for host
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativeloader

LOCAL_SRC_FILES:= $(native_loader_common_src_files)
LOCAL_SHARED_LIBRARIES := libnativehelper liblog libcutils
LOCAL_STATIC_LIBRARIES := libbase
LOCAL_CLANG := true
LOCAL_CFLAGS := $(native_loader_common_cflags)
LOCAL_CPPFLAGS := -std=gnu++14 -fvisibility=hidden
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
include $(BUILD_HOST_SHARED_LIBRARY)

# Static library for host
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativeloader

LOCAL_SRC_FILES:= $(native_loader_common_src_files)
LOCAL_STATIC_LIBRARIES := libnativehelper libcutils liblog libbase
LOCAL_CLANG := true
LOCAL_CFLAGS := $(native_loader_common_cflags)
LOCAL_CPPFLAGS := -std=gnu++14 -fvisibility=hidden
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
include $(BUILD_HOST_STATIC_LIBRARY)
