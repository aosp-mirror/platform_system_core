LOCAL_PATH:= $(call my-dir)

NATIVE_LOADER_COMMON_SRC_FILES := \
  native_loader.cpp

# Shared library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativeloader

LOCAL_SRC_FILES:= $(NATIVE_LOADER_COMMON_SRC_FILES)
LOCAL_SHARED_LIBRARIES := libnativehelper liblog libcutils
LOCAL_STATIC_LIBRARIES := libbase
LOCAL_CLANG := true
LOCAL_CFLAGS += -Werror -Wall
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

LOCAL_SRC_FILES:= $(NATIVE_LOADER_COMMON_SRC_FILES)
LOCAL_SHARED_LIBRARIES := libnativehelper liblog libcutils
LOCAL_STATIC_LIBRARIES := libbase
LOCAL_CLANG := true
LOCAL_CFLAGS += -Werror -Wall
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

LOCAL_SRC_FILES:= $(NATIVE_LOADER_COMMON_SRC_FILES)
LOCAL_STATIC_LIBRARIES := libnativehelper libcutils liblog libbase
LOCAL_CLANG := true
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++14 -fvisibility=hidden
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
include $(BUILD_HOST_STATIC_LIBRARY)
