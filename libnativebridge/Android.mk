LOCAL_PATH:= $(call my-dir)

NATIVE_BRIDGE_COMMON_SRC_FILES := \
  native_bridge.cc

# Shared library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativebridge

LOCAL_SRC_FILES:= $(NATIVE_BRIDGE_COMMON_SRC_FILES)
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++11 -fvisibility=protected
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_SHARED_LIBRARY)

# Shared library for host
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativebridge

LOCAL_SRC_FILES:= $(NATIVE_BRIDGE_COMMON_SRC_FILES)
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++11 -fvisibility=protected
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_HOST_SHARED_LIBRARY)

# Static library for host
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativebridge

LOCAL_SRC_FILES:= $(NATIVE_BRIDGE_COMMON_SRC_FILES)
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_CLANG := true
LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++11 -fvisibility=protected
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_HOST_STATIC_LIBRARY)


include $(LOCAL_PATH)/tests/Android.mk
