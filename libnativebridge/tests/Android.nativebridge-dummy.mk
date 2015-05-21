LOCAL_PATH:= $(call my-dir)

NATIVE_BRIDGE_COMMON_SRC_FILES := \
  DummyNativeBridge.cpp

# Shared library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativebridge-dummy

LOCAL_SRC_FILES:= $(NATIVE_BRIDGE_COMMON_SRC_FILES)
LOCAL_CLANG := true
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++11 -fvisibility=protected
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_SHARED_LIBRARY)

# Shared library for host
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativebridge-dummy

LOCAL_SRC_FILES:= $(NATIVE_BRIDGE_COMMON_SRC_FILES)
LOCAL_CLANG := true
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++11 -fvisibility=protected
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_HOST_SHARED_LIBRARY)


# v2.

NATIVE_BRIDGE2_COMMON_SRC_FILES := \
  DummyNativeBridge2.cpp

# Shared library for target
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativebridge2-dummy

LOCAL_SRC_FILES:= $(NATIVE_BRIDGE2_COMMON_SRC_FILES)
LOCAL_CLANG := true
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++11 -fvisibility=protected
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_SHARED_LIBRARY)

# Shared library for host
# ========================================================
include $(CLEAR_VARS)

LOCAL_MODULE:= libnativebridge2-dummy

LOCAL_SRC_FILES:= $(NATIVE_BRIDGE2_COMMON_SRC_FILES)
LOCAL_CLANG := true
LOCAL_CFLAGS += -Werror -Wall
LOCAL_CPPFLAGS := -std=gnu++11 -fvisibility=protected
LOCAL_LDFLAGS := -ldl
LOCAL_MULTILIB := both

include $(BUILD_HOST_SHARED_LIBRARY)
