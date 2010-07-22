LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# Shared library for target
# ========================================================

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libacc
LOCAL_SRC_FILES := acc.cpp

LOCAL_SHARED_LIBRARIES := libdl libcutils

include $(BUILD_SHARED_LIBRARY)

# Static library for host
# ========================================================

include $(CLEAR_VARS)
LOCAL_MODULE:= libacc
LOCAL_SRC_FILES := acc.cpp

LOCAL_CFLAGS := -O0 -g

LOCAL_STATIC_LIBRARIES := libcutils
LOCAL_LDLIBS := -ldl

include $(BUILD_HOST_STATIC_LIBRARY)

# Build children
# ========================================================

include $(call all-makefiles-under,$(LOCAL_PATH))
