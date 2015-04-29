LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

# ========================================================
# Executable
# ========================================================
include $(CLEAR_VARS)
LOCAL_SRC_FILES:= tzdatacheck.cpp
LOCAL_MODULE := tzdatacheck
LOCAL_SHARED_LIBRARIES := libbase libcutils liblog
LOCAL_CFLAGS := -Werror
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= tzdatacheck.cpp
LOCAL_MODULE := tzdatacheck
LOCAL_SHARED_LIBRARIES := libbase libcutils liblog
LOCAL_CFLAGS := -Werror
include $(BUILD_HOST_EXECUTABLE)

