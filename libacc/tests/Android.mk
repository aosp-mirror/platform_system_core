LOCAL_PATH:= $(call my-dir)

# Executable for host
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE:= acc

LOCAL_SRC_FILES:= \
	main.cpp

LOCAL_SHARED_LIBRARIES := \
    libacc

LOCAL_MODULE_TAGS := tests

include $(BUILD_HOST_EXECUTABLE)

# Executable for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE:= acc

LOCAL_SRC_FILES:= \
	main.cpp

LOCAL_SHARED_LIBRARIES := \
    libacc

LOCAL_CFLAGS := -O0 -g 

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)

# Runtime tests for host
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE:= accRuntimeTest

LOCAL_SRC_FILES:= \
	runtimeTest.cpp

LOCAL_SHARED_LIBRARIES := \
    libacc

LOCAL_MODULE_TAGS := tests

include $(BUILD_HOST_EXECUTABLE)

# Runtime tests for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE:= accRuntimeTest

LOCAL_SRC_FILES:= \
	runtimeTest.cpp

LOCAL_SHARED_LIBRARIES := \
    libacc

LOCAL_CFLAGS := -O0 -g 

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
