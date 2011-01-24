ifneq ($(BUILD_TINY_ANDROID),true)
BUILD_LIBSYSUTILS := false
ifneq ($(TARGET_SIMULATOR),true)
    BUILD_LIBSYSUTILS := true
endif

ifeq ($(BUILD_LIBSYSUTILS),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                             \
                  src/SocketListener.cpp      \
                  src/FrameworkListener.cpp   \
                  src/NetlinkListener.cpp     \
                  src/NetlinkEvent.cpp        \
                  src/FrameworkCommand.cpp    \
                  src/SocketClient.cpp        \
                  src/ServiceManager.cpp      \

LOCAL_MODULE:= libsysutils

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) 

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

ifeq ($(TARGET_SIMULATOR),true)
  LOCAL_LDLIBS += -lpthread
endif

include $(BUILD_SHARED_LIBRARY)

endif
endif
