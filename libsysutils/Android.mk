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
                  EventLogTags.logtags

LOCAL_MODULE:= libsysutils

LOCAL_CFLAGS := -Werror

LOCAL_SHARED_LIBRARIES := \
        libcutils \
        liblog \
        libnl

include $(BUILD_SHARED_LIBRARY)

