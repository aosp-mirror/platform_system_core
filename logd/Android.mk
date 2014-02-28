ifeq ($(TARGET_USES_LOGD),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= logd

LOCAL_SRC_FILES := \
    main.cpp \
    LogCommand.cpp \
    CommandListener.cpp \
    LogListener.cpp \
    LogReader.cpp \
    FlushCommand.cpp \
    LogBuffer.cpp \
    LogBufferElement.cpp \
    LogTimes.cpp

LOCAL_SHARED_LIBRARIES := \
    libsysutils \
    liblog \
    libcutils

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

endif # TARGET_USES_LOGD
