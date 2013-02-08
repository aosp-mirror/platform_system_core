LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= logd

ifneq ($(filter userdebug eng,$(TARGET_BUILD_VARIANT)),)
LOCAL_CFLAGS += -DUSERDEBUG_BUILD=1
endif

LOCAL_SRC_FILES := \
    main.cpp \
    LogCommand.cpp \
    CommandListener.cpp \
    LogListener.cpp \
    LogReader.cpp \
    FlushCommand.cpp \
    LogBuffer.cpp \
    LogBufferElement.cpp \
    LogTimes.cpp \
    LogStatistics.cpp \
    LogWhiteBlackList.cpp \
    libaudit.c \
    LogAudit.cpp

LOCAL_SHARED_LIBRARIES := \
    libsysutils \
    liblog \
    libcutils \
    libutils

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)
