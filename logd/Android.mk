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
    LogTimes.cpp \
    LogStatistics.cpp \
    LogWhiteBlackList.cpp \
    libaudit.c \
    LogAudit.cpp \
    event.logtags

LOCAL_SHARED_LIBRARIES := \
    libsysutils \
    liblog \
    libcutils \
    libutils

# This is what we want to do:
#  event_logtags = $(shell \
#    sed -n \
#        "s/^\([0-9]*\)[ \t]*$1[ \t].*/-D`echo $1 | tr a-z A-Z`_LOG_TAG=\1/p" \
#        $(LOCAL_PATH)/$2/event.logtags)
#  event_flag := $(call event_logtags,auditd)
# so make sure we do not regret hard-coding it as follows:
event_flag := -DAUDITD_LOG_TAG=1003

LOCAL_CFLAGS := -Werror $(event_flag)

include $(BUILD_EXECUTABLE)

include $(call first-makefiles-under,$(LOCAL_PATH))
