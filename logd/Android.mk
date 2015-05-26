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
    LogKlog.cpp \
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
#  event_flag += $(call event_logtags,logd)
# so make sure we do not regret hard-coding it as follows:
event_flag := -DAUDITD_LOG_TAG=1003 -DLOGD_LOG_TAG=1004

LOCAL_CFLAGS := -Werror $(event_flag)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := logpersist.start
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(bin_dir)
LOCAL_SRC_FILES := logpersist
ALL_TOOLS := logpersist.start logpersist.stop logpersist.cat
LOCAL_POST_INSTALL_CMD := $(hide) $(foreach t,$(filter-out $(LOCAL_MODULE),$(ALL_TOOLS)),ln -sf $(LOCAL_MODULE) $(TARGET_OUT)/bin/$(t);)
include $(BUILD_PREBUILT)

include $(call first-makefiles-under,$(LOCAL_PATH))
