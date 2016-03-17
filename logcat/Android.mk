# Copyright 2006-2014 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= logcat.cpp event.logtags

LOCAL_SHARED_LIBRARIES := liblog libbase libcutils libpcrecpp

LOCAL_MODULE := logcat

LOCAL_CFLAGS := -Werror

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := logpersist.start
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_INIT_RC := logcatd.rc
LOCAL_MODULE_PATH := $(bin_dir)
LOCAL_SRC_FILES := logpersist
ALL_TOOLS := logpersist.start logpersist.stop logpersist.cat
LOCAL_POST_INSTALL_CMD := $(hide) $(foreach t,$(filter-out $(LOCAL_MODULE),$(ALL_TOOLS)),ln -sf $(LOCAL_MODULE) $(TARGET_OUT)/bin/$(t);)
include $(BUILD_PREBUILT)

include $(call first-makefiles-under,$(LOCAL_PATH))
