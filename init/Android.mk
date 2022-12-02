# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := init_vendor
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
ifneq ($(BOARD_USES_RECOVERY_AS_BOOT),true)
LOCAL_REQUIRED_MODULES := \
   init_first_stage \

endif  # BOARD_USES_RECOVERY_AS_BOOT
include $(BUILD_PHONY_PACKAGE)
