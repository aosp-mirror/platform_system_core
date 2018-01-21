LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := crash_dump.policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MULTILIB := both

ifeq ($(TARGET_ARCH), $(filter $(TARGET_ARCH), arm arm64))
LOCAL_MODULE_STEM_32 := crash_dump.arm.policy
LOCAL_MODULE_STEM_64 := crash_dump.arm64.policy
endif

ifeq ($(TARGET_ARCH), $(filter $(TARGET_ARCH), x86 x86_64))
LOCAL_MODULE_STEM_32 := crash_dump.x86.policy
LOCAL_MODULE_STEM_64 := crash_dump.x86_64.policy
endif

LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/seccomp_policy
LOCAL_SRC_FILES_arm := seccomp_policy/crash_dump.arm.policy
LOCAL_SRC_FILES_arm64 := seccomp_policy/crash_dump.arm64.policy
LOCAL_SRC_FILES_x86 := seccomp_policy/crash_dump.x86.policy
LOCAL_SRC_FILES_x86_64 := seccomp_policy/crash_dump.x86_64.policy
include $(BUILD_PREBUILT)
