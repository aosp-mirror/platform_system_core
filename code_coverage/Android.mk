# policies to allow processes inside minijail to dump code coverage information
#

LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)
LOCAL_MODULE := code_coverage.policy
LOCAL_MODULE_CLASS := ETC
LOCAL_MULTILIB := both

ifeq ($(TARGET_ARCH), $(filter $(TARGET_ARCH), arm arm64))
LOCAL_MODULE_STEM_32 := code_coverage.arm.policy
LOCAL_MODULE_STEM_64 := code_coverage.arm64.policy
endif

ifeq ($(TARGET_ARCH), $(filter $(TARGET_ARCH), x86 x86_64))
LOCAL_MODULE_STEM_32 := code_coverage.x86.policy
LOCAL_MODULE_STEM_64 := code_coverage.x86_64.policy
endif

# different files for different configurations
ifeq ($(NATIVE_COVERAGE),true)
LOCAL_SRC_FILES_arm := seccomp_policy/code_coverage.arm.policy
LOCAL_SRC_FILES_arm64 := seccomp_policy/code_coverage.arm64.policy
LOCAL_SRC_FILES_x86 := seccomp_policy/code_coverage.x86.policy
LOCAL_SRC_FILES_x86_64 := seccomp_policy/code_coverage.x86_64.policy
else
LOCAL_SRC_FILES_arm := empty_policy/code_coverage.arm.policy
LOCAL_SRC_FILES_arm64 := empty_policy/code_coverage.arm64.policy
LOCAL_SRC_FILES_x86 := empty_policy/code_coverage.x86.policy
LOCAL_SRC_FILES_x86_64 := empty_policy/code_coverage.x86_64.policy
endif

LOCAL_MODULE_TARGET_ARCH := arm arm64 x86 x86_64
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/seccomp_policy
include $(BUILD_PREBUILT)
