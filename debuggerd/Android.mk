LOCAL_PATH:= $(call my-dir)

debuggerd_2nd_arch_var_prefix :=
include $(LOCAL_PATH)/debuggerd.mk

ifdef TARGET_2ND_ARCH
debuggerd_2nd_arch_var_prefix := $(TARGET_2ND_ARCH_VAR_PREFIX)
include $(LOCAL_PATH)/debuggerd.mk
endif

ifeq ($(ARCH_ARM_HAVE_VFP),true)
include $(CLEAR_VARS)

LOCAL_CFLAGS += -DWITH_VFP
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_CFLAGS += -DWITH_VFP_D32
endif # ARCH_ARM_HAVE_VFP_D32

LOCAL_SRC_FILES := vfp-crasher.c arm/vfp.S
LOCAL_MODULE := vfp-crasher
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libcutils liblog libc
LOCAL_MODULE_TARGET_ARCH := arm
include $(BUILD_EXECUTABLE)
endif # ARCH_ARM_HAVE_VFP == true

include $(CLEAR_VARS)
LOCAL_SRC_FILES := vfp-crasher.c arm64/vfp.S
LOCAL_MODULE := vfp-crasher64
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libcutils liblog libc
LOCAL_MODULE_TARGET_ARCH := arm64
include $(BUILD_EXECUTABLE)
