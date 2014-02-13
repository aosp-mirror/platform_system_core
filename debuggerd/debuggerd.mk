# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	backtrace.cpp \
	debuggerd.cpp \
	getevent.cpp \
	tombstone.cpp \
	utility.cpp \

LOCAL_SRC_FILES_arm    := arm/machine.cpp
LOCAL_SRC_FILES_arm64  := arm64/machine.cpp
LOCAL_SRC_FILES_mips   := mips/machine.cpp
LOCAL_SRC_FILES_x86    := x86/machine.cpp
LOCAL_SRC_FILES_x86_64 := x86_64/machine.cpp

LOCAL_CONLYFLAGS := -std=gnu99
LOCAL_CPPFLAGS := -std=gnu++11
LOCAL_CFLAGS := \
	-Wall \
	-Wno-array-bounds \
	-Werror \
	-Wno-unused-parameter \

ifeq ($(ARCH_ARM_HAVE_VFP),true)
LOCAL_CFLAGS_arm += -DWITH_VFP
endif # ARCH_ARM_HAVE_VFP
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_CFLAGS_arm += -DWITH_VFP_D32
endif # ARCH_ARM_HAVE_VFP_D32

LOCAL_SHARED_LIBRARIES := \
	libbacktrace \
	libc \
	libcutils \
	liblog \
	libselinux \

include external/stlport/libstlport.mk

ifeq ($(TARGET_IS_64_BIT)|$(debuggerd_2nd_arch_var_prefix),true|)
LOCAL_MODULE := debuggerd64
LOCAL_NO_2ND_ARCH := true
else
LOCAL_MODULE := debuggerd
LOCAL_32_BIT_ONLY := true
endif

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := crasher.c
LOCAL_SRC_FILES_arm    := arm/crashglue.S
LOCAL_SRC_FILES_arm64  := arm64/crashglue.S
LOCAL_SRC_FILES_mips   := mips/crashglue.S
LOCAL_SRC_FILES_x86    := x86/crashglue.S
LOCAL_SRC_FILES_x86_64 := x86_64/crashglue.S
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -fstack-protector-all -Wno-unused-parameter -Wno-free-nonheap-object
#LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SHARED_LIBRARIES := libcutils liblog libc

LOCAL_2ND_ARCH_VAR_PREFIX := $(debuggerd_2nd_arch_var_prefix)

ifeq ($(TARGET_IS_64_BIT)|$(debuggerd_2nd_arch_var_prefix),true|)
LOCAL_MODULE := crasher64
LOCAL_NO_2ND_ARCH := true
else
LOCAL_MODULE := crasher
LOCAL_32_BIT_ONLY := true
endif
include $(BUILD_EXECUTABLE)
