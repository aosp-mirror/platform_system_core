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
	-Werror

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

LOCAL_MODULE := debuggerd
LOCAL_MODULE_STEM_32 := debuggerd
LOCAL_MODULE_STEM_64 := debuggerd64
LOCAL_MULTILIB := both

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
LOCAL_CFLAGS += -fstack-protector-all -Werror -Wno-free-nonheap-object
#LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SHARED_LIBRARIES := libcutils liblog libc

LOCAL_MODULE := crasher
LOCAL_MODULE_STEM_32 := crasher
LOCAL_MODULE_STEM_64 := crasher64
LOCAL_MULTILIB := both

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

ifeq ($(ARCH_ARM_HAVE_VFP),true)
LOCAL_MODULE_TARGET_ARCH += arm
LOCAL_SRC_FILES_arm := arm/vfp.S
LOCAL_CFLAGS_arm += -DWITH_VFP
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_CFLAGS_arm += -DWITH_VFP_D32
endif # ARCH_ARM_HAVE_VFP_D32
endif # ARCH_ARM_HAVE_VFP == true
LOCAL_CFLAGS += -Werror

LOCAL_SRC_FILES_arm64 := arm64/vfp.S
LOCAL_MODULE_TARGET_ARCH += arm64

LOCAL_SRC_FILES := vfp-crasher.c
LOCAL_MODULE := vfp-crasher
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libcutils liblog libc

LOCAL_MODULE_STEM_32 := vfp-crasher
LOCAL_MODULE_STEM_64 := vfp-crasher64
LOCAL_MULTILIB := both

include $(BUILD_EXECUTABLE)
