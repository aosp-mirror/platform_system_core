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
LOCAL_SRC_FILES_mips64 := mips/machine.cpp
LOCAL_SRC_FILES_x86    := x86/machine.cpp
LOCAL_SRC_FILES_x86_64 := x86_64/machine.cpp

LOCAL_CPPFLAGS := \
    -std=gnu++11 \
    -W -Wall -Wextra \
    -Wunused \
    -Werror \

LOCAL_SHARED_LIBRARIES := \
    libbacktrace \
    libcutils \
    liblog \
    libselinux \

include external/stlport/libstlport.mk

LOCAL_MODULE := debuggerd
LOCAL_MODULE_STEM_32 := debuggerd
LOCAL_MODULE_STEM_64 := debuggerd64
LOCAL_MULTILIB := both
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk

include $(BUILD_EXECUTABLE)



include $(CLEAR_VARS)
LOCAL_SRC_FILES := crasher.c
LOCAL_SRC_FILES_arm    := arm/crashglue.S
LOCAL_SRC_FILES_arm64  := arm64/crashglue.S
LOCAL_SRC_FILES_mips   := mips/crashglue.S
LOCAL_SRC_FILES_mips64 := mips/crashglue.S
LOCAL_SRC_FILES_x86    := x86/crashglue.S
LOCAL_SRC_FILES_x86_64 := x86_64/crashglue.S
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -fstack-protector-all -Werror -Wno-free-nonheap-object
#LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SHARED_LIBRARIES := libcutils liblog libc

# The arm emulator has VFP but not VFPv3-D32.
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_ASFLAGS_arm += -DHAS_VFP_D32
endif

LOCAL_MODULE := crasher
LOCAL_MODULE_STEM_32 := crasher
LOCAL_MODULE_STEM_64 := crasher64
LOCAL_MULTILIB := both

include $(BUILD_EXECUTABLE)
