LOCAL_PATH := $(call my-dir)

crasher_cppflags := \
    -std=gnu++14 \
    -W \
    -Wall \
    -Wextra \
    -Wunused \
    -Werror \
    -O0 \
    -fstack-protector-all \
    -Wno-free-nonheap-object \
    -Wno-date-time

include $(CLEAR_VARS)
LOCAL_SRC_FILES := crasher.cpp
LOCAL_SRC_FILES_arm    := arm/crashglue.S
LOCAL_SRC_FILES_arm64  := arm64/crashglue.S
LOCAL_SRC_FILES_mips   := mips/crashglue.S
LOCAL_SRC_FILES_mips64 := mips64/crashglue.S
LOCAL_SRC_FILES_x86    := x86/crashglue.S
LOCAL_SRC_FILES_x86_64 := x86_64/crashglue.S
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_CPPFLAGS := $(crasher_cppflags)
LOCAL_SHARED_LIBRARIES := libbase liblog

# The arm emulator has VFP but not VFPv3-D32.
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_ASFLAGS_arm += -DHAS_VFP_D32
endif

LOCAL_MODULE := crasher
LOCAL_MODULE_STEM_32 := crasher
LOCAL_MODULE_STEM_64 := crasher64
LOCAL_MULTILIB := both

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := crasher.cpp
LOCAL_SRC_FILES_arm    := arm/crashglue.S
LOCAL_SRC_FILES_arm64  := arm64/crashglue.S
LOCAL_SRC_FILES_mips   := mips/crashglue.S
LOCAL_SRC_FILES_mips64 := mips64/crashglue.S
LOCAL_SRC_FILES_x86    := x86/crashglue.S
LOCAL_SRC_FILES_x86_64 := x86_64/crashglue.S
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_CPPFLAGS := $(crasher_cppflags) -DSTATIC_CRASHER
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_SHARED_LIBRARIES := libbase liblog

# The arm emulator has VFP but not VFPv3-D32.
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_ASFLAGS_arm += -DHAS_VFP_D32
endif

LOCAL_MODULE := static_crasher
LOCAL_MODULE_STEM_32 := static_crasher
LOCAL_MODULE_STEM_64 := static_crasher64
LOCAL_MULTILIB := both

LOCAL_STATIC_LIBRARIES := libdebuggerd_handler libbase liblog

include $(BUILD_EXECUTABLE)
