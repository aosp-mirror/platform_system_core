LOCAL_PATH := $(call my-dir)

common_cppflags := \
    -std=gnu++11 \
    -W \
    -Wall \
    -Wextra \
    -Wunused \
    -Werror \

ifeq ($(TARGET_IS_64_BIT),true)
common_cppflags += -DTARGET_IS_64_BIT
endif

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    backtrace.cpp \
    debuggerd.cpp \
    elf_utils.cpp \
    getevent.cpp \
    signal_sender.cpp \
    tombstone.cpp \
    utility.cpp \

LOCAL_SRC_FILES_arm    := arm/machine.cpp
LOCAL_SRC_FILES_arm64  := arm64/machine.cpp
LOCAL_SRC_FILES_mips   := mips/machine.cpp
LOCAL_SRC_FILES_mips64 := mips64/machine.cpp
LOCAL_SRC_FILES_x86    := x86/machine.cpp
LOCAL_SRC_FILES_x86_64 := x86_64/machine.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CPPFLAGS := $(common_cppflags)

LOCAL_INIT_RC_32 := debuggerd.rc
LOCAL_INIT_RC_64 := debuggerd64.rc

LOCAL_SHARED_LIBRARIES := \
    libbacktrace \
    libbase \
    libcutils \
    liblog \
    libselinux \

LOCAL_CLANG := true

LOCAL_MODULE := debuggerd
LOCAL_MODULE_STEM_32 := debuggerd
LOCAL_MODULE_STEM_64 := debuggerd64
LOCAL_MULTILIB := both

include $(BUILD_EXECUTABLE)

crasher_cppflags := $(common_cppflags) -fstack-protector-all -Wno-free-nonheap-object -Wno-date-time

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
LOCAL_SHARED_LIBRARIES := libcutils liblog

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
LOCAL_SHARED_LIBRARIES := libcutils liblog

# The arm emulator has VFP but not VFPv3-D32.
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_ASFLAGS_arm += -DHAS_VFP_D32
endif

LOCAL_MODULE := static_crasher
LOCAL_MODULE_STEM_32 := static_crasher
LOCAL_MODULE_STEM_64 := static_crasher64
LOCAL_MULTILIB := both

LOCAL_STATIC_LIBRARIES := libdebuggerd_client libcutils liblog

include $(BUILD_EXECUTABLE)

debuggerd_test_src_files := \
    utility.cpp \
    test/dump_memory_test.cpp \
    test/elf_fake.cpp \
    test/log_fake.cpp \
    test/property_fake.cpp \
    test/ptrace_fake.cpp \
    test/tombstone_test.cpp \
    test/selinux_fake.cpp \

debuggerd_shared_libraries := \
    libbacktrace \
    libbase \
    libcutils \

debuggerd_c_includes := \
    $(LOCAL_PATH)/test \

debuggerd_cpp_flags := \
    $(common_cppflags) \
    -Wno-missing-field-initializers \
    -fno-rtti \

# Only build the host tests on linux.
ifeq ($(HOST_OS),linux)

include $(CLEAR_VARS)

LOCAL_MODULE := debuggerd_test
LOCAL_SRC_FILES := $(debuggerd_test_src_files)
LOCAL_SHARED_LIBRARIES := $(debuggerd_shared_libraries)
LOCAL_C_INCLUDES := $(debuggerd_c_includes)
LOCAL_CPPFLAGS := $(debuggerd_cpp_flags)

LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
LOCAL_MULTILIB := both
include $(BUILD_HOST_NATIVE_TEST)

endif

include $(CLEAR_VARS)

LOCAL_MODULE := debuggerd_test
LOCAL_SRC_FILES := $(debuggerd_test_src_files)
LOCAL_SHARED_LIBRARIES := $(debuggerd_shared_libraries)
LOCAL_C_INCLUDES := $(debuggerd_c_includes)
LOCAL_CPPFLAGS := $(debuggerd_cpp_flags)

LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
LOCAL_MULTILIB := both
include $(BUILD_NATIVE_TEST)
