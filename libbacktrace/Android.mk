LOCAL_PATH:= $(call my-dir)

common_src := \
	BacktraceImpl.cpp \
	BacktraceMap.cpp \
	BacktraceThread.cpp \
	thread_utils.c \

common_cflags := \
	-Wall \
	-Wno-unused-parameter \
	-Werror \

common_conlyflags := \
	-std=gnu99 \

common_cppflags := \
	-std=gnu++11 \

common_shared_libs := \
	libcutils \
	libgccdemangle \
	liblog \

# To enable using libunwind on each arch, add it to this list.
libunwind_architectures :=

ifeq ($(TARGET_ARCH),$(filter $(TARGET_ARCH),$(libunwind_architectures)))

#----------------------------------------------------------------------------
# The native libbacktrace library with libunwind.
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	$(common_src) \
	UnwindCurrent.cpp \
	UnwindMap.cpp \
	UnwindPtrace.cpp \

LOCAL_CFLAGS := \
	$(common_cflags) \

LOCAL_CONLYFLAGS += \
	$(common_conlyflags) \

LOCAL_CPPFLAGS += \
	$(common_cppflags) \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := \
	$(common_c_includes) \
	external/libunwind/include \

LOCAL_SHARED_LIBRARIES := \
	$(common_shared_libs) \
	libunwind \
	libunwind-ptrace \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include external/stlport/libstlport.mk

include $(BUILD_SHARED_LIBRARY)

else

#----------------------------------------------------------------------------
# The native libbacktrace library with libcorkscrew.
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	$(common_src) \
	Corkscrew.cpp \

LOCAL_CFLAGS := \
	$(common_cflags) \

LOCAL_CONLYFLAGS += \
	$(common_conlyflags) \

LOCAL_CPPFLAGS += \
	$(common_cppflags) \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := \
	$(common_c_includes) \
	system/core/libcorkscrew \

LOCAL_SHARED_LIBRARIES := \
	$(common_shared_libs) \
	libcorkscrew \
	libdl \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include external/stlport/libstlport.mk

include $(BUILD_SHARED_LIBRARY)

endif

#----------------------------------------------------------------------------
# libbacktrace test library, all optimizations turned off
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := libbacktrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_testlib.c

LOCAL_CFLAGS += \
	-std=gnu99 \
	-O0 \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# libbacktrace test executable
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := backtrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_test.cpp \
	thread_utils.c \

LOCAL_CFLAGS += \
	$(common_cflags) \
	-fno-builtin \
	-fstack-protector-all \
	-O0 \
	-g \
	-DGTEST_OS_LINUX_ANDROID \
	-DGTEST_HAS_STD_STRING \

ifeq ($(TARGET_ARCH),arm64)
  $(info TODO: $(LOCAL_PATH)/Android.mk -fstack-protector not yet available for the AArch64 toolchain)
  LOCAL_CFLAGS += -fno-stack-protector
endif # arm64

LOCAL_CONLYFLAGS += \
	$(common_conlyflags) \

LOCAL_CPPFLAGS += \
	$(common_cppflags) \

LOCAL_SHARED_LIBRARIES += \
	libcutils \
	libbacktrace_test \
	libbacktrace \

LOCAL_LDLIBS := \
	-lpthread \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_NATIVE_TEST)

#----------------------------------------------------------------------------
# Only x86 host versions of libbacktrace supported.
#----------------------------------------------------------------------------
ifeq ($(HOST_ARCH),x86)

#----------------------------------------------------------------------------
# The host libbacktrace library using libcorkscrew
#----------------------------------------------------------------------------
include $(CLEAR_VARS)


LOCAL_CFLAGS += \
	$(common_cflags) \

LOCAL_CONLYFLAGS += \
	$(common_conlyflags) \

LOCAL_C_INCLUDES := \
	$(common_c_includes) \

LOCAL_SHARED_LIBRARIES := \
	libgccdemangle \
	liblog \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

ifeq ($(HOST_OS),linux)
LOCAL_SRC_FILES += \
	$(common_src) \
	Corkscrew.cpp \

LOCAL_C_INCLUDES += \
	system/core/libcorkscrew \

LOCAL_SHARED_LIBRARIES := \
	libcorkscrew \

LOCAL_CPPFLAGS += \
	$(common_cppflags) \

LOCAL_LDLIBS += \
	-ldl \
	-lrt \

else
LOCAL_SRC_FILES += \
	BacktraceMap.cpp \

endif

include $(BUILD_HOST_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# The host test is only supported on linux.
#----------------------------------------------------------------------------
ifeq ($(HOST_OS),linux)

#----------------------------------------------------------------------------
# libbacktrace host test library, all optimizations turned off
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := libbacktrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_testlib.c

LOCAL_CFLAGS += \
	-std=gnu99 \
	-O0 \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_HOST_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# libbacktrace host test executable
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := backtrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_test.cpp \
	thread_utils.c \

LOCAL_CFLAGS += \
	$(common_cflags) \
	-fno-builtin \
	-fstack-protector-all \
	-O0 \
	-g \
	-DGTEST_HAS_STD_STRING \

LOCAL_SHARED_LIBRARIES := \
	libbacktrace_test \
	libbacktrace \

LOCAL_LDLIBS := \
	-lpthread \

LOCAL_ADDITIONAL_DEPENDENCIES := \
	$(LOCAL_PATH)/Android.mk

include $(BUILD_HOST_NATIVE_TEST)

endif # HOST_OS == linux

endif # HOST_ARCH == x86
