LOCAL_PATH:= $(call my-dir)

#----------------------------------------------------------------------------
# The libbacktrace library using libunwind
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	unwind.c \
	unwind_remote.c \
	unwind_local.c \
	common.c \
	demangle.c \
	map_info.c \

LOCAL_CFLAGS := \
	-Wall \
	-Wno-unused-parameter \
	-Werror \
	-std=gnu99 \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_SHARED_LIBRARIES := \
	liblog \
	libunwind \
	libunwind-ptrace \
	libgccdemangle \

LOCAL_C_INCLUDES := \
	external/libunwind/include \

# The libunwind code is not in the tree yet, so don't build this library yet.
#include $(BUILD_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# The libbacktrace library using libcorkscrew
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	corkscrew.c \
	common.c \
	demangle.c \
	map_info.c \

LOCAL_CFLAGS := \
	-Wall \
	-Wno-unused-parameter \
	-Werror \
	-std=gnu99 \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_SHARED_LIBRARIES := \
	libcorkscrew \
	libdl \
	libgccdemangle \
	liblog \

include $(BUILD_SHARED_LIBRARY)

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

include $(BUILD_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# libbacktrace test executable
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := backtrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_test.c \

LOCAL_CFLAGS += \
	-std=gnu99 \

LOCAL_SHARED_LIBRARIES := \
	libbacktrace_test \
	libbacktrace \

include $(BUILD_EXECUTABLE)

#----------------------------------------------------------------------------
# Only linux-x86 host versions of libbacktrace supported.
#----------------------------------------------------------------------------
ifeq ($(HOST_OS)-$(HOST_ARCH),linux-x86)

#----------------------------------------------------------------------------
# The host libbacktrace library using libcorkscrew
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_SRC_FILES += \
	corkscrew.c \
	common.c \
	demangle.c \
	map_info.c \

LOCAL_CFLAGS += \
	-Wall \
	-Wno-unused-parameter \
	-Werror \
	-std=gnu99 \

LOCAL_SHARED_LIBRARIES := \
	liblog \
	libcorkscrew \
	libgccdemangle \
	liblog \

LOCAL_LDLIBS += \
	-ldl \
	-lrt \

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

include $(BUILD_HOST_SHARED_LIBRARY)

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

include $(BUILD_HOST_SHARED_LIBRARY)

#----------------------------------------------------------------------------
# libbacktrace host test executable
#----------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := backtrace_test
LOCAL_MODULE_FLAGS := debug

LOCAL_SRC_FILES := \
	backtrace_test.c \

LOCAL_CFLAGS += \
	-std=gnu99 \

LOCAL_SHARED_LIBRARIES := \
	libbacktrace_test \
	libbacktrace \

include $(BUILD_HOST_EXECUTABLE)

endif # HOST_OS-HOST_ARCH == linux-x86
