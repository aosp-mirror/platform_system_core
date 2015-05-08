#
# Copyright (C) 2014 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH:= $(call my-dir)

libbacktrace_common_cflags := \
	-Wall \
	-Werror \

libbacktrace_common_conlyflags := \
	-std=gnu99 \

libbacktrace_common_cppflags := \
	-std=gnu++11 \

# The latest clang (r230699) does not allow SP/PC to be declared in inline asm lists.
libbacktrace_common_clang_cflags += \
    -Wno-inline-asm

build_host := false
ifeq ($(HOST_OS),linux)
ifeq ($(HOST_ARCH),$(filter $(HOST_ARCH),x86 x86_64))
build_host := true
endif
endif

#-------------------------------------------------------------------------
# The libbacktrace library.
#-------------------------------------------------------------------------
libbacktrace_src_files := \
	Backtrace.cpp \
	BacktraceCurrent.cpp \
	BacktraceMap.cpp \
	BacktracePtrace.cpp \
	thread_utils.c \
	ThreadEntry.cpp \
	UnwindCurrent.cpp \
	UnwindMap.cpp \
	UnwindPtrace.cpp \

libbacktrace_shared_libraries_target := \
	libcutils \

libbacktrace_shared_libraries := \
	libbase \
	libunwind \

libbacktrace_shared_libraries_host := \
	liblog \

libbacktrace_static_libraries_host := \
	libcutils \

libbacktrace_ldlibs_host := \
	-lpthread \
	-lrt \

module := libbacktrace
module_tag := optional
build_type := target
build_target := SHARED_LIBRARY
include $(LOCAL_PATH)/Android.build.mk
build_type := host
libbacktrace_multilib := both
include $(LOCAL_PATH)/Android.build.mk

#-------------------------------------------------------------------------
# The libbacktrace_test library needed by backtrace_test.
#-------------------------------------------------------------------------
libbacktrace_test_cflags := \
	-O0 \

libbacktrace_test_src_files := \
	backtrace_testlib.c \

module := libbacktrace_test
module_tag := debug
build_type := target
build_target := SHARED_LIBRARY
libbacktrace_test_multilib := both
include $(LOCAL_PATH)/Android.build.mk
build_type := host
include $(LOCAL_PATH)/Android.build.mk

#-------------------------------------------------------------------------
# The backtrace_test executable.
#-------------------------------------------------------------------------
backtrace_test_cflags := \
	-fno-builtin \
	-O0 \
	-g \

backtrace_test_cflags_target := \
	-DENABLE_PSS_TESTS \

backtrace_test_src_files := \
	backtrace_test.cpp \
	GetPss.cpp \
	thread_utils.c \

backtrace_test_ldlibs_host := \
	-lpthread \
	-lrt \

backtrace_test_shared_libraries := \
	libbacktrace_test \
	libbacktrace \
	libbase \
	libcutils \

backtrace_test_shared_libraries_target += \
	libdl \

backtrace_test_ldlibs_host += \
	-ldl \

module := backtrace_test
module_tag := debug
build_type := target
build_target := NATIVE_TEST
backtrace_test_multilib := both
include $(LOCAL_PATH)/Android.build.mk
build_type := host
include $(LOCAL_PATH)/Android.build.mk

#----------------------------------------------------------------------------
# Special truncated libbacktrace library for mac.
#----------------------------------------------------------------------------
ifeq ($(HOST_OS),darwin)

include $(CLEAR_VARS)

LOCAL_MODULE := libbacktrace
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
	BacktraceMap.cpp \

LOCAL_MULTILIB := both

include $(BUILD_HOST_SHARED_LIBRARY)

endif # HOST_OS-darwin
