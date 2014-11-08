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

common_cflags := \
	-Wall \
	-Werror \

common_conlyflags := \
	-std=gnu99 \

common_cppflags := \
	-std=gnu++11 \

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
	BacktraceImpl.cpp \
	BacktraceMap.cpp \
	BacktraceThread.cpp \
	thread_utils.c \

libbacktrace_shared_libraries_target := \
	libcutils \
	libgccdemangle \

libbacktrace_src_files += \
	UnwindCurrent.cpp \
	UnwindMap.cpp \
	UnwindPtrace.cpp \

libbacktrace_c_includes := \
	external/libunwind/include \

libbacktrace_shared_libraries := \
	libunwind \
	libunwind-ptrace \

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
include $(LOCAL_PATH)/Android.build.mk

# Don't build for unbundled branches
ifeq (,$(TARGET_BUILD_APPS))
#-------------------------------------------------------------------------
# The libbacktrace library (libc++)
#-------------------------------------------------------------------------
libbacktrace_libc++_src_files := \
	BacktraceImpl.cpp \
	BacktraceMap.cpp \
	BacktraceThread.cpp \
	thread_utils.c \

libbacktrace_libc++_shared_libraries_target := \
	libcutils \
	libgccdemangle \

libbacktrace_libc++_src_files += \
	UnwindCurrent.cpp \
	UnwindMap.cpp \
	UnwindPtrace.cpp \

libbacktrace_libc++_c_includes := \
	external/libunwind/include \

libbacktrace_libc++_shared_libraries := \
	libunwind \
	libunwind-ptrace \

libbacktrace_libc++_shared_libraries_host := \
	liblog \

libbacktrace_libc++_static_libraries_host := \
	libcutils \

libbacktrace_libc++_ldlibs_host := \
	-lpthread \
	-lrt \

libbacktrace_libc++_libc++ := true

module := libbacktrace_libc++
module_tag := optional
build_type := target
build_target := SHARED_LIBRARY
include $(LOCAL_PATH)/Android.build.mk
build_type := host
libbacktrace_libc++_multilib := both
include $(LOCAL_PATH)/Android.build.mk
libbacktrace_libc++_multilib :=
endif

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

backtrace_test_shared_libraries_target := \
	libcutils \

backtrace_test_static_libraries_host := \
	libcutils \

module := backtrace_test
module_tag := debug
build_type := target
build_target := NATIVE_TEST
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

include $(BUILD_HOST_SHARED_LIBRARY)

# Don't build for unbundled branches
ifeq (,$(TARGET_BUILD_APPS))
#-------------------------------------------------------------------------
# The libbacktrace library (libc++)
#-------------------------------------------------------------------------
include $(CLEAR_VARS)

LOCAL_MODULE := libbacktrace_libc++
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
	BacktraceMap.cpp \

LOCAL_MULTILIB := both

include $(BUILD_HOST_SHARED_LIBRARY)

endif # TARGET_BUILD_APPS

endif # HOST_OS-darwin
