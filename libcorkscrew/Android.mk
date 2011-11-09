# Copyright (C) 2011 The Android Open Source Project
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

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	backtrace.c \
	backtrace-helper.c \
	demangle.c \
	map_info.c \
	ptrace.c \
	symbol_table.c

ifeq ($(TARGET_ARCH),arm)
LOCAL_SRC_FILES += \
	arch-arm/backtrace-arm.c \
	arch-arm/ptrace-arm.c
LOCAL_CFLAGS += -DCORKSCREW_HAVE_ARCH
endif
ifeq ($(TARGET_ARCH),x86)
LOCAL_SRC_FILES += \
	arch-x86/backtrace-x86.c \
	arch-x86/ptrace-x86.c
LOCAL_CFLAGS += -DCORKSCREW_HAVE_ARCH
endif

LOCAL_SHARED_LIBRARIES += libdl libcutils libgccdemangle

LOCAL_CFLAGS += -std=gnu99 -Werror
LOCAL_MODULE := libcorkscrew
LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
