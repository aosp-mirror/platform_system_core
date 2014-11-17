#
# Copyright (C) 2008 The Android Open Source Project
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
LOCAL_PATH := $(my-dir)
include $(CLEAR_VARS)

commonSources := \
	hashmap.c \
	atomic.c.arm \
	native_handle.c \
	config_utils.c \
	cpu_info.c \
	load_file.c \
	open_memstream.c \
	strdup16to8.c \
	strdup8to16.c \
	record_stream.c \
	process_name.c \
	threads.c \
	sched_policy.c \
	iosched_policy.c \
	str_parms.c \

# some files must not be compiled when building against Mingw
# they correspond to features not used by our host development tools
# which are also hard or even impossible to port to native Win32
WINDOWS_HOST_ONLY :=
ifeq ($(HOST_OS),windows)
    ifeq ($(strip $(USE_CYGWIN)),)
        WINDOWS_HOST_ONLY := 1
    endif
endif
# USE_MINGW is defined when we build against Mingw on Linux
ifneq ($(strip $(USE_MINGW)),)
    WINDOWS_HOST_ONLY := 1
endif

ifneq ($(WINDOWS_HOST_ONLY),1)
    commonSources += \
        fs.c \
        multiuser.c \
        socket_inaddr_any_server.c \
        socket_local_client.c \
        socket_local_server.c \
        socket_loopback_client.c \
        socket_loopback_server.c \
        socket_network_client.c \
        sockets.c \

    commonHostSources += \
        ashmem-host.c

endif


# Static library for host
# ========================================================
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) $(commonHostSources) dlmalloc_stubs.c
LOCAL_STATIC_LIBRARIES := liblog
ifneq ($(HOST_OS),windows)
LOCAL_CFLAGS += -Werror
endif
LOCAL_MULTILIB := both
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_HOST_STATIC_LIBRARY)


# Tests for host
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := tst_str_parms
LOCAL_CFLAGS += -DTEST_STR_PARMS
ifneq ($(HOST_OS),windows)
LOCAL_CFLAGS += -Werror
endif
LOCAL_SRC_FILES := str_parms.c hashmap.c memory.c
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_MODULE_TAGS := optional
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_HOST_EXECUTABLE)


# Shared and static library for target
# ========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) \
        android_reboot.c \
        ashmem-dev.c \
        debugger.c \
        klog.c \
        memory.c \
        partition_utils.c \
        properties.c \
        qtaguid.c \
        trace.c \
        uevent.c \

LOCAL_SRC_FILES_arm += \
        arch-arm/memset32.S \

# arch-arm/memset32.S does not compile with Clang.
LOCAL_CLANG_ASFLAGS_arm += -no-integrated-as

LOCAL_SRC_FILES_arm64 += \
        arch-arm64/android_memset.S \

ifndef ARCH_MIPS_REV6
LOCAL_SRC_FILES_mips += \
        arch-mips/android_memset.c \

LOCAL_CFLAGS_mips += -DHAVE_MEMSET16 -DHAVE_MEMSET32
endif

# TODO: switch mips64 back to using arch-mips/android_memset.c
LOCAL_SRC_FILES_mips64 += \
#       arch-mips/android_memset.c \

LOCAL_SRC_FILES_x86 += \
        arch-x86/android_memset16.S \
        arch-x86/android_memset32.S \

LOCAL_SRC_FILES_x86_64 += \
        arch-x86_64/android_memset16.S \
        arch-x86_64/android_memset32.S \

LOCAL_CFLAGS_arm += -DHAVE_MEMSET16 -DHAVE_MEMSET32
LOCAL_CFLAGS_arm64 += -DHAVE_MEMSET16 -DHAVE_MEMSET32
#LOCAL_CFLAGS_mips64 += -DHAVE_MEMSET16 -DHAVE_MEMSET32
LOCAL_CFLAGS_x86 += -DHAVE_MEMSET16 -DHAVE_MEMSET32
LOCAL_CFLAGS_x86_64 += -DHAVE_MEMSET16 -DHAVE_MEMSET32

LOCAL_C_INCLUDES := $(libcutils_c_includes)
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_CFLAGS += -Werror -std=gnu90
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
# TODO: remove liblog as whole static library, once we don't have prebuilt that requires
# liblog symbols present in libcutils.
LOCAL_WHOLE_STATIC_LIBRARIES := libcutils liblog
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_CFLAGS += -Werror
LOCAL_C_INCLUDES := $(libcutils_c_includes)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tst_str_parms
LOCAL_CFLAGS += -DTEST_STR_PARMS -Werror
LOCAL_SRC_FILES := str_parms.c hashmap.c memory.c
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_MODULE_TAGS := optional
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
