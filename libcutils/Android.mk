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
	load_file.c \
	strlcpy.c \
	open_memstream.c \
	strdup16to8.c \
	strdup8to16.c \
	record_stream.c \
	process_name.c \
	threads.c \
	sched_policy.c \
	iosched_policy.c \
	str_parms.c \
	fs_config.c

# some files must not be compiled when building against Mingw
# they correspond to features not used by our host development tools
# which are also hard or even impossible to port to native Win32
nonWindowsSources := \
        fs.c \
        multiuser.c \
        socket_inaddr_any_server.c \
        socket_local_client.c \
        socket_local_server.c \
        socket_loopback_client.c \
        socket_loopback_server.c \
        socket_network_client.c \
        sockets.c \

nonWindowsHostSources := \
        ashmem-host.c \
        trace-host.c


# Shared and static library for host
# ========================================================
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) dlmalloc_stubs.c
LOCAL_SRC_FILES_darwin := $(nonWindowsSources) $(nonWindowsHostSources)
LOCAL_SRC_FILES_linux := $(nonWindowsSources) $(nonWindowsHostSources)
LOCAL_STATIC_LIBRARIES := liblog
LOCAL_CFLAGS_darwin := -Werror -Wall -Wextra
LOCAL_CFLAGS_linux := -Werror -Wall -Wextra
LOCAL_MULTILIB := both
LOCAL_MODULE_HOST_OS := darwin linux windows
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) dlmalloc_stubs.c
LOCAL_SRC_FILES_darwin := $(nonWindowsSources) $(nonWindowsHostSources)
LOCAL_SRC_FILES_linux := $(nonWindowsSources) $(nonWindowsHostSources)
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_CFLAGS_darwin := -Werror -Wall -Wextra
LOCAL_CFLAGS_linux := -Werror -Wall -Wextra
LOCAL_MULTILIB := both
include $(BUILD_HOST_SHARED_LIBRARY)



# Shared and static library for target
# ========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) \
        $(nonWindowsSources) \
        android_reboot.c \
        ashmem-dev.c \
        debugger.c \
        klog.c \
        partition_utils.c \
        properties.c \
        qtaguid.c \
        trace-dev.c \
        uevent.c \

LOCAL_SRC_FILES_arm += arch-arm/memset32.S
LOCAL_SRC_FILES_arm64 += arch-arm64/android_memset.S

LOCAL_SRC_FILES_mips += arch-mips/android_memset.c
LOCAL_SRC_FILES_mips64 += arch-mips/android_memset.c

LOCAL_SRC_FILES_x86 += \
        arch-x86/android_memset16.S \
        arch-x86/android_memset32.S \

LOCAL_SRC_FILES_x86_64 += \
        arch-x86_64/android_memset16.S \
        arch-x86_64/android_memset32.S \

LOCAL_C_INCLUDES := $(libcutils_c_includes)
LOCAL_STATIC_LIBRARIES := liblog
ifneq ($(ENABLE_CPUSETS),)
LOCAL_CFLAGS += -DUSE_CPUSETS
endif
ifneq ($(ENABLE_SCHEDBOOST),)
LOCAL_CFLAGS += -DUSE_SCHEDBOOST
endif
LOCAL_CFLAGS += -Werror -Wall -Wextra -std=gnu90
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
# TODO: remove liblog as whole static library, once we don't have prebuilt that requires
# liblog symbols present in libcutils.
LOCAL_WHOLE_STATIC_LIBRARIES := libcutils liblog
LOCAL_SHARED_LIBRARIES := liblog
ifneq ($(ENABLE_CPUSETS),)
LOCAL_CFLAGS += -DUSE_CPUSETS
endif
ifneq ($(ENABLE_SCHEDBOOST),)
LOCAL_CFLAGS += -DUSE_SCHEDBOOST
endif
LOCAL_CFLAGS += -Werror -Wall -Wextra
LOCAL_C_INCLUDES := $(libcutils_c_includes)
LOCAL_CLANG := true
LOCAL_SANITIZE := integer
include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
