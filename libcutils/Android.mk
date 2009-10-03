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
	array.c \
	hashmap.c \
	atomic.c \
	native_handle.c \
	buffer.c \
	socket_inaddr_any_server.c \
	socket_local_client.c \
	socket_local_server.c \
	socket_loopback_client.c \
	socket_loopback_server.c \
	socket_network_client.c \
	config_utils.c \
	cpu_info.c \
	load_file.c \
	strdup16to8.c \
	strdup8to16.c \
	record_stream.c \
	process_name.c \
	properties.c \
	threads.c \
	sched_policy.c

commonHostSources := \
        ashmem-host.c

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

ifeq ($(WINDOWS_HOST_ONLY),1)
    commonSources += \
        uio.c
else
    commonSources += \
        abort_socket.c \
        mspace.c \
        selector.c \
        tztime.c \
        zygote.c

    commonHostSources += \
        tzstrftime.c
endif


# Static library for host
# ========================================================
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) $(commonHostSources)
LOCAL_LDLIBS := -lpthread
LOCAL_STATIC_LIBRARIES := liblog
include $(BUILD_HOST_STATIC_LIBRARY)


ifeq ($(TARGET_SIMULATOR),true)

# Shared library for simulator
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) $(commonHostSources) memory.c dlmalloc_stubs.c
LOCAL_LDLIBS := -lpthread
LOCAL_SHARED_LIBRARIES := liblog
include $(BUILD_SHARED_LIBRARY)

else #!sim

# Shared and static library for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
LOCAL_SRC_FILES := $(commonSources) ashmem-dev.c mq.c

ifeq ($(TARGET_ARCH),arm)
LOCAL_SRC_FILES += memset32.S atomic-android-arm.S
else  # !arm
LOCAL_SRC_FILES += memory.c
endif # !arm

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)
LOCAL_STATIC_LIBRARIES := liblog
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcutils
LOCAL_WHOLE_STATIC_LIBRARIES := libcutils
LOCAL_SHARED_LIBRARIES := liblog
include $(BUILD_SHARED_LIBRARY)

endif #!sim
