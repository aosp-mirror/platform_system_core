#
# Copyright (C) 2008-2014 The Android Open Source Project
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

ifneq ($(TARGET_USES_LOGD),false)
liblog_sources := logd_write.c log_event_write.c
else
liblog_sources := logd_write_kern.c
endif

# some files must not be compiled when building against Mingw
# they correspond to features not used by our host development tools
# which are also hard or even impossible to port to native Win32
WITH_MINGW :=
ifeq ($(HOST_OS),windows)
    ifeq ($(strip $(USE_CYGWIN)),)
        WITH_MINGW := true
    endif
endif
# USE_MINGW is defined when we build against Mingw on Linux
ifneq ($(strip $(USE_MINGW)),)
    WITH_MINGW := true
endif

ifndef WITH_MINGW
    liblog_sources += \
        logprint.c \
        event_tag_map.c
else
    liblog_sources += \
        uio.c
endif

liblog_host_sources := $(liblog_sources) fake_log_device.c
liblog_target_sources := $(liblog_sources) log_time.cpp
ifneq ($(TARGET_USES_LOGD),false)
liblog_target_sources += log_read.c
else
liblog_target_sources += log_read_kern.c
endif

# Shared and static library for host
# ========================================================
LOCAL_MODULE := liblog
LOCAL_SRC_FILES := $(liblog_host_sources)
LOCAL_CFLAGS := -DFAKE_LOG_DEVICE=1 -Werror
LOCAL_MULTILIB := both
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := liblog
LOCAL_WHOLE_STATIC_LIBRARIES := liblog
ifeq ($(strip $(HOST_OS)),linux)
LOCAL_LDLIBS := -lrt
endif
LOCAL_MULTILIB := both
include $(BUILD_HOST_SHARED_LIBRARY)


# Shared and static library for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := liblog
LOCAL_SRC_FILES := $(liblog_target_sources)
LOCAL_CFLAGS := -Werror
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := liblog
LOCAL_WHOLE_STATIC_LIBRARIES := liblog
LOCAL_CFLAGS := -Werror
include $(BUILD_SHARED_LIBRARY)

include $(call first-makefiles-under,$(LOCAL_PATH))
