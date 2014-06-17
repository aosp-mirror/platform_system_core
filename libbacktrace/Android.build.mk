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

include $(CLEAR_VARS)

LOCAL_MODULE := $(module)
LOCAL_MODULE_TAGS := $(module_tag)
LOCAL_MULTILIB := $($(module)_multilib)

LOCAL_ADDITIONAL_DEPENDENCIES := \
    $(LOCAL_PATH)/Android.mk \
    $(LOCAL_PATH)/Android.build.mk \

LOCAL_CFLAGS := \
    $(common_cflags) \
    $($(module)_cflags) \
    $($(module)_cflags_$(build_type)) \

LOCAL_CONLYFLAGS += \
    $(common_conlyflags) \
    $($(module)_conlyflags) \
    $($(module)_conlyflags_$(build_type)) \

LOCAL_CPPFLAGS += \
    $(common_cppflags) \
    $($(module)_cppflags) \
    $($(module)_cppflags_$(build_type)) \

LOCAL_C_INCLUDES := \
    $(common_c_includes) \
    $($(module)_c_includes) \
    $($(module)_c_includes_$(build_type)) \

LOCAL_SRC_FILES := \
    $($(module)_src_files) \
    $($(module)_src_files_$(build_type)) \

LOCAL_STATIC_LIBRARIES := \
    $($(module)_static_libraries) \
    $($(module)_static_libraries_$(build_type)) \

LOCAL_SHARED_LIBRARIES := \
    $($(module)_shared_libraries) \
    $($(module)_shared_libraries_$(build_type)) \

LOCAL_LDLIBS := \
    $($(module)_ldlibs) \
    $($(module)_ldlibs_$(build_type)) \

ifeq ($(build_type),target)
  ifneq ($($(module)_libc++),)
    include external/libcxx/libcxx.mk
  else
    include external/stlport/libstlport.mk
  endif

  include $(BUILD_$(build_target))
endif

ifeq ($(build_type),host)
  # Only build if host builds are supported.
  ifeq ($(build_host),true)
    ifneq ($($(module)_libc++),)
      include external/libcxx/libcxx.mk
    endif
    include $(BUILD_HOST_$(build_target))
  endif
endif
