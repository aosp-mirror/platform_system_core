#
# Copyright (C) 2015 The Android Open-Source Project
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

# WARNING: Everything listed here will be built on ALL platforms,
# including x86, the emulator, and the SDK.  Modules must be uniquely
# named (liblights.panda), and must build everywhere, or limit themselves
# to only building on ARM if they include assembly. Individual makefiles
# are responsible for having their own logic, for fine-grained control.

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

###
# trusty_keymaster is a binary used only for on-device testing.  It
# runs Trusty Keymaster through a basic set of operations with RSA
# and ECDSA keys.
###
LOCAL_MODULE := trusty_keymaster_tipc
LOCAL_SRC_FILES := \
	trusty_keymaster_device.cpp \
	trusty_keymaster_ipc.cpp \
	trusty_keymaster_main.cpp
LOCAL_SHARED_LIBRARIES := \
	libcrypto \
	libcutils \
	libkeymaster_portable \
	libkeymaster \
	libtrusty \
	libkeymaster_messages \
	libsoftkeymasterdevice \
	liblog

include $(BUILD_EXECUTABLE)

###
# keystore.trusty is the HAL used by keystore on Trusty devices.
##

include $(CLEAR_VARS)

LOCAL_MODULE := keystore.trusty
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := module.cpp \
	trusty_keymaster_ipc.cpp \
	trusty_keymaster_device.cpp
LOCAL_CLFAGS = -fvisibility=hidden -Wall -Werror
LOCAL_SHARED_LIBRARIES := \
	libcrypto \
	libkeymaster_messages \
	libtrusty \
	liblog \
	libcutils
LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
