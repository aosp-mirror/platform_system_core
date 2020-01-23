# Copyright (C) 2007 Google Inc.
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

#
# Package fastboot-related executables.
#

my_dist_files := $(SOONG_HOST_OUT_EXECUTABLES)/mke2fs
my_dist_files += $(SOONG_HOST_OUT_EXECUTABLES)/e2fsdroid
my_dist_files += $(SOONG_HOST_OUT_EXECUTABLES)/make_f2fs
my_dist_files += $(SOONG_HOST_OUT_EXECUTABLES)/sload_f2fs
$(call dist-for-goals,dist_files sdk win_sdk,$(my_dist_files))
my_dist_files :=
