/*
 *  Copyright 2014 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

__BEGIN_DECLS

static constexpr const char* CGROUPV2_HIERARCHY_NAME = "cgroup2";
[[deprecated]] static constexpr const char* CGROUPV2_CONTROLLER_NAME = "cgroup2";

bool CgroupsAvailable();
bool CgroupGetControllerPath(const std::string& cgroup_name, std::string* path);
bool CgroupGetControllerFromPath(const std::string& path, std::string* cgroup_name);
bool CgroupGetAttributePath(const std::string& attr_name, std::string* path);
bool CgroupGetAttributePathForTask(const std::string& attr_name, int tid, std::string* path);

bool SetTaskProfiles(int tid, const std::vector<std::string>& profiles, bool use_fd_cache = false);
bool SetProcessProfiles(uid_t uid, pid_t pid, const std::vector<std::string>& profiles);
bool SetUserProfiles(uid_t uid, const std::vector<std::string>& profiles);

__END_DECLS

bool SetTaskProfiles(int tid, std::initializer_list<std::string_view> profiles,
                     bool use_fd_cache = false);
bool SetProcessProfiles(uid_t uid, pid_t pid, std::initializer_list<std::string_view> profiles);
#if _LIBCPP_STD_VER > 17
bool SetTaskProfiles(int tid, std::span<const std::string_view> profiles,
                     bool use_fd_cache = false);
bool SetProcessProfiles(uid_t uid, pid_t pid, std::span<const std::string_view> profiles);
#endif

__BEGIN_DECLS

#ifndef __ANDROID_VNDK__

bool SetProcessProfilesCached(uid_t uid, pid_t pid, const std::vector<std::string>& profiles);

static constexpr const char* CGROUPS_RC_PATH = "/dev/cgroup_info/cgroup.rc";

bool UsePerAppMemcg();

// Drop the fd cache of cgroup path. It is used for when resource caching is enabled and a process
// loses the access to the path, the access checking (See SetCgroupAction::EnableResourceCaching)
// should be active again. E.g. Zygote specialization for child process.
void DropTaskProfilesResourceCaching();

// Return 0 if all processes were killed and the cgroup was successfully removed.
// Returns -1 in the case of an error occurring or if there are processes still running.
int killProcessGroup(uid_t uid, int initialPid, int signal);

// Returns the same as killProcessGroup(), however it does not retry, which means
// that it only returns 0 in the case that the cgroup exists and it contains no processes.
int killProcessGroupOnce(uid_t uid, int initialPid, int signal);

// Sends the provided signal to all members of a process group, but does not wait for processes to
// exit, or for the cgroup to be removed. Callers should also ensure that killProcessGroup is called
// later to ensure the cgroup is fully removed, otherwise system resources will leak.
// Returns true if no errors are encountered sending signals, otherwise false.
bool sendSignalToProcessGroup(uid_t uid, int initialPid, int signal);

int createProcessGroup(uid_t uid, int initialPid, bool memControl = false);

// Set various properties of a process group. For these functions to work, the process group must
// have been created by passing memControl=true to createProcessGroup.
bool setProcessGroupSwappiness(uid_t uid, int initialPid, int swappiness);
bool setProcessGroupSoftLimit(uid_t uid, int initialPid, int64_t softLimitInBytes);
bool setProcessGroupLimit(uid_t uid, int initialPid, int64_t limitInBytes);

void removeAllEmptyProcessGroups(void);

// Provides the path for an attribute in a specific process group
// Returns false in case of error, true in case of success
bool getAttributePathForTask(const std::string& attr_name, int tid, std::string* path);

// Check if a profile can be applied without failing.
// Returns true if it can be applied without failing, false otherwise
bool isProfileValidForProcess(const std::string& profile_name, uid_t uid, int pid);

#endif // __ANDROID_VNDK__

__END_DECLS
