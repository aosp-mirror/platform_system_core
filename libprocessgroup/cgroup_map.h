/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>

#include <map>
#include <mutex>
#include <string>

// Minimal controller description to be mmapped into process address space
class CgroupController {
  public:
    CgroupController() {}
    CgroupController(uint32_t version, const std::string& name, const std::string& path);

    uint32_t version() const { return version_; }
    const char* name() const { return name_; }
    const char* path() const { return path_; }

    std::string GetTasksFilePath(const std::string& path) const;
    std::string GetProcsFilePath(const std::string& path, uid_t uid, pid_t pid) const;
    bool GetTaskGroup(int tid, std::string* group) const;

  private:
    static constexpr size_t CGROUP_NAME_BUF_SZ = 16;
    static constexpr size_t CGROUP_PATH_BUF_SZ = 32;

    uint32_t version_;
    char name_[CGROUP_NAME_BUF_SZ];
    char path_[CGROUP_PATH_BUF_SZ];
};

// Complete controller description for mounting cgroups
class CgroupDescriptor {
  public:
    CgroupDescriptor(uint32_t version, const std::string& name, const std::string& path,
                     mode_t mode, const std::string& uid, const std::string& gid);

    const CgroupController* controller() const { return &controller_; }
    mode_t mode() const { return mode_; }
    std::string uid() const { return uid_; }
    std::string gid() const { return gid_; }

  private:
    CgroupController controller_;
    mode_t mode_;
    std::string uid_;
    std::string gid_;
};

struct CgroupFile {
    static constexpr uint32_t FILE_VERSION_1 = 1;
    static constexpr uint32_t FILE_CURR_VERSION = FILE_VERSION_1;

    uint32_t version_;
    uint32_t controller_count_;
    CgroupController controllers_[];
};

class CgroupMap {
  public:
    static constexpr const char* CGROUPS_RC_FILE = "cgroup.rc";

    // Selinux policy ensures only init process can successfully use this function
    static bool SetupCgroups();

    static CgroupMap& GetInstance();

    const CgroupController* FindController(const std::string& name) const;

  private:
    struct CgroupFile* cg_file_data_;
    size_t cg_file_size_;

    CgroupMap();
    ~CgroupMap();

    bool LoadRcFile();
    void Print();
};
