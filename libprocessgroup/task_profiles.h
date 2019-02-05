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
#include <string>
#include <vector>

#include <android-base/unique_fd.h>
#include <cgroup_map.h>

class ProfileAttribute {
  public:
    ProfileAttribute(const CgroupController* controller, const std::string& file_name)
        : controller_(controller), file_name_(file_name) {}

    const CgroupController* controller() const { return controller_; }
    const std::string& file_name() const { return file_name_; }

    bool GetPathForTask(int tid, std::string* path) const;

  private:
    const CgroupController* controller_;
    std::string file_name_;
};

// Abstract profile element
class ProfileAction {
  public:
    virtual ~ProfileAction() {}

    // Default implementations will fail
    virtual bool ExecuteForProcess(uid_t, pid_t) const { return -1; };
    virtual bool ExecuteForTask(int) const { return -1; };
};

// Profile actions
class SetClampsAction : public ProfileAction {
  public:
    SetClampsAction(int boost, int clamp) noexcept : boost_(boost), clamp_(clamp) {}

    virtual bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual bool ExecuteForTask(int tid) const;

  protected:
    int boost_;
    int clamp_;
};

class SetTimerSlackAction : public ProfileAction {
  public:
    SetTimerSlackAction(unsigned long slack) noexcept : slack_(slack) {}

    virtual bool ExecuteForTask(int tid) const;

  private:
    unsigned long slack_;

    static bool IsTimerSlackSupported(int tid);
};

// Set attribute profile element
class SetAttributeAction : public ProfileAction {
  public:
    SetAttributeAction(const ProfileAttribute* attribute, const std::string& value)
        : attribute_(attribute), value_(value) {}

    virtual bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual bool ExecuteForTask(int tid) const;

  private:
    const ProfileAttribute* attribute_;
    std::string value_;
};

// Set cgroup profile element
class SetCgroupAction : public ProfileAction {
  public:
    SetCgroupAction(const CgroupController* c, const std::string& p);

    virtual bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual bool ExecuteForTask(int tid) const;

    const CgroupController* controller() const { return controller_; }
    std::string path() const { return path_; }

  private:
    const CgroupController* controller_;
    std::string path_;
    android::base::unique_fd fd_;

    static bool IsAppDependentPath(const std::string& path);
    static bool AddTidToCgroup(int tid, int fd);
};

class TaskProfile {
  public:
    TaskProfile() {}

    void Add(std::unique_ptr<ProfileAction> e) { elements_.push_back(std::move(e)); }

    bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    bool ExecuteForTask(int tid) const;

  private:
    std::vector<std::unique_ptr<ProfileAction>> elements_;
};

class TaskProfiles {
  public:
    // Should be used by all users
    static TaskProfiles& GetInstance();

    const TaskProfile* GetProfile(const std::string& name) const;
    const ProfileAttribute* GetAttribute(const std::string& name) const;

  private:
    std::map<std::string, std::unique_ptr<TaskProfile>> profiles_;
    std::map<std::string, std::unique_ptr<ProfileAttribute>> attributes_;

    TaskProfiles();

    bool Load(const CgroupMap& cg_map);
};
