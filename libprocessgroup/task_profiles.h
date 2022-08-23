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
#include <string_view>
#include <vector>

#include <android-base/unique_fd.h>
#include <cgroup_map.h>

class IProfileAttribute {
  public:
    virtual ~IProfileAttribute() = 0;
    virtual void Reset(const CgroupController& controller, const std::string& file_name) = 0;
    virtual const CgroupController* controller() const = 0;
    virtual const std::string& file_name() const = 0;
    virtual bool GetPathForTask(int tid, std::string* path) const = 0;
};

class ProfileAttribute : public IProfileAttribute {
  public:
    // Cgroup attributes may have different names in the v1 and v2 hierarchies. If `file_v2_name` is
    // not empty, `file_name` is the name for the v1 hierarchy and `file_v2_name` is the name for
    // the v2 hierarchy. If `file_v2_name` is empty, `file_name` is used for both hierarchies.
    ProfileAttribute(const CgroupController& controller, const std::string& file_name,
                     const std::string& file_v2_name)
        : controller_(controller), file_name_(file_name), file_v2_name_(file_v2_name) {}
    ~ProfileAttribute() = default;

    const CgroupController* controller() const override { return &controller_; }
    const std::string& file_name() const override { return file_name_; }
    void Reset(const CgroupController& controller, const std::string& file_name) override;

    bool GetPathForTask(int tid, std::string* path) const override;

  private:
    CgroupController controller_;
    std::string file_name_;
    std::string file_v2_name_;
};

// Abstract profile element
class ProfileAction {
  public:
    enum ResourceCacheType { RCT_TASK = 0, RCT_PROCESS, RCT_COUNT };

    virtual ~ProfileAction() {}

    virtual const char* Name() const = 0;

    // Default implementations will fail
    virtual bool ExecuteForProcess(uid_t, pid_t) const { return false; };
    virtual bool ExecuteForTask(int) const { return false; };

    virtual void EnableResourceCaching(ResourceCacheType) {}
    virtual void DropResourceCaching(ResourceCacheType) {}

  protected:
    enum CacheUseResult { SUCCESS, FAIL, UNUSED };
};

// Profile actions
class SetClampsAction : public ProfileAction {
  public:
    SetClampsAction(int boost, int clamp) noexcept : boost_(boost), clamp_(clamp) {}

    const char* Name() const override { return "SetClamps"; }
    bool ExecuteForProcess(uid_t uid, pid_t pid) const override;
    bool ExecuteForTask(int tid) const override;

  protected:
    int boost_;
    int clamp_;
};

class SetTimerSlackAction : public ProfileAction {
  public:
    SetTimerSlackAction(unsigned long slack) noexcept : slack_(slack) {}

    const char* Name() const override { return "SetTimerSlack"; }
    bool ExecuteForTask(int tid) const override;

  private:
    unsigned long slack_;

    static bool IsTimerSlackSupported(int tid);
};

// Set attribute profile element
class SetAttributeAction : public ProfileAction {
  public:
    SetAttributeAction(const IProfileAttribute* attribute, const std::string& value, bool optional)
        : attribute_(attribute), value_(value), optional_(optional) {}

    const char* Name() const override { return "SetAttribute"; }
    bool ExecuteForProcess(uid_t uid, pid_t pid) const override;
    bool ExecuteForTask(int tid) const override;

  private:
    const IProfileAttribute* attribute_;
    std::string value_;
    bool optional_;
};

// Set cgroup profile element
class SetCgroupAction : public ProfileAction {
  public:
    SetCgroupAction(const CgroupController& c, const std::string& p);

    const char* Name() const override { return "SetCgroup"; }
    bool ExecuteForProcess(uid_t uid, pid_t pid) const override;
    bool ExecuteForTask(int tid) const override;
    void EnableResourceCaching(ResourceCacheType cache_type) override;
    void DropResourceCaching(ResourceCacheType cache_type) override;

    const CgroupController* controller() const { return &controller_; }

  private:
    CgroupController controller_;
    std::string path_;
    android::base::unique_fd fd_[ProfileAction::RCT_COUNT];
    mutable std::mutex fd_mutex_;

    static bool AddTidToCgroup(int tid, int fd, const char* controller_name);
    CacheUseResult UseCachedFd(ResourceCacheType cache_type, int id) const;
};

// Write to file action
class WriteFileAction : public ProfileAction {
  public:
    WriteFileAction(const std::string& task_path, const std::string& proc_path,
                    const std::string& value, bool logfailures);

    const char* Name() const override { return "WriteFile"; }
    bool ExecuteForProcess(uid_t uid, pid_t pid) const override;
    bool ExecuteForTask(int tid) const override;
    void EnableResourceCaching(ResourceCacheType cache_type) override;
    void DropResourceCaching(ResourceCacheType cache_type) override;

  private:
    std::string task_path_, proc_path_, value_;
    bool logfailures_;
    android::base::unique_fd fd_[ProfileAction::RCT_COUNT];
    mutable std::mutex fd_mutex_;

    bool WriteValueToFile(const std::string& value, ResourceCacheType cache_type, int uid, int pid,
                          bool logfailures) const;
    CacheUseResult UseCachedFd(ResourceCacheType cache_type, const std::string& value) const;
};

class TaskProfile {
  public:
    TaskProfile(const std::string& name) : name_(name), res_cached_(false) {}

    const std::string& Name() const { return name_; }
    void Add(std::unique_ptr<ProfileAction> e) { elements_.push_back(std::move(e)); }
    void MoveTo(TaskProfile* profile);

    bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    bool ExecuteForTask(int tid) const;
    void EnableResourceCaching(ProfileAction::ResourceCacheType cache_type);
    void DropResourceCaching(ProfileAction::ResourceCacheType cache_type);

  private:
    const std::string name_;
    bool res_cached_;
    std::vector<std::unique_ptr<ProfileAction>> elements_;
};

// Set aggregate profile element
class ApplyProfileAction : public ProfileAction {
  public:
    ApplyProfileAction(const std::vector<std::shared_ptr<TaskProfile>>& profiles)
        : profiles_(profiles) {}

    const char* Name() const override { return "ApplyProfileAction"; }
    bool ExecuteForProcess(uid_t uid, pid_t pid) const override;
    bool ExecuteForTask(int tid) const override;
    void EnableResourceCaching(ProfileAction::ResourceCacheType cache_type) override;
    void DropResourceCaching(ProfileAction::ResourceCacheType cache_type) override;

  private:
    std::vector<std::shared_ptr<TaskProfile>> profiles_;
};

class TaskProfiles {
  public:
    // Should be used by all users
    static TaskProfiles& GetInstance();

    TaskProfile* GetProfile(std::string_view name) const;
    const IProfileAttribute* GetAttribute(std::string_view name) const;
    void DropResourceCaching(ProfileAction::ResourceCacheType cache_type) const;
    bool SetProcessProfiles(uid_t uid, pid_t pid, const std::vector<std::string>& profiles,
                            bool use_fd_cache);
    bool SetTaskProfiles(int tid, const std::vector<std::string>& profiles, bool use_fd_cache);

  private:
    TaskProfiles();

    bool Load(const CgroupMap& cg_map, const std::string& file_name);

    std::map<std::string, std::shared_ptr<TaskProfile>, std::less<>> profiles_;
    std::map<std::string, std::unique_ptr<IProfileAttribute>, std::less<>> attributes_;
};
