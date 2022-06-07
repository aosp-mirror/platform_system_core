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
#include <vector>

#include <android-base/unique_fd.h>
#include <cgroup_map.h>

class ProfileAttribute {
  public:
    ProfileAttribute(const CgroupController& controller, const std::string& file_name)
        : controller_(controller), file_name_(file_name) {}

    const CgroupController* controller() const { return &controller_; }
    const std::string& file_name() const { return file_name_; }
    void Reset(const CgroupController& controller, const std::string& file_name);

    bool GetPathForTask(int tid, std::string* path) const;

  private:
    CgroupController controller_;
    std::string file_name_;
};

// Abstract profile element
class ProfileAction {
  public:
    enum ResourceCacheType { RCT_TASK = 0, RCT_PROCESS, RCT_COUNT };

    virtual ~ProfileAction() {}

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

    virtual bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual bool ExecuteForTask(int tid) const;

  protected:
    int boost_;
    int clamp_;
};

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)

class SetTimerSlackAction : public ProfileAction {
  public:
    SetTimerSlackAction(unsigned long slack) noexcept : slack_(slack) {}

    virtual bool ExecuteForTask(int tid) const;

  private:
    unsigned long slack_;

    static bool IsTimerSlackSupported(int tid);
};

#else

class SetTimerSlackAction : public ProfileAction {
  public:
    SetTimerSlackAction(unsigned long) noexcept {}

    virtual bool ExecuteForTask(int) const { return true; }
};

#endif

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
    SetCgroupAction(const CgroupController& c, const std::string& p);

    virtual bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual bool ExecuteForTask(int tid) const;
    virtual void EnableResourceCaching(ResourceCacheType cache_type);
    virtual void DropResourceCaching(ResourceCacheType cache_type);

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
    WriteFileAction(const std::string& path, const std::string& value, bool logfailures);

    virtual bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual bool ExecuteForTask(int tid) const;
    virtual void EnableResourceCaching(ResourceCacheType cache_type);
    virtual void DropResourceCaching(ResourceCacheType cache_type);

  private:
    std::string path_, value_;
    bool logfailures_;
    android::base::unique_fd fd_;
    mutable std::mutex fd_mutex_;

    static bool WriteValueToFile(const std::string& value, const std::string& path,
                                 bool logfailures);
    CacheUseResult UseCachedFd(ResourceCacheType cache_type, const std::string& value) const;
};

class TaskProfile {
  public:
    TaskProfile() : res_cached_(false) {}

    void Add(std::unique_ptr<ProfileAction> e) { elements_.push_back(std::move(e)); }
    void MoveTo(TaskProfile* profile);

    bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    bool ExecuteForTask(int tid) const;
    void EnableResourceCaching(ProfileAction::ResourceCacheType cache_type);
    void DropResourceCaching(ProfileAction::ResourceCacheType cache_type);

  private:
    bool res_cached_;
    std::vector<std::unique_ptr<ProfileAction>> elements_;
};

// Set aggregate profile element
class ApplyProfileAction : public ProfileAction {
  public:
    ApplyProfileAction(const std::vector<std::shared_ptr<TaskProfile>>& profiles)
        : profiles_(profiles) {}

    virtual bool ExecuteForProcess(uid_t uid, pid_t pid) const;
    virtual bool ExecuteForTask(int tid) const;
    virtual void EnableResourceCaching(ProfileAction::ResourceCacheType cache_type);
    virtual void DropResourceCaching(ProfileAction::ResourceCacheType cache_type);

  private:
    std::vector<std::shared_ptr<TaskProfile>> profiles_;
};

class TaskProfiles {
  public:
    // Should be used by all users
    static TaskProfiles& GetInstance();

    TaskProfile* GetProfile(const std::string& name) const;
    const ProfileAttribute* GetAttribute(const std::string& name) const;
    void DropResourceCaching(ProfileAction::ResourceCacheType cache_type) const;
    bool SetProcessProfiles(uid_t uid, pid_t pid, const std::vector<std::string>& profiles,
                            bool use_fd_cache);
    bool SetTaskProfiles(int tid, const std::vector<std::string>& profiles, bool use_fd_cache);

  private:
    std::map<std::string, std::shared_ptr<TaskProfile>> profiles_;
    std::map<std::string, std::unique_ptr<ProfileAttribute>> attributes_;

    TaskProfiles();

    bool Load(const CgroupMap& cg_map, const std::string& file_name);
};
