/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_DEVICES_H
#define _INIT_DEVICES_H

#include <sys/stat.h>
#include <sys/types.h>

#include <functional>
#include <string>
#include <vector>

#include "init_parser.h"

enum coldboot_action_t {
    // coldboot continues without creating the device for the uevent
    COLDBOOT_CONTINUE = 0,
    // coldboot continues after creating the device for the uevent
    COLDBOOT_CREATE,
    // coldboot stops after creating the device for uevent but doesn't
    // create the COLDBOOT_DONE file
    COLDBOOT_STOP,
    // same as COLDBOOT_STOP, but creates the COLDBOOT_DONE file
    COLDBOOT_FINISH
};

struct uevent {
    std::string action;
    std::string path;
    std::string subsystem;
    std::string firmware;
    std::string partition_name;
    std::string device_name;
    int partition_num;
    int major;
    int minor;
};

class Permissions {
  public:
    Permissions(const std::string& name, mode_t perm, uid_t uid, gid_t gid);

    bool Match(const std::string& path) const;

    mode_t perm() const { return perm_; }
    uid_t uid() const { return uid_; }
    gid_t gid() const { return gid_; }

  protected:
    const std::string& name() const { return name_; }

  private:
    std::string name_;
    mode_t perm_;
    uid_t uid_;
    gid_t gid_;
    bool prefix_;
    bool wildcard_;
};

class SysfsPermissions : public Permissions {
  public:
    SysfsPermissions(const std::string& name, const std::string& attribute, mode_t perm, uid_t uid,
                     gid_t gid)
        : Permissions(name, perm, uid, gid), attribute_(attribute) {}

    bool MatchWithSubsystem(const std::string& path, const std::string& subsystem) const;
    void SetPermissions(const std::string& path) const;

  private:
    const std::string attribute_;
};

class Subsystem {
  public:
    friend class SubsystemParser;

    Subsystem() {}

    // Returns the full path for a uevent of a device that is a member of this subsystem,
    // according to the rules parsed from ueventd.rc
    std::string ParseDevPath(uevent* uevent) const;

    bool operator==(const std::string& string_name) { return name_ == string_name; }

  private:
    enum class DevnameSource {
        DEVNAME_UEVENT_DEVNAME,
        DEVNAME_UEVENT_DEVPATH,
    };

    std::string name_;
    std::string dir_name_ = "/dev";
    DevnameSource devname_source_;
};

class SubsystemParser : public SectionParser {
  public:
    SubsystemParser() {}
    bool ParseSection(std::vector<std::string>&& args, const std::string& filename, int line,
                      std::string* err) override;
    bool ParseLineSection(std::vector<std::string>&& args, int line, std::string* err) override;
    void EndSection() override;

  private:
    bool ParseDevName(std::vector<std::string>&& args, std::string* err);
    bool ParseDirName(std::vector<std::string>&& args, std::string* err);

    Subsystem subsystem_;
};

bool ParsePermissionsLine(std::vector<std::string>&& args, std::string* err, bool is_sysfs);
typedef std::function<coldboot_action_t(struct uevent* uevent)> coldboot_callback;
extern coldboot_action_t handle_device_fd(coldboot_callback fn = nullptr);
extern void device_init(const char* path = nullptr, coldboot_callback fn = nullptr);
extern void device_close();
int get_device_fd();

// Exposed for testing
extern std::vector<std::string> platform_devices;
bool find_platform_device(const std::string& path, std::string* out_path);
std::vector<std::string> get_character_device_symlinks(uevent* uevent);
std::vector<std::string> get_block_device_symlinks(uevent* uevent);
void sanitize_partition_name(std::string* string);
void handle_platform_device_event(uevent* uevent);

#endif /* _INIT_DEVICES_H */
