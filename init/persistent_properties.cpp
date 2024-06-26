/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "persistent_properties.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>

#include <memory>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "util.h"

using android::base::Dirname;
using android::base::ReadFdToString;
using android::base::StartsWith;
using android::base::unique_fd;
using android::base::WriteStringToFd;

namespace android {
namespace init {

std::string persistent_property_filename = "/data/property/persistent_properties";

namespace {

constexpr const char kLegacyPersistentPropertyDir[] = "/data/property";

void AddPersistentProperty(const std::string& name, const std::string& value,
                           PersistentProperties* persistent_properties) {
    auto persistent_property_record = persistent_properties->add_properties();
    persistent_property_record->set_name(name);
    persistent_property_record->set_value(value);
}

Result<PersistentProperties> LoadLegacyPersistentProperties() {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(kLegacyPersistentPropertyDir), closedir);
    if (!dir) {
        return ErrnoError() << "Unable to open persistent property directory \""
                            << kLegacyPersistentPropertyDir << "\"";
    }

    PersistentProperties persistent_properties;
    dirent* entry;
    while ((entry = readdir(dir.get())) != nullptr) {
        if (!StartsWith(entry->d_name, "persist.")) {
            continue;
        }
        if (entry->d_type != DT_REG) {
            continue;
        }

        unique_fd fd(openat(dirfd(dir.get()), entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
        if (fd == -1) {
            PLOG(ERROR) << "Unable to open persistent property file \"" << entry->d_name << "\"";
            continue;
        }

        struct stat sb;
        if (fstat(fd.get(), &sb) == -1) {
            PLOG(ERROR) << "fstat on property file \"" << entry->d_name << "\" failed";
            continue;
        }

        // File must not be accessible to others, be owned by root/root, and
        // not be a hard link to any other file.
        if (((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) || sb.st_uid != 0 || sb.st_gid != 0 ||
            sb.st_nlink != 1) {
            PLOG(ERROR) << "skipping insecure property file " << entry->d_name
                        << " (uid=" << sb.st_uid << " gid=" << sb.st_gid << " nlink=" << sb.st_nlink
                        << " mode=" << std::oct << sb.st_mode << ")";
            continue;
        }

        std::string value;
        if (ReadFdToString(fd, &value)) {
            AddPersistentProperty(entry->d_name, value, &persistent_properties);
        } else {
            PLOG(ERROR) << "Unable to read persistent property file " << entry->d_name;
        }
    }
    return persistent_properties;
}

void RemoveLegacyPersistentPropertyFiles() {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(kLegacyPersistentPropertyDir), closedir);
    if (!dir) {
        PLOG(ERROR) << "Unable to open persistent property directory \""
                    << kLegacyPersistentPropertyDir << "\"";
        return;
    }

    dirent* entry;
    while ((entry = readdir(dir.get())) != nullptr) {
        if (!StartsWith(entry->d_name, "persist.")) {
            continue;
        }
        if (entry->d_type != DT_REG) {
            continue;
        }
        unlinkat(dirfd(dir.get()), entry->d_name, 0);
    }
}

Result<std::string> ReadPersistentPropertyFile() {
    const std::string temp_filename = persistent_property_filename + ".tmp";
    if (access(temp_filename.c_str(), F_OK) == 0) {
        LOG(INFO)
            << "Found temporary property file while attempting to persistent system properties"
               " a previous persistent property write may have failed";
        unlink(temp_filename.c_str());
    }
    auto file_contents = ReadFile(persistent_property_filename);
    if (!file_contents.ok()) {
        return Error() << "Unable to read persistent property file: " << file_contents.error();
    }
    return *file_contents;
}

Result<PersistentProperties> ParsePersistentPropertyFile(const std::string& file_contents) {
    PersistentProperties persistent_properties;
    if (!persistent_properties.ParseFromString(file_contents)) {
        return Error() << "Unable to parse persistent property file: Could not parse protobuf";
    }
    for (auto& prop : persistent_properties.properties()) {
        if (!StartsWith(prop.name(), "persist.") && !StartsWith(prop.name(), "next_boot.")) {
            return Error() << "Unable to load persistent property file: property '" << prop.name()
                           << "' doesn't start with 'persist.' or 'next_boot.'";
        }
    }
    return persistent_properties;
}

}  // namespace

Result<PersistentProperties> LoadPersistentPropertyFile() {
    auto file_contents = ReadPersistentPropertyFile();
    if (!file_contents.ok()) return file_contents.error();

    auto persistent_properties = ParsePersistentPropertyFile(*file_contents);
    if (!persistent_properties.ok()) {
        // If the file cannot be parsed in either format, then we don't have any recovery
        // mechanisms, so we delete it to allow for future writes to take place successfully.
        unlink(persistent_property_filename.c_str());
    }
    return persistent_properties;
}

Result<void> WritePersistentPropertyFile(const PersistentProperties& persistent_properties) {
    const std::string temp_filename = persistent_property_filename + ".tmp";
    unique_fd fd(TEMP_FAILURE_RETRY(
        open(temp_filename.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC | O_CLOEXEC, 0600)));
    if (fd == -1) {
        return ErrnoError() << "Could not open temporary properties file";
    }
    std::string serialized_string;
    if (!persistent_properties.SerializeToString(&serialized_string)) {
        return Error() << "Unable to serialize properties";
    }
    if (!WriteStringToFd(serialized_string, fd)) {
        return ErrnoError() << "Unable to write file contents";
    }
    fsync(fd.get());
    fd.reset();

    if (rename(temp_filename.c_str(), persistent_property_filename.c_str())) {
        int saved_errno = errno;
        unlink(temp_filename.c_str());
        return Error(saved_errno) << "Unable to rename persistent property file";
    }

    // rename() is atomic with regards to the kernel's filesystem buffers, but the parent
    // directories must be fsync()'ed otherwise, the rename is not necessarily written to storage.
    // Note in this case, that the source and destination directories are the same, so only one
    // fsync() is required.
    auto dir = Dirname(persistent_property_filename);
    auto dir_fd = unique_fd{open(dir.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC)};
    if (dir_fd < 0) {
        return ErrnoError() << "Unable to open persistent properties directory for fsync()";
    }
    fsync(dir_fd.get());

    return {};
}

PersistentProperties LoadPersistentPropertiesFromMemory() {
    PersistentProperties persistent_properties;
    __system_property_foreach(
            [](const prop_info* pi, void* cookie) {
                __system_property_read_callback(
                        pi,
                        [](void* cookie, const char* name, const char* value, unsigned serial) {
                            if (StartsWith(name, "persist.")) {
                                auto properties = reinterpret_cast<PersistentProperties*>(cookie);
                                AddPersistentProperty(name, value, properties);
                            }
                        },
                        cookie);
            },
            &persistent_properties);
    return persistent_properties;
}

// Persistent properties are not written often, so we rather not keep any data in memory and read
// then rewrite the persistent property file for each update.
void WritePersistentProperty(const std::string& name, const std::string& value) {
    auto persistent_properties = LoadPersistentPropertyFile();

    if (!persistent_properties.ok()) {
        LOG(ERROR) << "Recovering persistent properties from memory: "
                   << persistent_properties.error();
        persistent_properties = LoadPersistentPropertiesFromMemory();
    }
    auto it = std::find_if(persistent_properties->mutable_properties()->begin(),
                           persistent_properties->mutable_properties()->end(),
                           [&name](const auto& record) { return record.name() == name; });
    if (it != persistent_properties->mutable_properties()->end()) {
        if (it->value() == value) {
            return;
        }
        it->set_name(name);
        it->set_value(value);
    } else {
        AddPersistentProperty(name, value, &persistent_properties.value());
    }

    if (auto result = WritePersistentPropertyFile(*persistent_properties); !result.ok()) {
        LOG(ERROR) << "Could not store persistent property: " << result.error();
    }
}

PersistentProperties LoadPersistentProperties() {
    auto persistent_properties = LoadPersistentPropertyFile();

    if (!persistent_properties.ok()) {
        LOG(ERROR) << "Could not load single persistent property file, trying legacy directory: "
                   << persistent_properties.error();
        persistent_properties = LoadLegacyPersistentProperties();
        if (!persistent_properties.ok()) {
            LOG(ERROR) << "Unable to load legacy persistent properties: "
                       << persistent_properties.error();
            return {};
        }
        if (auto result = WritePersistentPropertyFile(*persistent_properties); result.ok()) {
            RemoveLegacyPersistentPropertyFiles();
        } else {
            LOG(ERROR) << "Unable to write single persistent property file: " << result.error();
            // Fall through so that we still set the properties that we've read.
        }
    }

    // loop over to find all staged props
    auto const staged_prefix = std::string_view("next_boot.");
    auto staged_props = std::unordered_map<std::string, std::string>();
    for (const auto& property_record : persistent_properties->properties()) {
        auto const& prop_name = property_record.name();
        auto const& prop_value = property_record.value();
        if (StartsWith(prop_name, staged_prefix)) {
            auto actual_prop_name = prop_name.substr(staged_prefix.size());
            staged_props[actual_prop_name] = prop_value;
        }
    }

    if (staged_props.empty()) {
        return *persistent_properties;
    }

    // if has staging, apply staging and perserve the original prop order
    PersistentProperties updated_persistent_properties;
    for (const auto& property_record : persistent_properties->properties()) {
        auto const& prop_name = property_record.name();
        auto const& prop_value = property_record.value();

        // don't include staged props anymore
        if (StartsWith(prop_name, staged_prefix)) {
            continue;
        }

        auto iter = staged_props.find(prop_name);
        if (iter != staged_props.end()) {
            AddPersistentProperty(prop_name, iter->second, &updated_persistent_properties);
            staged_props.erase(iter);
        } else {
            AddPersistentProperty(prop_name, prop_value, &updated_persistent_properties);
        }
    }

    // add any additional staged props
    for (auto const& [prop_name, prop_value] : staged_props) {
        AddPersistentProperty(prop_name, prop_value, &updated_persistent_properties);
    }

    // write current updated persist prop file
    auto result = WritePersistentPropertyFile(updated_persistent_properties);
    if (!result.ok()) {
        LOG(ERROR) << "Could not store persistent property: " << result.error();
    }

    return updated_persistent_properties;
}



}  // namespace init
}  // namespace android
