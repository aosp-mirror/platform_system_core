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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "util.h"

using android::base::ReadFdToString;
using android::base::StartsWith;
using android::base::WriteStringToFd;
using android::base::unique_fd;

namespace android {
namespace init {

std::string persistent_property_filename = "/data/property/persistent_properties";

namespace {

constexpr const uint32_t kMagic = 0x8495E0B4;
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

        unique_fd fd(openat(dirfd(dir.get()), entry->d_name, O_RDONLY | O_NOFOLLOW));
        if (fd == -1) {
            PLOG(ERROR) << "Unable to open persistent property file \"" << entry->d_name << "\"";
            continue;
        }

        struct stat sb;
        if (fstat(fd, &sb) == -1) {
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

class PersistentPropertyFileParser {
  public:
    PersistentPropertyFileParser(const std::string& contents) : contents_(contents), position_(0) {}
    Result<PersistentProperties> Parse();

  private:
    Result<std::string> ReadString();
    Result<uint32_t> ReadUint32();

    const std::string& contents_;
    size_t position_;
};

Result<PersistentProperties> PersistentPropertyFileParser::Parse() {
    if (auto magic = ReadUint32(); magic) {
        if (*magic != kMagic) {
            return Error() << "Magic value '0x" << std::hex << *magic
                           << "' does not match expected value '0x" << kMagic << "'";
        }
    } else {
        return Error() << "Could not read magic value: " << magic.error();
    }

    if (auto version = ReadUint32(); version) {
        if (*version != 1) {
            return Error() << "Version '" << *version
                           << "' does not match any compatible version: (1)";
        }
    } else {
        return Error() << "Could not read version: " << version.error();
    }

    auto num_properties = ReadUint32();
    if (!num_properties) {
        return Error() << "Could not read num_properties: " << num_properties.error();
    }

    PersistentProperties result;
    while (position_ < contents_.size()) {
        auto name = ReadString();
        if (!name) {
            return Error() << "Could not read name: " << name.error();
        }
        if (!StartsWith(*name, "persist.")) {
            return Error() << "Property '" << *name << "' does not starts with 'persist.'";
        }
        auto value = ReadString();
        if (!value) {
            return Error() << "Could not read value: " << value.error();
        }
        AddPersistentProperty(*name, *value, &result);
    }

    return result;
}

Result<std::string> PersistentPropertyFileParser::ReadString() {
    auto string_length = ReadUint32();
    if (!string_length) {
        return Error() << "Could not read size for string";
    }

    if (position_ + *string_length > contents_.size()) {
        return Error() << "String size would cause it to overflow the input buffer";
    }
    auto result = std::string(contents_, position_, *string_length);
    position_ += *string_length;
    return result;
}

Result<uint32_t> PersistentPropertyFileParser::ReadUint32() {
    if (position_ + 3 > contents_.size()) {
        return Error() << "Input buffer not large enough to read uint32_t";
    }
    uint32_t result = *reinterpret_cast<const uint32_t*>(&contents_[position_]);
    position_ += sizeof(uint32_t);
    return result;
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
    if (!file_contents) {
        return Error() << "Unable to read persistent property file: " << file_contents.error();
    }
    return *file_contents;
}

}  // namespace

Result<PersistentProperties> LoadPersistentPropertyFile() {
    auto file_contents = ReadPersistentPropertyFile();
    if (!file_contents) return file_contents.error();

    // Check the intermediate "I should have used protobufs from the start" format.
    // TODO: Remove this.
    auto parsed_contents = PersistentPropertyFileParser(*file_contents).Parse();
    if (parsed_contents) {
        LOG(INFO) << "Intermediate format persistent property file found, converting to protobuf";

        // Update to the protobuf format
        WritePersistentPropertyFile(*parsed_contents);
        return parsed_contents;
    }

    PersistentProperties persistent_properties;
    if (persistent_properties.ParseFromString(*file_contents)) return persistent_properties;

    // If the file cannot be parsed in either format, then we don't have any recovery
    // mechanisms, so we delete it to allow for future writes to take place successfully.
    unlink(persistent_property_filename.c_str());
    return Error() << "Unable to parse persistent property file: " << parsed_contents.error();
}

Result<Success> WritePersistentPropertyFile(const PersistentProperties& persistent_properties) {
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
    fsync(fd);
    fd.reset();

    if (rename(temp_filename.c_str(), persistent_property_filename.c_str())) {
        int saved_errno = errno;
        unlink(temp_filename.c_str());
        return Error(saved_errno) << "Unable to rename persistent property file";
    }
    return Success();
}

// Persistent properties are not written often, so we rather not keep any data in memory and read
// then rewrite the persistent property file for each update.
void WritePersistentProperty(const std::string& name, const std::string& value) {
    auto file_contents = ReadPersistentPropertyFile();
    PersistentProperties persistent_properties;

    if (!file_contents || !persistent_properties.ParseFromString(*file_contents)) {
        LOG(ERROR) << "Recovering persistent properties from memory: "
                   << (!file_contents ? file_contents.error_string() : "Could not parse protobuf");
        persistent_properties = LoadPersistentPropertiesFromMemory();
    }
    auto it = std::find_if(persistent_properties.mutable_properties()->begin(),
                           persistent_properties.mutable_properties()->end(),
                           [&name](const auto& record) { return record.name() == name; });
    if (it != persistent_properties.mutable_properties()->end()) {
        it->set_name(name);
        it->set_value(value);
    } else {
        AddPersistentProperty(name, value, &persistent_properties);
    }

    if (auto result = WritePersistentPropertyFile(persistent_properties); !result) {
        LOG(ERROR) << "Could not store persistent property: " << result.error();
    }
}

PersistentProperties LoadPersistentProperties() {
    auto persistent_properties = LoadPersistentPropertyFile();

    if (!persistent_properties) {
        LOG(ERROR) << "Could not load single persistent property file, trying legacy directory: "
                   << persistent_properties.error();
        persistent_properties = LoadLegacyPersistentProperties();
        if (!persistent_properties) {
            LOG(ERROR) << "Unable to load legacy persistent properties: "
                       << persistent_properties.error();
            return {};
        }
        if (auto result = WritePersistentPropertyFile(*persistent_properties); result) {
            RemoveLegacyPersistentPropertyFiles();
        } else {
            LOG(ERROR) << "Unable to write single persistent property file: " << result.error();
            // Fall through so that we still set the properties that we've read.
        }
    }

    return *persistent_properties;
}

}  // namespace init
}  // namespace android
