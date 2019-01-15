/*
 *  Copyright 2018 Google, Inc
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

#ifndef _LIBDM_DMTARGET_H_
#define _LIBDM_DMTARGET_H_

#include <linux/dm-ioctl.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace android {
namespace dm {

class DmTargetTypeInfo {
  public:
    DmTargetTypeInfo() : major_(0), minor_(0), patch_(0) {}
    DmTargetTypeInfo(const struct dm_target_versions* info)
        : name_(info->name),
          major_(info->version[0]),
          minor_(info->version[1]),
          patch_(info->version[2]) {}

    const std::string& name() const { return name_; }
    std::string version() const {
        return std::to_string(major_) + "." + std::to_string(minor_) + "." + std::to_string(patch_);
    }

  private:
    std::string name_;
    uint32_t major_;
    uint32_t minor_;
    uint32_t patch_;
};

class DmTarget {
  public:
    DmTarget(uint64_t start, uint64_t length) : start_(start), length_(length) {}

    virtual ~DmTarget() = default;

    // Returns name of the target.
    virtual std::string name() const = 0;

    // Return the first logical sector represented by this target.
    uint64_t start() const { return start_; }

    // Returns size in number of sectors when this target is part of
    // a DmTable, return 0 otherwise.
    uint64_t size() const { return length_; }

    // Function that converts this object to a string of arguments that can
    // be passed to the kernel for adding this target in a table. Each target (e.g. verity, linear)
    // must implement this, for it to be used on a device.
    std::string Serialize() const;

    virtual bool Valid() const { return true; }

  protected:
    // Get the parameter string that is passed to the end of the dm_target_spec
    // for this target type.
    virtual std::string GetParameterString() const = 0;

  private:
    // logical sector number start and total length (in terms of 512-byte sectors) represented
    // by this target within a DmTable.
    uint64_t start_, length_;
};

class DmTargetZero final : public DmTarget {
  public:
    DmTargetZero(uint64_t start, uint64_t length) : DmTarget(start, length) {}

    std::string name() const override { return "zero"; }
    std::string GetParameterString() const override;
};

class DmTargetLinear final : public DmTarget {
  public:
    DmTargetLinear(uint64_t start, uint64_t length, const std::string& block_device,
                   uint64_t physical_sector)
        : DmTarget(start, length), block_device_(block_device), physical_sector_(physical_sector) {}

    std::string name() const override { return "linear"; }
    std::string GetParameterString() const override;
    const std::string& block_device() const { return block_device_; }

  private:
    std::string block_device_;
    uint64_t physical_sector_;
};

class DmTargetVerity final : public DmTarget {
  public:
    DmTargetVerity(uint64_t start, uint64_t length, uint32_t version,
                   const std::string& block_device, const std::string& hash_device,
                   uint32_t data_block_size, uint32_t hash_block_size, uint32_t num_data_blocks,
                   uint32_t hash_start_block, const std::string& hash_algorithm,
                   const std::string& root_digest, const std::string& salt);

    void UseFec(const std::string& device, uint32_t num_roots, uint32_t num_blocks, uint32_t start);
    void SetVerityMode(const std::string& mode);
    void IgnoreZeroBlocks();

    std::string name() const override { return "verity"; }
    std::string GetParameterString() const override;
    bool Valid() const override { return valid_; }

  private:
    std::vector<std::string> base_args_;
    std::vector<std::string> optional_args_;
    bool valid_;
};

class DmTargetAndroidVerity final : public DmTarget {
  public:
    DmTargetAndroidVerity(uint64_t start, uint64_t length, const std::string& block_device,
                          const std::string& keyid)
        : DmTarget(start, length), keyid_(keyid), block_device_(block_device) {}

    std::string name() const override { return "android-verity"; }
    std::string GetParameterString() const override;

  private:
    std::string keyid_;
    std::string block_device_;
};

// This is the same as DmTargetVerity, but the table may be specified as a raw
// string. This code exists only for fs_mgr_verity and should be avoided. Use
// DmTargetVerity for new code instead.
class DmTargetVerityString final : public DmTarget {
  public:
    DmTargetVerityString(uint64_t start, uint64_t length, const std::string& target_string)
        : DmTarget(start, length), target_string_(target_string) {}

    std::string name() const override { return "verity"; }
    std::string GetParameterString() const override { return target_string_; }
    bool Valid() const override { return true; }

  private:
    std::string target_string_;
};

// dm-bow is the backup on write target that can provide checkpoint capability
// for file systems that do not support checkpoints natively
class DmTargetBow final : public DmTarget {
  public:
    DmTargetBow(uint64_t start, uint64_t length, const std::string& target_string)
        : DmTarget(start, length), target_string_(target_string) {}

    std::string name() const override { return "bow"; }
    std::string GetParameterString() const override { return target_string_; }

  private:
    std::string target_string_;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DMTARGET_H_ */
