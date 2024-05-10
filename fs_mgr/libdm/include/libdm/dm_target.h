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

    uint32_t major_version() const { return major_; }
    uint32_t minor_version() const { return minor_; }
    uint32_t patch_level() const { return patch_; }

    bool IsAtLeast(uint32_t major, uint32_t minor, uint32_t patch) const {
        if (major_ > major) return true;
        if (major_ < major) return false;
        if (minor_ > minor) return true;
        if (minor_ < minor) return false;
        return patch_ >= patch;
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

class DmTargetStripe final : public DmTarget {
  public:
    DmTargetStripe(uint64_t start, uint64_t length, uint64_t chunksize,
                   const std::string& block_device0, const std::string& block_device1)
        : DmTarget(start, length),
          chunksize(chunksize),
          block_device0_(block_device0),
          block_device1_(block_device1) {}

    std::string name() const override { return "striped"; }
    std::string GetParameterString() const override;

  private:
    uint64_t chunksize;
    std::string block_device0_;
    std::string block_device1_;
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
    void CheckAtMostOnce();

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

    void SetBlockSize(uint32_t block_size) { block_size_ = block_size; }

    std::string name() const override { return "bow"; }
    std::string GetParameterString() const override;

  private:
    std::string target_string_;
    uint32_t block_size_ = 0;
};

enum class SnapshotStorageMode {
    // The snapshot will be persisted to the COW device.
    Persistent,
    // The snapshot will be lost on reboot.
    Transient,
    // The snapshot will be merged from the COW device into the base device,
    // in the background.
    Merge
};

// Writes to a snapshot device will be written to the given COW device. Reads
// will read from the COW device or base device. The chunk size is specified
// in sectors.
class DmTargetSnapshot final : public DmTarget {
  public:
    DmTargetSnapshot(uint64_t start, uint64_t length, const std::string& base_device,
                     const std::string& cow_device, SnapshotStorageMode mode, uint64_t chunk_size)
        : DmTarget(start, length),
          base_device_(base_device),
          cow_device_(cow_device),
          mode_(mode),
          chunk_size_(chunk_size) {}

    std::string name() const override;
    std::string GetParameterString() const override;
    bool Valid() const override { return true; }

    struct Status {
        uint64_t sectors_allocated;
        uint64_t total_sectors;
        uint64_t metadata_sectors;
        std::string error;
    };

    static double MergePercent(const Status& status, uint64_t sectors_initial = 0);
    static bool ParseStatusText(const std::string& text, Status* status);
    static bool ReportsOverflow(const std::string& target_type);
    static bool GetDevicesFromParams(const std::string& params, std::string* base_device,
                                     std::string* cow_device);

  private:
    std::string base_device_;
    std::string cow_device_;
    SnapshotStorageMode mode_;
    uint64_t chunk_size_;
};

// snapshot-origin will read/write directly to the backing device, updating any
// snapshot devices with a matching origin.
class DmTargetSnapshotOrigin final : public DmTarget {
  public:
    DmTargetSnapshotOrigin(uint64_t start, uint64_t length, const std::string& device)
        : DmTarget(start, length), device_(device) {}

    std::string name() const override { return "snapshot-origin"; }
    std::string GetParameterString() const override { return device_; }
    bool Valid() const override { return true; }

  private:
    std::string device_;
};

class DmTargetCrypt final : public DmTarget {
  public:
    DmTargetCrypt(uint64_t start, uint64_t length, const std::string& cipher,
                  const std::string& key, uint64_t iv_sector_offset, const std::string& device,
                  uint64_t device_sector)
        : DmTarget(start, length),
          cipher_(cipher),
          key_(key),
          iv_sector_offset_(iv_sector_offset),
          device_(device),
          device_sector_(device_sector) {}

    void AllowDiscards() { allow_discards_ = true; }
    void AllowEncryptOverride() { allow_encrypt_override_ = true; }
    void SetIvLargeSectors() { iv_large_sectors_ = true; }
    void SetSectorSize(uint32_t sector_size) { sector_size_ = sector_size; }

    std::string name() const override { return "crypt"; }
    bool Valid() const override { return true; }
    std::string GetParameterString() const override;

  private:
    std::string cipher_;
    std::string key_;
    uint64_t iv_sector_offset_;
    std::string device_;
    uint64_t device_sector_;
    bool allow_discards_ = false;
    bool allow_encrypt_override_ = false;
    bool iv_large_sectors_ = false;
    uint32_t sector_size_ = 0;
};

class DmTargetDefaultKey final : public DmTarget {
  public:
    DmTargetDefaultKey(uint64_t start, uint64_t length, const std::string& cipher,
                       const std::string& key, const std::string& blockdev, uint64_t start_sector)
        : DmTarget(start, length),
          cipher_(cipher),
          key_(key),
          blockdev_(blockdev),
          start_sector_(start_sector) {}

    std::string name() const override { return kName; }
    bool Valid() const override;
    std::string GetParameterString() const override;
    void SetUseLegacyOptionsFormat() { use_legacy_options_format_ = true; }
    void SetSetDun() { set_dun_ = true; }
    void SetWrappedKeyV0() { is_hw_wrapped_ = true; }

  private:
    inline static const std::string kName = "default-key";

    std::string cipher_;
    std::string key_;
    std::string blockdev_;
    uint64_t start_sector_;
    bool use_legacy_options_format_ = false;
    bool set_dun_ = false;
    bool is_hw_wrapped_ = false;
};

class DmTargetUser final : public DmTarget {
  public:
    DmTargetUser(uint64_t start, uint64_t length, std::string control_device)
        : DmTarget(start, length), control_device_(control_device) {}

    std::string name() const override { return "user"; }
    std::string control_device() const { return control_device_; }
    std::string GetParameterString() const override;

  private:
    std::string control_device_;
};

class DmTargetError final : public DmTarget {
  public:
    DmTargetError(uint64_t start, uint64_t length) : DmTarget(start, length) {}

    std::string name() const override { return "error"; }
    std::string GetParameterString() const override { return ""; }
};

class DmTargetThinPool final : public DmTarget {
  public:
    DmTargetThinPool(uint64_t start, uint64_t length, const std::string& metadata_dev,
                     const std::string& data_dev, uint64_t data_block_size,
                     uint64_t low_water_mark);

    std::string name() const override { return "thin-pool"; }
    std::string GetParameterString() const override;
    bool Valid() const override;

  private:
    std::string metadata_dev_;
    std::string data_dev_;
    uint64_t data_block_size_;
    uint64_t low_water_mark_;
};

class DmTargetThin final : public DmTarget {
  public:
    DmTargetThin(uint64_t start, uint64_t length, const std::string& pool_dev, uint64_t dev_id);

    std::string name() const override { return "thin"; }
    std::string GetParameterString() const override;

  private:
    std::string pool_dev_;
    uint64_t dev_id_;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DMTARGET_H_ */
