/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "vendor_boot_img_utils.h"

#include <string.h>

#include <android-base/file.h>
#include <android-base/result.h>
#include <bootimg.h>
#include <libavb/libavb.h>

namespace {

using android::base::Result;

// Updates a given buffer by creating a new one.
class DataUpdater {
  public:
    DataUpdater(const std::string& old_data) : old_data_(&old_data) {
        old_data_ptr_ = old_data_->data();
        new_data_.resize(old_data_->size(), '\0');
        new_data_ptr_ = new_data_.data();
    }
    // Copy |num_bytes| from src to dst.
    [[nodiscard]] Result<void> Copy(uint32_t num_bytes) {
        if (num_bytes == 0) return {};
        if (auto res = CheckAdvance(old_data_ptr_, old_end(), num_bytes, __FUNCTION__); !res.ok())
            return res;
        if (auto res = CheckAdvance(new_data_ptr_, new_end(), num_bytes, __FUNCTION__); !res.ok())
            return res;
        memcpy(new_data_ptr_, old_data_ptr_, num_bytes);
        old_data_ptr_ += num_bytes;
        new_data_ptr_ += num_bytes;
        return {};
    }
    // Replace |old_num_bytes| from src with new data.
    [[nodiscard]] Result<void> Replace(uint32_t old_num_bytes, const std::string& new_data) {
        return Replace(old_num_bytes, new_data.data(), new_data.size());
    }
    [[nodiscard]] Result<void> Replace(uint32_t old_num_bytes, const void* new_data,
                                       uint32_t new_data_size) {
        if (auto res = CheckAdvance(old_data_ptr_, old_end(), old_num_bytes, __FUNCTION__);
            !res.ok())
            return res;
        old_data_ptr_ += old_num_bytes;

        if (new_data_size == 0) return {};
        if (auto res = CheckAdvance(new_data_ptr_, new_end(), new_data_size, __FUNCTION__);
            !res.ok())
            return res;
        memcpy(new_data_ptr_, new_data, new_data_size);
        new_data_ptr_ += new_data_size;
        return {};
    }
    // Skip |old_skip| from src and |new_skip| from dst, respectively.
    [[nodiscard]] Result<void> Skip(uint32_t old_skip, uint32_t new_skip) {
        if (auto res = CheckAdvance(old_data_ptr_, old_end(), old_skip, __FUNCTION__); !res.ok())
            return res;
        old_data_ptr_ += old_skip;
        if (auto res = CheckAdvance(new_data_ptr_, new_end(), new_skip, __FUNCTION__); !res.ok())
            return res;
        new_data_ptr_ += new_skip;
        return {};
    }

    [[nodiscard]] Result<void> Seek(uint32_t offset) {
        if (offset > size()) return Errorf("Cannot seek 0x{:x}, size is 0x{:x}", offset, size());
        old_data_ptr_ = old_begin() + offset;
        new_data_ptr_ = new_begin() + offset;
        return {};
    }

    std::string Finish() {
        new_data_ptr_ = nullptr;
        return std::move(new_data_);
    }

    [[nodiscard]] Result<void> CheckOffset(uint32_t old_offset, uint32_t new_offset) {
        if (old_begin() + old_offset != old_cur())
            return Errorf("Old offset mismatch: expected: 0x{:x}, actual: 0x{:x}", old_offset,
                          old_cur() - old_begin());
        if (new_begin() + new_offset != new_cur())
            return Errorf("New offset mismatch: expected: 0x{:x}, actual: 0x{:x}", new_offset,
                          new_cur() - new_begin());
        return {};
    }

    uint64_t size() const { return old_data_->size(); }
    const char* old_begin() const { return old_data_->data(); }
    const char* old_cur() { return old_data_ptr_; }
    const char* old_end() const { return old_data_->data() + old_data_->size(); }
    char* new_begin() { return new_data_.data(); }
    char* new_cur() { return new_data_ptr_; }
    char* new_end() { return new_data_.data() + new_data_.size(); }

  private:
    // Check if it is okay to advance |num_bytes| from |current|.
    [[nodiscard]] Result<void> CheckAdvance(const char* current, const char* end,
                                            uint32_t num_bytes, const char* op) {
        auto new_end = current + num_bytes;
        if (new_end < current /* add overflow */)
            return Errorf("{}: Addition overflow: 0x{} + 0x{:x} < 0x{}", op, fmt::ptr(current),
                          num_bytes, fmt::ptr(current));
        if (new_end > end)
            return Errorf("{}: Boundary overflow: 0x{} + 0x{:x} > 0x{}", op, fmt::ptr(current),
                          num_bytes, fmt::ptr(end));
        return {};
    }
    const std::string* old_data_;
    std::string new_data_;
    const char* old_data_ptr_;
    char* new_data_ptr_;
};

// Get the size of vendor boot header.
[[nodiscard]] Result<uint32_t> get_vendor_boot_header_size(const vendor_boot_img_hdr_v3* hdr) {
    if (hdr->header_version == 3) return sizeof(vendor_boot_img_hdr_v3);
    if (hdr->header_version == 4) return sizeof(vendor_boot_img_hdr_v4);
    return Errorf("Unrecognized vendor boot header version {}", hdr->header_version);
}

// Check that content contains a valid vendor boot image header with a version at least |version|.
[[nodiscard]] Result<void> check_vendor_boot_hdr(const std::string& content, uint32_t version) {
    // get_vendor_boot_header_size reads header_version, so make sure reading it does not
    // go out of bounds by ensuring that the content has at least the size of V3 header.
    if (content.size() < sizeof(vendor_boot_img_hdr_v3)) {
        return Errorf("Size of vendor boot is 0x{:x}, less than size of V3 header: 0x{:x}",
                      content.size(), sizeof(vendor_boot_img_hdr_v3));
    }
    // Now read hdr->header_version and assert the size.
    auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v3*>(content.data());
    auto expect_header_size = get_vendor_boot_header_size(hdr);
    if (!expect_header_size.ok()) return expect_header_size.error();
    if (content.size() < *expect_header_size) {
        return Errorf("Size of vendor boot is 0x{:x}, less than size of V{} header: 0x{:x}",
                      content.size(), version, *expect_header_size);
    }
    if (memcmp(hdr->magic, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE) != 0) {
        return Errorf("Vendor boot image magic mismatch");
    }
    if (hdr->page_size == 0) {
        return Errorf("Page size cannot be zero");
    }
    if (hdr->header_version < version) {
        return Errorf("Require vendor boot header V{} but is V{}", version, hdr->header_version);
    }
    return {};
}

// Wrapper of ReadFdToString. Seek to the beginning and read the whole file to string.
[[nodiscard]] Result<std::string> load_file(android::base::borrowed_fd fd, uint64_t expected_size,
                                            const char* what) {
    if (lseek(fd.get(), 0, SEEK_SET) != 0) {
        return ErrnoErrorf("Can't seek to the beginning of {} image", what);
    }
    std::string content;
    if (!android::base::ReadFdToString(fd, &content)) {
        return ErrnoErrorf("Cannot read {} to string", what);
    }
    if (content.size() != expected_size) {
        return Errorf("Size of {} does not match, expected 0x{:x}, read 0x{:x}", what,
                      expected_size, content.size());
    }
    return content;
}

// Wrapper of WriteStringToFd. Seek to the beginning and write the whole file to string.
[[nodiscard]] Result<void> store_file(android::base::borrowed_fd fd, const std::string& data,
                                      const char* what) {
    if (lseek(fd.get(), 0, SEEK_SET) != 0) {
        return ErrnoErrorf("Cannot seek to beginning of {} before writing", what);
    }
    if (!android::base::WriteStringToFd(data, fd)) {
        return ErrnoErrorf("Cannot write new content to {}", what);
    }
    if (TEMP_FAILURE_RETRY(ftruncate(fd.get(), data.size())) == -1) {
        return ErrnoErrorf("Truncating new vendor boot image to 0x{:x} fails", data.size());
    }
    return {};
}

// Copy AVB footer if it exists in the old buffer.
[[nodiscard]] Result<void> copy_avb_footer(DataUpdater* updater) {
    if (updater->size() < AVB_FOOTER_SIZE) return {};
    if (auto res = updater->Seek(updater->size() - AVB_FOOTER_SIZE); !res.ok()) return res;
    if (memcmp(updater->old_cur(), AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) != 0) return {};
    return updater->Copy(AVB_FOOTER_SIZE);
}

// round |value| up to a multiple of |page_size|.
// aware that this can be integer overflow if value is too large
inline uint32_t round_up(uint32_t value, uint32_t page_size) {
    return (value + page_size - 1) / page_size * page_size;
}

// Replace the vendor ramdisk as a whole.
[[nodiscard]] Result<std::string> replace_default_vendor_ramdisk(const std::string& vendor_boot,
                                                                 const std::string& new_ramdisk) {
    if (auto res = check_vendor_boot_hdr(vendor_boot, 3); !res.ok()) return res.error();
    auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v3*>(vendor_boot.data());
    auto hdr_size = get_vendor_boot_header_size(hdr);
    if (!hdr_size.ok()) return hdr_size.error();
    // Refer to bootimg.h for details. Numbers are in bytes.
    const uint32_t o = round_up(*hdr_size, hdr->page_size);
    const uint32_t p = round_up(hdr->vendor_ramdisk_size, hdr->page_size);
    const uint32_t q = round_up(hdr->dtb_size, hdr->page_size);

    DataUpdater updater(vendor_boot);

    // Copy header (O bytes), then update fields in header.
    if (auto res = updater.Copy(o); !res.ok()) return res.error();
    auto new_hdr = reinterpret_cast<vendor_boot_img_hdr_v3*>(updater.new_begin());
    new_hdr->vendor_ramdisk_size = new_ramdisk.size();
    // Because it is unknown how the new ramdisk is fragmented, the whole table is replaced
    // with a single entry representing the full ramdisk.
    if (new_hdr->header_version >= 4) {
        auto new_hdr_v4 = static_cast<vendor_boot_img_hdr_v4*>(new_hdr);
        new_hdr_v4->vendor_ramdisk_table_entry_size = sizeof(vendor_ramdisk_table_entry_v4);
        new_hdr_v4->vendor_ramdisk_table_entry_num = 1;
        new_hdr_v4->vendor_ramdisk_table_size = new_hdr_v4->vendor_ramdisk_table_entry_num *
                                                new_hdr_v4->vendor_ramdisk_table_entry_size;
    }

    // Copy the new ramdisk.
    if (auto res = updater.Replace(hdr->vendor_ramdisk_size, new_ramdisk); !res.ok())
        return res.error();
    const uint32_t new_p = round_up(new_hdr->vendor_ramdisk_size, new_hdr->page_size);
    if (auto res = updater.Skip(p - hdr->vendor_ramdisk_size, new_p - new_hdr->vendor_ramdisk_size);
        !res.ok())
        return res.error();
    if (auto res = updater.CheckOffset(o + p, o + new_p); !res.ok()) return res.error();

    // Copy DTB (Q bytes).
    if (auto res = updater.Copy(q); !res.ok()) return res.error();

    if (new_hdr->header_version >= 4) {
        auto hdr_v4 = static_cast<const vendor_boot_img_hdr_v4*>(hdr);
        const uint32_t r = round_up(hdr_v4->vendor_ramdisk_table_size, hdr_v4->page_size);
        const uint32_t s = round_up(hdr_v4->bootconfig_size, hdr_v4->page_size);

        auto new_entry = reinterpret_cast<vendor_ramdisk_table_entry_v4*>(updater.new_cur());
        auto new_hdr_v4 = static_cast<const vendor_boot_img_hdr_v4*>(new_hdr);
        auto new_r = round_up(new_hdr_v4->vendor_ramdisk_table_size, new_hdr->page_size);
        if (auto res = updater.Skip(r, new_r); !res.ok()) return res.error();
        if (auto res = updater.CheckOffset(o + p + q + r, o + new_p + q + new_r); !res.ok())
            return res.error();

        // Replace table with single entry representing the full ramdisk.
        new_entry->ramdisk_size = new_hdr->vendor_ramdisk_size;
        new_entry->ramdisk_offset = 0;
        new_entry->ramdisk_type = VENDOR_RAMDISK_TYPE_NONE;
        memset(new_entry->ramdisk_name, '\0', VENDOR_RAMDISK_NAME_SIZE);
        memset(new_entry->board_id, '\0', VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE);

        // Copy bootconfig (S bytes).
        if (auto res = updater.Copy(s); !res.ok()) return res.error();
    }

    if (auto res = copy_avb_footer(&updater); !res.ok()) return res.error();
    return updater.Finish();
}

// Find a ramdisk fragment with a unique name. Abort if none or multiple fragments are found.
[[nodiscard]] Result<const vendor_ramdisk_table_entry_v4*> find_unique_ramdisk(
        const std::string& ramdisk_name, const vendor_ramdisk_table_entry_v4* table,
        uint32_t size) {
    const vendor_ramdisk_table_entry_v4* ret = nullptr;
    uint32_t idx = 0;
    const vendor_ramdisk_table_entry_v4* entry = table;
    for (; idx < size; idx++, entry++) {
        auto entry_name_c_str = reinterpret_cast<const char*>(entry->ramdisk_name);
        auto entry_name_len = strnlen(entry_name_c_str, VENDOR_RAMDISK_NAME_SIZE);
        std::string_view entry_name(entry_name_c_str, entry_name_len);
        if (entry_name == ramdisk_name) {
            if (ret != nullptr) {
                return Errorf("Multiple vendor ramdisk '{}' found, name should be unique",
                              ramdisk_name.c_str());
            }
            ret = entry;
        }
    }
    if (ret == nullptr) {
        return Errorf("Vendor ramdisk '{}' not found", ramdisk_name.c_str());
    }
    return ret;
}

// Find the vendor ramdisk fragment with |ramdisk_name| within the content of |vendor_boot|, and
// replace it with the content of |new_ramdisk|.
[[nodiscard]] Result<std::string> replace_vendor_ramdisk_fragment(const std::string& ramdisk_name,
                                                                  const std::string& vendor_boot,
                                                                  const std::string& new_ramdisk) {
    if (auto res = check_vendor_boot_hdr(vendor_boot, 4); !res.ok()) return res.error();
    auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v4*>(vendor_boot.data());
    auto hdr_size = get_vendor_boot_header_size(hdr);
    if (!hdr_size.ok()) return hdr_size.error();
    // Refer to bootimg.h for details. Numbers are in bytes.
    const uint32_t o = round_up(*hdr_size, hdr->page_size);
    const uint32_t p = round_up(hdr->vendor_ramdisk_size, hdr->page_size);
    const uint32_t q = round_up(hdr->dtb_size, hdr->page_size);
    const uint32_t r = round_up(hdr->vendor_ramdisk_table_size, hdr->page_size);
    const uint32_t s = round_up(hdr->bootconfig_size, hdr->page_size);

    uint64_t total_size = (uint64_t)o + p + q + r + s;
    if (total_size > vendor_boot.size()) {
        return Errorf("Vendor boot image size is too small, overflow");
    }

    if ((uint64_t)hdr->vendor_ramdisk_table_entry_num * sizeof(vendor_ramdisk_table_entry_v4) >
        (uint64_t)o + p + q + r) {
        return Errorf("Too many vendor ramdisk entries in table, overflow");
    }

    // Find entry with name |ramdisk_name|.
    auto old_table_start =
            reinterpret_cast<const vendor_ramdisk_table_entry_v4*>(vendor_boot.data() + o + p + q);
    auto find_res =
            find_unique_ramdisk(ramdisk_name, old_table_start, hdr->vendor_ramdisk_table_entry_num);
    if (!find_res.ok()) return find_res.error();
    const vendor_ramdisk_table_entry_v4* replace_entry = *find_res;
    uint32_t replace_idx = replace_entry - old_table_start;

    // Now reconstruct.
    DataUpdater updater(vendor_boot);

    // Copy header (O bytes), then update fields in header.
    if (auto res = updater.Copy(o); !res.ok()) return res.error();
    auto new_hdr = reinterpret_cast<vendor_boot_img_hdr_v4*>(updater.new_begin());

    // Copy ramdisk fragments, replace for the matching index.
    {
        auto old_ramdisk_entry = reinterpret_cast<const vendor_ramdisk_table_entry_v4*>(
                vendor_boot.data() + o + p + q);
        uint32_t new_total_ramdisk_size = 0;
        for (uint32_t new_ramdisk_idx = 0; new_ramdisk_idx < hdr->vendor_ramdisk_table_entry_num;
             new_ramdisk_idx++, old_ramdisk_entry++) {
            if (new_ramdisk_idx == replace_idx) {
                if (auto res = updater.Replace(replace_entry->ramdisk_size, new_ramdisk); !res.ok())
                    return res.error();
                new_total_ramdisk_size += new_ramdisk.size();
            } else {
                if (auto res = updater.Copy(old_ramdisk_entry->ramdisk_size); !res.ok())
                    return res.error();
                new_total_ramdisk_size += old_ramdisk_entry->ramdisk_size;
            }
        }
        new_hdr->vendor_ramdisk_size = new_total_ramdisk_size;
    }

    // Pad ramdisk to page boundary.
    const uint32_t new_p = round_up(new_hdr->vendor_ramdisk_size, new_hdr->page_size);
    if (auto res = updater.Skip(p - hdr->vendor_ramdisk_size, new_p - new_hdr->vendor_ramdisk_size);
        !res.ok())
        return res.error();
    if (auto res = updater.CheckOffset(o + p, o + new_p); !res.ok()) return res.error();

    // Copy DTB (Q bytes).
    if (auto res = updater.Copy(q); !res.ok()) return res.error();

    // Copy table, but with corresponding entries modified, including:
    // - ramdisk_size of the entry replaced
    // - ramdisk_offset of subsequent entries.
    for (uint32_t new_total_ramdisk_size = 0, new_entry_idx = 0;
         new_entry_idx < hdr->vendor_ramdisk_table_entry_num; new_entry_idx++) {
        auto new_entry = reinterpret_cast<vendor_ramdisk_table_entry_v4*>(updater.new_cur());
        if (auto res = updater.Copy(hdr->vendor_ramdisk_table_entry_size); !res.ok())
            return res.error();
        new_entry->ramdisk_offset = new_total_ramdisk_size;

        if (new_entry_idx == replace_idx) {
            new_entry->ramdisk_size = new_ramdisk.size();
        }
        new_total_ramdisk_size += new_entry->ramdisk_size;
    }

    // Copy padding of R pages; this is okay because table size is not changed.
    if (auto res = updater.Copy(r - hdr->vendor_ramdisk_table_entry_num *
                                            hdr->vendor_ramdisk_table_entry_size);
        !res.ok())
        return res.error();
    if (auto res = updater.CheckOffset(o + p + q + r, o + new_p + q + r); !res.ok())
        return res.error();

    // Copy bootconfig (S bytes).
    if (auto res = updater.Copy(s); !res.ok()) return res.error();

    if (auto res = copy_avb_footer(&updater); !res.ok()) return res.error();
    return updater.Finish();
}

}  // namespace

[[nodiscard]] Result<void> replace_vendor_ramdisk(android::base::borrowed_fd vendor_boot_fd,
                                                  uint64_t vendor_boot_size,
                                                  const std::string& ramdisk_name,
                                                  android::base::borrowed_fd new_ramdisk_fd,
                                                  uint64_t new_ramdisk_size) {
    if (new_ramdisk_size > std::numeric_limits<uint32_t>::max()) {
        return Errorf("New vendor ramdisk is too big");
    }

    auto vendor_boot = load_file(vendor_boot_fd, vendor_boot_size, "vendor boot");
    if (!vendor_boot.ok()) return vendor_boot.error();
    auto new_ramdisk = load_file(new_ramdisk_fd, new_ramdisk_size, "new vendor ramdisk");
    if (!new_ramdisk.ok()) return new_ramdisk.error();

    Result<std::string> new_vendor_boot;
    if (ramdisk_name == "default") {
        new_vendor_boot = replace_default_vendor_ramdisk(*vendor_boot, *new_ramdisk);
    } else {
        new_vendor_boot = replace_vendor_ramdisk_fragment(ramdisk_name, *vendor_boot, *new_ramdisk);
    }
    if (!new_vendor_boot.ok()) return new_vendor_boot.error();
    if (auto res = store_file(vendor_boot_fd, *new_vendor_boot, "new vendor boot image"); !res.ok())
        return res.error();

    return {};
}
