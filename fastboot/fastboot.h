/*
 * Copyright (C) 2018 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#pragma once

#include <functional>
#include <string>
#include "fastboot_driver_interface.h"
#include "filesystem.h"
#include "task.h"
#include "util.h"

#include <bootimg.h>

#include "result.h"
#include "socket.h"
#include "util.h"
#include "ziparchive/zip_archive.h"

class FastBootTool {
  public:
    int Main(int argc, char* argv[]);

    void ParseOsPatchLevel(boot_img_hdr_v1*, const char*);
    void ParseOsVersion(boot_img_hdr_v1*, const char*);
    unsigned ParseFsOption(const char*);
};

enum fb_buffer_type {
    FB_BUFFER_FD,
    FB_BUFFER_SPARSE,
};

struct fastboot_buffer {
    enum fb_buffer_type type;
    std::vector<SparsePtr> files;
    int64_t sz;
    unique_fd fd;
    int64_t image_size;
};

enum class ImageType {
    // Must be flashed for device to boot into the kernel.
    BootCritical,
    // Normal partition to be flashed during "flashall".
    Normal,
    // Partition that is never flashed during "flashall".
    Extra
};

struct Image {
    std::string nickname;
    std::string img_name;
    std::string sig_name;
    std::string part_name;
    bool optional_if_no_image;
    ImageType type;
    bool IsSecondary() const { return nickname.empty(); }
};

using ImageEntry = std::pair<const Image*, std::string>;

struct FlashingPlan {
    unsigned fs_options = 0;
    // If the image uses the default slot, or the user specified "all", then
    // the paired string will be empty. If the image requests a specific slot
    // (for example, system_other) it is specified instead.
    ImageSource* source;
    bool wants_wipe = false;
    bool skip_reboot = false;
    bool wants_set_active = false;
    bool skip_secondary = false;
    bool force_flash = false;
    bool should_optimize_flash_super = true;
    bool should_use_fastboot_info = true;
    bool exclude_dynamic_partitions = false;
    uint64_t sparse_limit = 0;

    std::string slot_override;
    std::string current_slot;
    std::string secondary_slot;

    fastboot::IFastBootDriver* fb;
};

class FlashAllTool {
  public:
    FlashAllTool(FlashingPlan* fp);

    void Flash();
    std::vector<std::unique_ptr<Task>> CollectTasks();

  private:
    void CheckRequirements();
    void DetermineSlot();
    void CollectImages();
    void AddFlashTasks(const std::vector<std::pair<const Image*, std::string>>& images,
                       std::vector<std::unique_ptr<Task>>& tasks);

    std::vector<std::unique_ptr<Task>> CollectTasksFromFastbootInfo();
    std::vector<std::unique_ptr<Task>> CollectTasksFromImageList();

    std::vector<ImageEntry> boot_images_;
    std::vector<ImageEntry> os_images_;
    std::vector<std::unique_ptr<Task>> tasks_;

    FlashingPlan* fp_;
};

class ZipImageSource final : public ImageSource {
  public:
    explicit ZipImageSource(ZipArchiveHandle zip) : zip_(zip) {}
    bool ReadFile(const std::string& name, std::vector<char>* out) const override;
    unique_fd OpenFile(const std::string& name) const override;

  private:
    ZipArchiveHandle zip_;
};

class LocalImageSource final : public ImageSource {
  public:
    bool ReadFile(const std::string& name, std::vector<char>* out) const override;
    unique_fd OpenFile(const std::string& name) const override;
};

char* get_android_product_out();
bool should_flash_in_userspace(const std::string& partition_name);
bool is_userspace_fastboot();
void do_flash(const char* pname, const char* fname, const bool apply_vbmeta,
              const FlashingPlan* fp);
void do_for_partitions(const std::string& part, const std::string& slot,
                       const std::function<void(const std::string&)>& func, bool force_slot);
std::string find_item(const std::string& item);
void reboot_to_userspace_fastboot();
void syntax_error(const char* fmt, ...);
std::string get_current_slot();

// Code for Parsing fastboot-info.txt
bool CheckFastbootInfoRequirements(const std::vector<std::string>& command,
                                   uint32_t host_tool_version);
std::unique_ptr<FlashTask> ParseFlashCommand(const FlashingPlan* fp,
                                             const std::vector<std::string>& parts);
std::unique_ptr<RebootTask> ParseRebootCommand(const FlashingPlan* fp,
                                               const std::vector<std::string>& parts);
std::unique_ptr<WipeTask> ParseWipeCommand(const FlashingPlan* fp,
                                           const std::vector<std::string>& parts);
std::unique_ptr<Task> ParseFastbootInfoLine(const FlashingPlan* fp,
                                            const std::vector<std::string>& command);
bool AddResizeTasks(const FlashingPlan* fp, std::vector<std::unique_ptr<Task>>& tasks);
std::vector<std::unique_ptr<Task>> ParseFastbootInfo(const FlashingPlan* fp,
                                                     const std::vector<std::string>& file);

struct NetworkSerial {
    Socket::Protocol protocol;
    std::string address;
    int port;
};

Result<NetworkSerial, FastbootError> ParseNetworkSerial(const std::string& serial);
std::string GetPartitionName(const ImageEntry& entry, const std::string& current_slot_);
void flash_partition_files(const std::string& partition, const std::vector<SparsePtr>& files);
int64_t get_sparse_limit(int64_t size, const FlashingPlan* fp);
std::vector<SparsePtr> resparse_file(sparse_file* s, int64_t max_size);

bool supports_AB(fastboot::IFastBootDriver* fb);
bool is_retrofit_device(const ImageSource* source);
bool is_logical(const std::string& partition);
void fb_perform_format(const std::string& partition, int skip_if_not_supported,
                       const std::string& type_override, const std::string& size_override,
                       const unsigned fs_options, const FlashingPlan* fp);
