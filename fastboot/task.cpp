//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include "task.h"

#include "fastboot_driver.h"

#include <android-base/logging.h>
#include <android-base/parseint.h>

#include "fastboot.h"
#include "filesystem.h"
#include "super_flash_helper.h"
#include "util.h"

using namespace std::string_literals;
FlashTask::FlashTask(const std::string& slot, const std::string& pname, const std::string& fname,
                     const bool apply_vbmeta, const FlashingPlan* fp)
    : pname_(pname), fname_(fname), slot_(slot), apply_vbmeta_(apply_vbmeta), fp_(fp) {}

bool FlashTask::IsDynamicParitition(const ImageSource* source, const FlashTask* task) {
    std::vector<char> contents;
    if (!source->ReadFile("super_empty.img", &contents)) {
        return false;
    }
    auto metadata = android::fs_mgr::ReadFromImageBlob(contents.data(), contents.size());
    return should_flash_in_userspace(*metadata.get(), task->GetPartitionAndSlot());
}

void FlashTask::Run() {
    auto flash = [&](const std::string& partition) {
        if (should_flash_in_userspace(fp_->source.get(), partition) && !is_userspace_fastboot() &&
            !fp_->force_flash) {
            die("The partition you are trying to flash is dynamic, and "
                "should be flashed via fastbootd. Please run:\n"
                "\n"
                "    fastboot reboot fastboot\n"
                "\n"
                "And try again. If you are intentionally trying to "
                "overwrite a fixed partition, use --force.");
        }
        do_flash(partition.c_str(), fname_.c_str(), apply_vbmeta_, fp_);
    };
    do_for_partitions(pname_, slot_, flash, true);
}

std::string FlashTask::ToString() const {
    std::string apply_vbmeta_string = "";
    if (apply_vbmeta_) {
        apply_vbmeta_string = " --apply_vbmeta";
    }
    return "flash" + apply_vbmeta_string + " " + pname_ + " " + fname_;
}

std::string FlashTask::GetPartitionAndSlot() const {
    auto slot = slot_;
    if (slot.empty()) {
        slot = get_current_slot();
    }
    if (slot.empty()) {
        return pname_;
    }
    if (slot == "all") {
        LOG(FATAL) << "Cannot retrieve a singular name when using all slots";
    }
    return pname_ + "_" + slot;
}

RebootTask::RebootTask(const FlashingPlan* fp) : fp_(fp){};
RebootTask::RebootTask(const FlashingPlan* fp, const std::string& reboot_target)
    : reboot_target_(reboot_target), fp_(fp){};

void RebootTask::Run() {
    if (reboot_target_ == "fastboot") {
        if (!is_userspace_fastboot()) {
            reboot_to_userspace_fastboot();
            fp_->fb->WaitForDisconnect();
        }
    } else if (reboot_target_ == "recovery") {
        fp_->fb->RebootTo("recovery");
        fp_->fb->WaitForDisconnect();
    } else if (reboot_target_ == "bootloader") {
        fp_->fb->RebootTo("bootloader");
        fp_->fb->WaitForDisconnect();
    } else if (reboot_target_ == "") {
        fp_->fb->Reboot();
        fp_->fb->WaitForDisconnect();
    } else {
        syntax_error("unknown reboot target %s", reboot_target_.c_str());
    }
}

std::string RebootTask::ToString() const {
    return "reboot " + reboot_target_;
}

OptimizedFlashSuperTask::OptimizedFlashSuperTask(const std::string& super_name,
                                                 std::unique_ptr<SuperFlashHelper> helper,
                                                 SparsePtr sparse_layout, uint64_t super_size,
                                                 const FlashingPlan* fp)
    : super_name_(super_name),
      helper_(std::move(helper)),
      sparse_layout_(std::move(sparse_layout)),
      super_size_(super_size),
      fp_(fp) {}

void OptimizedFlashSuperTask::Run() {
    // Use the reported super partition size as the upper limit, rather than
    // sparse_file_len, which (1) can fail and (2) is kind of expensive, since
    // it will map in all of the embedded fds.
    std::vector<SparsePtr> files;
    if (int limit = get_sparse_limit(super_size_, fp_)) {
        files = resparse_file(sparse_layout_.get(), limit);
    } else {
        files.emplace_back(std::move(sparse_layout_));
    }

    // Send the data to the device.
    flash_partition_files(super_name_, files);
}

std::string OptimizedFlashSuperTask::ToString() const {
    return "optimized-flash-super";
}

// This looks for a block within tasks that has the following pattern [reboot fastboot,
// update-super, $LIST_OF_DYNAMIC_FLASH_TASKS] and returns true if this is found.Theoretically
// this check is just a pattern match and could break if fastboot-info has a bunch of junk commands
// but all devices should pretty much follow this pattern
bool OptimizedFlashSuperTask::CanOptimize(const ImageSource* source,
                                          const std::vector<std::unique_ptr<Task>>& tasks) {
    for (size_t i = 0; i < tasks.size(); i++) {
        auto reboot_task = tasks[i]->AsRebootTask();
        if (!reboot_task || reboot_task->GetTarget() != "fastboot") {
            continue;
        }
        // The check for i >= tasks.size() - 2 is because we are peeking two tasks ahead. We need to
        // check for an update-super && flash {dynamic_partition}
        if (i >= tasks.size() - 2 || !tasks[i + 1]->AsUpdateSuperTask()) {
            continue;
        }
        auto flash_task = tasks[i + 2]->AsFlashTask();
        if (!FlashTask::IsDynamicParitition(source, flash_task)) {
            continue;
        }
        return true;
    }
    return false;
}

std::unique_ptr<OptimizedFlashSuperTask> OptimizedFlashSuperTask::Initialize(
        const FlashingPlan* fp, std::vector<std::unique_ptr<Task>>& tasks) {
    if (!fp->should_optimize_flash_super) {
        LOG(INFO) << "super optimization is disabled";
        return nullptr;
    }
    if (!supports_AB(fp->fb)) {
        LOG(VERBOSE) << "Cannot optimize flashing super on non-AB device";
        return nullptr;
    }
    if (fp->slot_override == "all") {
        LOG(VERBOSE) << "Cannot optimize flashing super for all slots";
        return nullptr;
    }
    if (!CanOptimize(fp->source.get(), tasks)) {
        return nullptr;
    }

    // Does this device use dynamic partitions at all?
    unique_fd fd = fp->source->OpenFile("super_empty.img");

    if (fd < 0) {
        LOG(VERBOSE) << "could not open super_empty.img";
        return nullptr;
    }

    std::string super_name;
    // Try to find whether there is a super partition.
    if (fp->fb->GetVar("super-partition-name", &super_name) != fastboot::SUCCESS) {
        super_name = "super";
    }
    uint64_t partition_size;
    std::string partition_size_str;
    if (fp->fb->GetVar("partition-size:" + super_name, &partition_size_str) != fastboot::SUCCESS) {
        LOG(VERBOSE) << "Cannot optimize super flashing: could not determine super partition";
        return nullptr;
    }
    partition_size_str = fb_fix_numeric_var(partition_size_str);
    if (!android::base::ParseUint(partition_size_str, &partition_size)) {
        LOG(VERBOSE) << "Could not parse " << super_name << " size: " << partition_size_str;
        return nullptr;
    }

    std::unique_ptr<SuperFlashHelper> helper = std::make_unique<SuperFlashHelper>(*fp->source);
    if (!helper->Open(fd)) {
        return nullptr;
    }

    for (const auto& task : tasks) {
        if (auto flash_task = task->AsFlashTask()) {
            auto partition = flash_task->GetPartitionAndSlot();
            if (!helper->AddPartition(partition, flash_task->GetImageName(), false)) {
                return nullptr;
            }
        }
    }

    auto s = helper->GetSparseLayout();
    if (!s) return nullptr;

    // Remove tasks that are concatenated into this optimized task
    auto remove_if_callback = [&](const auto& task) -> bool {
        if (auto flash_task = task->AsFlashTask()) {
            return helper->WillFlash(flash_task->GetPartitionAndSlot());
        } else if (auto update_super_task = task->AsUpdateSuperTask()) {
            return true;
        } else if (auto reboot_task = task->AsRebootTask()) {
            if (reboot_task->GetTarget() == "fastboot") {
                return true;
            }
        }
        return false;
    };

    tasks.erase(std::remove_if(tasks.begin(), tasks.end(), remove_if_callback), tasks.end());

    return std::make_unique<OptimizedFlashSuperTask>(super_name, std::move(helper), std::move(s),
                                                     partition_size, fp);
}

UpdateSuperTask::UpdateSuperTask(const FlashingPlan* fp) : fp_(fp) {}

void UpdateSuperTask::Run() {
    unique_fd fd = fp_->source->OpenFile("super_empty.img");
    if (fd < 0) {
        return;
    }
    if (!is_userspace_fastboot()) {
        reboot_to_userspace_fastboot();
    }

    std::string super_name;
    if (fp_->fb->GetVar("super-partition-name", &super_name) != fastboot::RetCode::SUCCESS) {
        super_name = "super";
    }
    fp_->fb->Download(super_name, fd, get_file_size(fd));

    std::string command = "update-super:" + super_name;
    if (fp_->wants_wipe) {
        command += ":wipe";
    }
    fp_->fb->RawCommand(command, "Updating super partition");
}
std::string UpdateSuperTask::ToString() const {
    return "update-super";
}

ResizeTask::ResizeTask(const FlashingPlan* fp, const std::string& pname, const std::string& size,
                       const std::string& slot)
    : fp_(fp), pname_(pname), size_(size), slot_(slot) {}

void ResizeTask::Run() {
    auto resize_partition = [this](const std::string& partition) -> void {
        if (is_logical(partition)) {
            fp_->fb->ResizePartition(partition, size_);
        }
    };
    do_for_partitions(pname_, slot_, resize_partition, false);
}

std::string ResizeTask::ToString() const {
    return "resize " + pname_;
}

DeleteTask::DeleteTask(const FlashingPlan* fp, const std::string& pname) : fp_(fp), pname_(pname){};

void DeleteTask::Run() {
    fp_->fb->DeletePartition(pname_);
}

std::string DeleteTask::ToString() const {
    return "delete " + pname_;
}

WipeTask::WipeTask(const FlashingPlan* fp, const std::string& pname) : fp_(fp), pname_(pname){};

void WipeTask::Run() {
    std::string partition_type;
    if (fp_->fb->GetVar("partition-type:" + pname_, &partition_type) != fastboot::SUCCESS) {
        LOG(ERROR) << "wipe task partition not found: " << pname_;
        return;
    }
    if (partition_type.empty()) return;
    if (fp_->fb->Erase(pname_) != fastboot::SUCCESS) {
        LOG(ERROR) << "wipe task erase failed with partition: " << pname_;
        return;
    }
    fb_perform_format(pname_, 1, partition_type, "", fp_->fs_options, fp_);
}

std::string WipeTask::ToString() const {
    return "erase " + pname_;
}
