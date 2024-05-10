//
// Copyright (C) 2020 The Android Open Source Project
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
#pragma once

#include <string>

#include "super_flash_helper.h"
#include "util.h"

struct FlashingPlan;
struct Image;
using ImageEntry = std::pair<const Image*, std::string>;

class FlashTask;
class RebootTask;
class UpdateSuperTask;
class OptimizedFlashSuperTask;
class WipeTask;
class ResizeTask;
class Task {
  public:
    Task() = default;
    virtual void Run() = 0;
    virtual std::string ToString() const = 0;

    virtual FlashTask* AsFlashTask() { return nullptr; }
    virtual RebootTask* AsRebootTask() { return nullptr; }
    virtual UpdateSuperTask* AsUpdateSuperTask() { return nullptr; }
    virtual OptimizedFlashSuperTask* AsOptimizedFlashSuperTask() { return nullptr; }
    virtual WipeTask* AsWipeTask() { return nullptr; }
    virtual ResizeTask* AsResizeTask() { return nullptr; }

    virtual ~Task() = default;
};

class FlashTask : public Task {
  public:
    FlashTask(const std::string& slot, const std::string& pname, const std::string& fname,
              const bool apply_vbmeta, const FlashingPlan* fp);
    virtual FlashTask* AsFlashTask() override { return this; }

    static bool IsDynamicPartition(const ImageSource* source, const FlashTask* task);
    void Run() override;
    std::string ToString() const override;
    std::string GetPartition() const { return pname_; }
    std::string GetImageName() const { return fname_; }
    std::string GetSlot() const { return slot_; }
    std::string GetPartitionAndSlot() const;

  private:
    const std::string pname_;
    const std::string fname_;
    const std::string slot_;
    const bool apply_vbmeta_;
    const FlashingPlan* fp_;
};

class RebootTask : public Task {
  public:
    RebootTask(const FlashingPlan* fp);
    RebootTask(const FlashingPlan* fp, const std::string& reboot_target);
    virtual RebootTask* AsRebootTask() override { return this; }
    void Run() override;
    std::string ToString() const override;
    std::string GetTarget() const { return reboot_target_; };

  private:
    const std::string reboot_target_ = "";
    const FlashingPlan* fp_;
};

class OptimizedFlashSuperTask : public Task {
  public:
    OptimizedFlashSuperTask(const std::string& super_name, std::unique_ptr<SuperFlashHelper> helper,
                            SparsePtr sparse_layout, uint64_t super_size, const FlashingPlan* fp);
    virtual OptimizedFlashSuperTask* AsOptimizedFlashSuperTask() override { return this; }

    static std::unique_ptr<OptimizedFlashSuperTask> Initialize(
            const FlashingPlan* fp, std::vector<std::unique_ptr<Task>>& tasks);
    static bool CanOptimize(const ImageSource* source,
                            const std::vector<std::unique_ptr<Task>>& tasks);

    void Run() override;
    std::string ToString() const override;

  private:
    const std::string super_name_;
    std::unique_ptr<SuperFlashHelper> helper_;
    SparsePtr sparse_layout_;
    uint64_t super_size_;
    const FlashingPlan* fp_;
};

class UpdateSuperTask : public Task {
  public:
    UpdateSuperTask(const FlashingPlan* fp);
    virtual UpdateSuperTask* AsUpdateSuperTask() override { return this; }

    void Run() override;
    std::string ToString() const override;

  private:
    const FlashingPlan* fp_;
};

class ResizeTask : public Task {
  public:
    ResizeTask(const FlashingPlan* fp, const std::string& pname, const std::string& size,
               const std::string& slot);
    void Run() override;
    std::string ToString() const override;
    virtual ResizeTask* AsResizeTask() override { return this; }

  private:
    const FlashingPlan* fp_;
    const std::string pname_;
    const std::string size_;
    const std::string slot_;
};

class DeleteTask : public Task {
  public:
    DeleteTask(const FlashingPlan* fp, const std::string& pname);
    void Run() override;
    std::string ToString() const override;

  private:
    const FlashingPlan* fp_;
    const std::string pname_;
};

class WipeTask : public Task {
  public:
    WipeTask(const FlashingPlan* fp, const std::string& pname);
    virtual WipeTask* AsWipeTask() override { return this; }
    void Run() override;
    std::string ToString() const override;

  private:
    const FlashingPlan* fp_;
    const std::string pname_;
};
