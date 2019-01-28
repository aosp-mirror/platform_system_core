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

#ifndef _LIBUNWINDSTACK_UNWINDER_H
#define _LIBUNWINDSTACK_UNWINDER_H

#include <stdint.h>
#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

#include <unwindstack/DexFiles.h>
#include <unwindstack/Error.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

namespace unwindstack {

// Forward declarations.
class Elf;
enum ArchEnum : uint8_t;

struct FrameData {
  size_t num;

  uint64_t rel_pc;
  uint64_t pc;
  uint64_t sp;

  std::string function_name;
  uint64_t function_offset = 0;

  std::string map_name;
  // The offset from the first map representing the frame. When there are
  // two maps (read-only and read-execute) this will be the offset from
  // the read-only map. When there is only one map, this will be the
  // same as the actual offset of the map and match map_exact_offset.
  uint64_t map_elf_start_offset = 0;
  // The actual offset from the map where the pc lies.
  uint64_t map_exact_offset = 0;
  uint64_t map_start = 0;
  uint64_t map_end = 0;
  uint64_t map_load_bias = 0;
  int map_flags = 0;
};

class Unwinder {
 public:
  Unwinder(size_t max_frames, Maps* maps, Regs* regs, std::shared_ptr<Memory> process_memory)
      : max_frames_(max_frames), maps_(maps), regs_(regs), process_memory_(process_memory) {
    frames_.reserve(max_frames);
  }
  Unwinder(size_t max_frames, Maps* maps, std::shared_ptr<Memory> process_memory)
      : max_frames_(max_frames), maps_(maps), process_memory_(process_memory) {
    frames_.reserve(max_frames);
  }

  ~Unwinder() = default;

  void Unwind(const std::vector<std::string>* initial_map_names_to_skip = nullptr,
              const std::vector<std::string>* map_suffixes_to_ignore = nullptr);

  size_t NumFrames() { return frames_.size(); }

  const std::vector<FrameData>& frames() { return frames_; }

  std::vector<FrameData> ConsumeFrames() {
    std::vector<FrameData> frames = std::move(frames_);
    frames_.clear();
    return frames;
  }

  std::string FormatFrame(size_t frame_num);
  static std::string FormatFrame(const FrameData& frame, bool is32bit);

  void SetJitDebug(JitDebug* jit_debug, ArchEnum arch);

  void SetRegs(Regs* regs) { regs_ = regs; }
  Maps* GetMaps() { return maps_; }
  std::shared_ptr<Memory>& GetProcessMemory() { return process_memory_; }

  // Disabling the resolving of names results in the function name being
  // set to an empty string and the function offset being set to zero.
  void SetResolveNames(bool resolve) { resolve_names_ = resolve; }

#if !defined(NO_LIBDEXFILE_SUPPORT)
  void SetDexFiles(DexFiles* dex_files, ArchEnum arch);
#endif

  ErrorCode LastErrorCode() { return last_error_.code; }
  uint64_t LastErrorAddress() { return last_error_.address; }

 protected:
  Unwinder(size_t max_frames) : max_frames_(max_frames) { frames_.reserve(max_frames); }

  void FillInDexFrame();
  void FillInFrame(MapInfo* map_info, Elf* elf, uint64_t rel_pc, uint64_t func_pc,
                   uint64_t pc_adjustment);

  size_t max_frames_;
  Maps* maps_;
  Regs* regs_;
  std::vector<FrameData> frames_;
  std::shared_ptr<Memory> process_memory_;
  JitDebug* jit_debug_ = nullptr;
#if !defined(NO_LIBDEXFILE_SUPPORT)
  DexFiles* dex_files_ = nullptr;
#endif
  bool resolve_names_ = true;
  ErrorData last_error_;
};

class UnwinderFromPid : public Unwinder {
 public:
  UnwinderFromPid(size_t max_frames, pid_t pid) : Unwinder(max_frames), pid_(pid) {}
  ~UnwinderFromPid() = default;

  bool Init(ArchEnum arch);

 private:
  pid_t pid_;
  std::unique_ptr<Maps> maps_ptr_;
  std::unique_ptr<JitDebug> jit_debug_ptr_;
#if !defined(NO_LIBDEXFILE_SUPPORT)
  std::unique_ptr<DexFiles> dex_files_ptr_;
#endif
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_UNWINDER_H
