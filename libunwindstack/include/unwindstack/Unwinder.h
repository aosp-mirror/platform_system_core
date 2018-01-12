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

#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

namespace unwindstack {

// Forward declarations.
class Elf;
class JitDebug;
enum ArchEnum : uint8_t;

struct FrameData {
  size_t num;

  uint64_t rel_pc;
  uint64_t pc;
  uint64_t sp;

  std::string function_name;
  uint64_t function_offset;

  std::string map_name;
  uint64_t map_offset;
  uint64_t map_start;
  uint64_t map_end;
  uint64_t map_load_bias;
  int map_flags;
};

class Unwinder {
 public:
  Unwinder(size_t max_frames, Maps* maps, Regs* regs, std::shared_ptr<Memory> process_memory)
      : max_frames_(max_frames), maps_(maps), regs_(regs), process_memory_(process_memory) {
    frames_.reserve(max_frames);
  }
  ~Unwinder() = default;

  void Unwind(const std::vector<std::string>* initial_map_names_to_skip = nullptr,
              const std::vector<std::string>* map_suffixes_to_ignore = nullptr);

  size_t NumFrames() { return frames_.size(); }

  const std::vector<FrameData>& frames() { return frames_; }

  std::string FormatFrame(size_t frame_num);
  static std::string FormatFrame(const FrameData& frame, bool is32bit);

  void SetJitDebug(JitDebug* jit_debug, ArchEnum arch);

 private:
  void FillInFrame(MapInfo* map_info, Elf* elf, uint64_t adjusted_rel_pc, uint64_t adjusted_pc);

  size_t max_frames_;
  Maps* maps_;
  Regs* regs_;
  std::vector<FrameData> frames_;
  std::shared_ptr<Memory> process_memory_;
  JitDebug* jit_debug_ = nullptr;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_UNWINDER_H
