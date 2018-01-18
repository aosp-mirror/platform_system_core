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

#define _GNU_SOURCE 1
#include <elf.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>

#include <android-base/stringprintf.h>

#include <unwindstack/Elf.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Unwinder.h>

namespace unwindstack {

void Unwinder::FillInFrame(MapInfo* map_info, Elf* elf, uint64_t adjusted_rel_pc, uint64_t func_pc) {
  size_t frame_num = frames_.size();
  frames_.resize(frame_num + 1);
  FrameData* frame = &frames_.at(frame_num);
  frame->num = frame_num;
  frame->sp = regs_->sp();
  frame->rel_pc = adjusted_rel_pc;
  frame->dex_pc = regs_->dex_pc();

  if (map_info == nullptr) {
    frame->pc = regs_->pc();
    return;
  }

  frame->pc = map_info->start + adjusted_rel_pc;
  frame->map_name = map_info->name;
  frame->map_offset = map_info->offset;
  frame->map_start = map_info->start;
  frame->map_end = map_info->end;
  frame->map_flags = map_info->flags;
  frame->map_load_bias = elf->GetLoadBias();

  if (!elf->GetFunctionName(func_pc, &frame->function_name, &frame->function_offset)) {
    frame->function_name = "";
    frame->function_offset = 0;
  }
}

static bool ShouldStop(const std::vector<std::string>* map_suffixes_to_ignore,
                       std::string& map_name) {
  if (map_suffixes_to_ignore == nullptr) {
    return false;
  }
  auto pos = map_name.find_last_of('.');
  if (pos == std::string::npos) {
    return false;
  }

  return std::find(map_suffixes_to_ignore->begin(), map_suffixes_to_ignore->end(),
                   map_name.substr(pos + 1)) != map_suffixes_to_ignore->end();
}

void Unwinder::Unwind(const std::vector<std::string>* initial_map_names_to_skip,
                      const std::vector<std::string>* map_suffixes_to_ignore) {
  frames_.clear();

  bool return_address_attempt = false;
  bool adjust_pc = false;
  std::unique_ptr<JitDebug> jit_debug;
  for (; frames_.size() < max_frames_;) {
    uint64_t cur_pc = regs_->pc();
    uint64_t cur_sp = regs_->sp();

    MapInfo* map_info = maps_->Find(regs_->pc());
    uint64_t rel_pc;
    uint64_t adjusted_pc;
    uint64_t adjusted_rel_pc;
    Elf* elf;
    if (map_info == nullptr) {
      rel_pc = regs_->pc();
      adjusted_rel_pc = rel_pc;
      adjusted_pc = rel_pc;
    } else {
      if (ShouldStop(map_suffixes_to_ignore, map_info->name)) {
        break;
      }
      elf = map_info->GetElf(process_memory_, true);
      rel_pc = elf->GetRelPc(regs_->pc(), map_info);
      if (adjust_pc) {
        adjusted_pc = regs_->GetAdjustedPc(rel_pc, elf);
      } else {
        adjusted_pc = rel_pc;
      }
      adjusted_rel_pc = adjusted_pc;

      // If the pc is in an invalid elf file, try and get an Elf object
      // using the jit debug information.
      if (!elf->valid() && jit_debug_ != nullptr) {
        uint64_t adjusted_jit_pc = regs_->pc() - (rel_pc - adjusted_pc);
        Elf* jit_elf = jit_debug_->GetElf(maps_, adjusted_jit_pc);
        if (jit_elf != nullptr) {
          // The jit debug information requires a non relative adjusted pc.
          adjusted_pc = adjusted_jit_pc;
          adjusted_rel_pc = adjusted_pc - map_info->start;
          elf = jit_elf;
        }
      }
    }

    if (map_info == nullptr || initial_map_names_to_skip == nullptr ||
        std::find(initial_map_names_to_skip->begin(), initial_map_names_to_skip->end(),
                  basename(map_info->name.c_str())) == initial_map_names_to_skip->end()) {
      FillInFrame(map_info, elf, adjusted_rel_pc, adjusted_pc);

      // Once a frame is added, stop skipping frames.
      initial_map_names_to_skip = nullptr;
    }
    adjust_pc = true;

    bool stepped;
    bool in_device_map = false;
    if (map_info == nullptr) {
      stepped = false;
    } else {
      if (map_info->flags & MAPS_FLAGS_DEVICE_MAP) {
        // Do not stop here, fall through in case we are
        // in the speculative unwind path and need to remove
        // some of the speculative frames.
        stepped = false;
        in_device_map = true;
      } else {
        MapInfo* sp_info = maps_->Find(regs_->sp());
        if (sp_info != nullptr && sp_info->flags & MAPS_FLAGS_DEVICE_MAP) {
          // Do not stop here, fall through in case we are
          // in the speculative unwind path and need to remove
          // some of the speculative frames.
          stepped = false;
          in_device_map = true;
        } else {
          bool finished;
          stepped = elf->Step(rel_pc, adjusted_pc, map_info->elf_offset, regs_,
                              process_memory_.get(), &finished);
          if (stepped && finished) {
            break;
          }
        }
      }
    }

    if (!stepped) {
      if (return_address_attempt) {
        // Remove the speculative frame.
        frames_.pop_back();
        break;
      } else if (in_device_map) {
        // Do not attempt any other unwinding, pc or sp is in a device
        // map.
        break;
      } else {
        // Steping didn't work, try this secondary method.
        if (!regs_->SetPcFromReturnAddress(process_memory_.get())) {
          break;
        }
        return_address_attempt = true;
      }
    } else {
      return_address_attempt = false;
    }

    // If the pc and sp didn't change, then consider everything stopped.
    if (cur_pc == regs_->pc() && cur_sp == regs_->sp()) {
      break;
    }
  }
}

std::string Unwinder::FormatFrame(size_t frame_num) {
  if (frame_num >= frames_.size()) {
    return "";
  }
  return FormatFrame(frames_[frame_num], regs_->Is32Bit());
}

std::string Unwinder::FormatFrame(const FrameData& frame, bool is32bit) {
  std::string data;

  if (is32bit) {
    data += android::base::StringPrintf("  #%02zu pc %08" PRIx64, frame.num, frame.rel_pc);
  } else {
    data += android::base::StringPrintf("  #%02zu pc %016" PRIx64, frame.num, frame.rel_pc);
  }

  if (frame.map_offset != 0) {
    data += android::base::StringPrintf(" (offset 0x%" PRIx64 ")", frame.map_offset);
  }

  if (frame.map_start == frame.map_end) {
    // No valid map associated with this frame.
    data += "  <unknown>";
  } else if (!frame.map_name.empty()) {
    data += "  " + frame.map_name;
  } else {
    data += android::base::StringPrintf("  <anonymous:%" PRIx64 ">", frame.map_start);
  }
  if (!frame.function_name.empty()) {
    data += " (" + frame.function_name;
    if (frame.function_offset != 0) {
      data += android::base::StringPrintf("+%" PRId64, frame.function_offset);
    }
    data += ')';
  }
  return data;
}

void Unwinder::SetJitDebug(JitDebug* jit_debug, ArchEnum arch) {
  jit_debug->SetArch(arch);
  jit_debug_ = jit_debug;
}

}  // namespace unwindstack
