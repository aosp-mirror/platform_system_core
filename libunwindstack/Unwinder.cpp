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

#include <android-base/stringprintf.h>

#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Unwinder.h>

namespace unwindstack {

void Unwinder::FillInFrame(MapInfo* map_info, Elf* elf, uint64_t rel_pc, bool adjust_pc) {
  size_t frame_num = frames_.size();
  frames_.resize(frame_num + 1);
  FrameData* frame = &frames_.at(frame_num);
  frame->num = frame_num;
  frame->pc = regs_->pc();
  frame->sp = regs_->sp();
  frame->rel_pc = rel_pc;

  if (map_info == nullptr) {
    return;
  }

  if (adjust_pc) {
    // Don't adjust the first frame pc.
    frame->rel_pc = regs_->GetAdjustedPc(rel_pc, elf);

    // Adjust the original pc.
    frame->pc -= rel_pc - frame->rel_pc;
  }

  frame->map_name = map_info->name;
  frame->map_offset = map_info->elf_offset;
  frame->map_start = map_info->start;
  frame->map_end = map_info->end;
  frame->map_flags = map_info->flags;
  frame->map_load_bias = elf->GetLoadBias();

  if (!elf->GetFunctionName(frame->rel_pc, &frame->function_name, &frame->function_offset)) {
    frame->function_name = "";
    frame->function_offset = 0;
  }
}

void Unwinder::Unwind(std::set<std::string>* initial_map_names_to_skip) {
  frames_.clear();

  bool return_address_attempt = false;
  bool adjust_pc = false;
  for (; frames_.size() < max_frames_;) {
    MapInfo* map_info = maps_->Find(regs_->pc());

    uint64_t rel_pc;
    Elf* elf;
    if (map_info == nullptr) {
      rel_pc = regs_->pc();
    } else {
      elf = map_info->GetElf(process_memory_, true);
      rel_pc = elf->GetRelPc(regs_->pc(), map_info);
    }

    if (map_info == nullptr || initial_map_names_to_skip == nullptr ||
        initial_map_names_to_skip->find(basename(map_info->name.c_str())) ==
            initial_map_names_to_skip->end()) {
      FillInFrame(map_info, elf, rel_pc, adjust_pc);
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
          stepped =
              elf->Step(rel_pc + map_info->elf_offset, regs_, process_memory_.get(), &finished);
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
  }
}

std::string Unwinder::FormatFrame(size_t frame_num) {
  if (frame_num >= frames_.size()) {
    return "";
  }
  return FormatFrame(frames_[frame_num],
                     regs_->MachineType() == EM_ARM || regs_->MachineType() == EM_386);
}

std::string Unwinder::FormatFrame(const FrameData& frame, bool bits32) {
  std::string data;

  if (bits32) {
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

}  // namespace unwindstack
