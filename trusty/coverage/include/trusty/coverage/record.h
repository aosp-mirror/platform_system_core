/*
 * Copyright (C) 2020 The Android Open Source Project
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

/* This file needs to be kept in-sync with its counterpart on Trusty side:
 * trusty/user/base/lib/coverage/common/include/lib/coverage/common/record.h */

#pragma once

#include <stdint.h>

/**
 * enum coverage_record_type - Coverage region header type
 * @COV_START: Magic header start marker
 * @COV_8BIT_COUNTERS: 8bit counter for each instrumentation point
 * @COV_INSTR_PCS: Pointer length offset of each instrumentation point from the
 *                 start of the binary
 * @COV_TOTAL_LENGTH: Total length of the entire coverage record, must be the
 *                    last header item.
 *
 * Describes the type of a region of the coverage record. See &struct
 * coverage_record_header.
 */
enum coverage_record_type {
    COV_START = 0x434f5652,
    COV_8BIT_COUNTERS = 1,
    COV_INSTR_PCS = 2,
    COV_TOTAL_LENGTH = 0,
};

/**
 * struct coverage_record_header - Header entry describing a region of the
 * coverage record.
 * @type: type of the region, must be one of @enum coverage_record_type
 * @offset: offset from the beginning of the header to the start of the region
 *
 * Coverage records start with a header which is a list of struct
 * coverage_record_header, beginning with an entry with type COV_START and
 * terminated with an entry with type COV_TOTAL_LENGTH. Each of these header
 * entries corresponds to a region of the record, with the offset indicating the
 * offset of the start of that region from the beginning of the record (i.e. the
 * beginning of the header). Each record type and offset is 32-bit field with
 * native endianness. The first header item must be COV_START with a 0 offset.
 * The COV_START entry should be initialized when the coverage header is
 * complete and ready for consumption by the client, because coverage record
 * initialization happens asynchronously. The final header item,
 * COV_TOTAL_LENGTH, which must always be present, indicates the total length of
 * the coverage record, including the header.
 *
 * Coverage regions should be contiguous, so the end of one region is the start
 * of the next, and the coverage header must be in the same order as the regions
 * in the record body. Thus we can compute the length of a region by subtracting
 * the region's offset from the offset of the next header item.
 */
struct coverage_record_header {
    uint32_t type;
    uint32_t offset;
};
