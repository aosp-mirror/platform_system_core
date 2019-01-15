/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <sys/types.h>
#include <unistd.h>

#include <meminfo/meminfo.h>
#include <meminfo/pageacct.h>
#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>

// Macros to do per-page flag manipulation
#define _BITS(x, offset, bits) (((x) >> (offset)) & ((1LL << (bits)) - 1))
#define PAGE_PRESENT(x) (_BITS(x, 63, 1))
#define PAGE_SWAPPED(x) (_BITS(x, 62, 1))
#define PAGE_SHIFT(x) (_BITS(x, 55, 6))
#define PAGE_PFN(x) (_BITS(x, 0, 55))
#define PAGE_SWAP_OFFSET(x) (_BITS(x, 5, 50))
#define PAGE_SWAP_TYPE(x) (_BITS(x, 0, 5))
