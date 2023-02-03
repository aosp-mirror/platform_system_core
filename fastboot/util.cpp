/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "util.h"

using android::base::borrowed_fd;

static bool g_verbose = false;

double now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

void die(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "fastboot: error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(EXIT_FAILURE);
}

void die(const std::string& str) {
    die("%s", str.c_str());
}

void set_verbose() {
    g_verbose = true;
}

void verbose(const char* fmt, ...) {
    if (!g_verbose) return;

    if (*fmt != '\n') {
        va_list ap;
        va_start(ap, fmt);
        fprintf(stderr, "fastboot: verbose: ");
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
    fprintf(stderr, "\n");
}

bool should_flash_in_userspace(const android::fs_mgr::LpMetadata& metadata,
                               const std::string& partition_name) {
    for (const auto& partition : metadata.partitions) {
        auto candidate = android::fs_mgr::GetPartitionName(partition);
        if (partition.attributes & LP_PARTITION_ATTR_SLOT_SUFFIXED) {
            // On retrofit devices, we don't know if, or whether, the A or B
            // slot has been flashed for dynamic partitions. Instead we add
            // both names to the list as a conservative guess.
            if (candidate + "_a" == partition_name || candidate + "_b" == partition_name) {
                return true;
            }
        } else if (candidate == partition_name) {
            return true;
        }
    }
    return false;
}

bool is_sparse_file(borrowed_fd fd) {
    SparsePtr s(sparse_file_import(fd.get(), false, false), sparse_file_destroy);
    return !!s;
}

int64_t get_file_size(borrowed_fd fd) {
    struct stat sb;
    if (fstat(fd.get(), &sb) == -1) {
        die("could not get file size");
    }
    return sb.st_size;
}
