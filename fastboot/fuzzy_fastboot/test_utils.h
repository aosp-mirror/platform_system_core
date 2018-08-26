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

#include <sparse/sparse.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>
#include <fstream>
#include <random>
#include <string>
#include <unordered_map>
#include "fastboot_driver.h"

namespace fastboot {

char rand_legal();
char rand_illegal();
char rand_char();
// start and end are inclusive
int random_int(int start, int end);

// I don't want to have to manage memory for this guy
struct SparseWrapper {
    SparseWrapper(unsigned int block_size, int64_t len) {
        sparse = sparse_file_new(block_size, len);
    }

    SparseWrapper(struct sparse_file* sf) { sparse = sf; }

    ~SparseWrapper() {
        if (sparse) {
            sparse_file_destroy(sparse);
        }
    }

    const std::string Rep() {
        unsigned bs = sparse_file_block_size(sparse);
        unsigned len = sparse_file_len(sparse, true, false);
        return android::base::StringPrintf("[block_size=%u, len=%u]", bs, len);
    }

    struct sparse_file* operator*() {
        return sparse;
    }

    struct sparse_file* sparse;
};

std::string RandomString(size_t length, std::function<char(void)> provider);
// RVO will avoid copy
std::vector<char> RandomBuf(size_t length, std::function<char(void)> provider = rand_char);

std::vector<std::string> SplitBySpace(const std::string& s);

std::unordered_map<std::string, std::string> ParseArgs(int argc, char** argv, std::string* err_msg);

std::vector<std::string> GeneratePartitionNames(const std::string& base, int num_slots = 0);

int ConfigureSerial(const std::string& port);

int StartProgram(const std::string program, const std::vector<std::string> args, int* pipe);
int WaitProgram(const pid_t pid, const int pipe, std::string* error_msg);

}  // namespace fastboot
