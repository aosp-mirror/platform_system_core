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
#include <stdio.h>
#include <unistd.h>

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gflags/gflags.h>
#include <libsnapshot/cow_reader.h>
#include "parser_v2.h"

DEFINE_bool(silent, false, "Run silently");
DEFINE_bool(decompress, false, "Attempt to decompress data ops");
DEFINE_bool(show_bad_data, false, "If an op fails to decompress, show its daw data");
DEFINE_bool(show_ops, false, "Print all opcode information");
DEFINE_string(order, "", "If show_ops is true, change the order (either merge or reverse-merge)");
DEFINE_bool(show_merged, false,
            "If show_ops is true, and order is merge or reverse-merge, include merged ops");
DEFINE_bool(verify_merge_sequence, false, "Verify merge order sequencing");
DEFINE_bool(show_merge_sequence, false, "Show merge order sequence");
DEFINE_bool(show_raw_ops, false, "Show raw ops directly from the underlying parser");
DEFINE_string(extract_to, "", "Extract the COW contents to the given file");

namespace android {
namespace snapshot {

using android::base::borrowed_fd;
using android::base::unique_fd;

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

static void ShowBad(CowReader& reader, const CowOperation* op) {
    size_t count;
    auto buffer = std::make_unique<uint8_t[]>(op->data_length);

    if (!reader.GetRawBytes(op, buffer.get(), op->data_length, &count)) {
        std::cerr << "Failed to read at all!\n";
    } else {
        std::cout << "The Block data is:\n";
        for (int i = 0; i < op->data_length; i++) {
            std::cout << std::hex << (int)buffer[i];
        }
        std::cout << std::dec << "\n\n";
        if (op->data_length >= sizeof(CowOperation)) {
            std::cout << "The start, as an op, would be " << *(CowOperation*)buffer.get() << "\n";
        }
    }
}

static bool ShowRawOpStreamV2(borrowed_fd fd, const CowHeader& header) {
    CowParserV2 parser;
    if (!parser.Parse(fd, header)) {
        LOG(ERROR) << "v2 parser failed";
        return false;
    }
    for (const auto& op : *parser.ops()) {
        std::cout << op << "\n";
        if (auto iter = parser.data_loc()->find(op.new_block); iter != parser.data_loc()->end()) {
            std::cout << "    data loc: " << iter->second << "\n";
        }
    }
    return true;
}

static bool ShowRawOpStream(borrowed_fd fd) {
    CowHeader header;
    if (!ReadCowHeader(fd, &header)) {
        LOG(ERROR) << "parse header failed";
        return false;
    }

    switch (header.prefix.major_version) {
        case 1:
        case 2:
            return ShowRawOpStreamV2(fd, header);
        default:
            LOG(ERROR) << "unknown COW version: " << header.prefix.major_version;
            return false;
    }
}

static bool Inspect(const std::string& path) {
    unique_fd fd(open(path.c_str(), O_RDONLY));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << path;
        return false;
    }

    unique_fd extract_to;
    if (!FLAGS_extract_to.empty()) {
        extract_to.reset(open(FLAGS_extract_to.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0664));
        if (extract_to < 0) {
            PLOG(ERROR) << "could not open " << FLAGS_extract_to << " for writing";
            return false;
        }
    }

    CowReader reader;

    auto start_time = std::chrono::steady_clock::now();
    if (!reader.Parse(fd)) {
        LOG(ERROR) << "parse failed: " << path;
        return false;
    }
    std::chrono::duration<double> parse_time = std::chrono::steady_clock::now() - start_time;

    const CowHeader& header = reader.GetHeader();
    CowFooter footer;
    bool has_footer = false;
    if (reader.GetFooter(&footer)) has_footer = true;

    if (!FLAGS_silent) {
        std::cout << "Version: " << header.prefix.major_version << "."
                  << header.prefix.minor_version << "\n";
        std::cout << "Header size: " << header.prefix.header_size << "\n";
        std::cout << "Footer size: " << header.footer_size << "\n";
        std::cout << "Block size: " << header.block_size << "\n";
        std::cout << "Merge ops: " << header.num_merge_ops << "\n";
        std::cout << "Readahead buffer: " << header.buffer_size << " bytes\n";
        if (has_footer) {
            std::cout << "Footer: ops usage: " << footer.op.ops_size << " bytes\n";
            std::cout << "Footer: op count: " << footer.op.num_ops << "\n";
        } else {
            std::cout << "Footer: none\n";
        }
    }

    if (!FLAGS_silent) {
        std::cout << "Parse time: " << (parse_time.count() * 1000) << "ms\n";
    }

    if (FLAGS_verify_merge_sequence) {
        std::cout << "\n";
        if (reader.VerifyMergeOps()) {
            std::cout << "\nMerge sequence is consistent.\n";
        } else {
            std::cout << "\nMerge sequence is inconsistent!\n";
        }
    }

    std::unique_ptr<ICowOpIter> iter;
    if (FLAGS_order.empty()) {
        iter = reader.GetOpIter();
    } else if (FLAGS_order == "reverse-merge") {
        iter = reader.GetRevMergeOpIter(FLAGS_show_merged);
    } else if (FLAGS_order == "merge") {
        iter = reader.GetMergeOpIter(FLAGS_show_merged);
    }

    std::string buffer(header.block_size, '\0');

    if (!FLAGS_silent && FLAGS_show_raw_ops) {
        std::cout << "\n";
        std::cout << "Listing raw op stream:\n";
        std::cout << "----------------------\n";
        if (!ShowRawOpStream(fd)) {
            return false;
        }
    }

    if (!FLAGS_silent && FLAGS_show_ops) {
        std::cout << "\n";
        std::cout << "Listing op stream:\n";
        std::cout << "------------------\n";
    }

    bool success = true;
    uint64_t xor_ops = 0, copy_ops = 0, replace_ops = 0, zero_ops = 0;
    while (!iter->AtEnd()) {
        const CowOperation* op = iter->Get();

        if (!FLAGS_silent && FLAGS_show_ops) std::cout << *op << "\n";

        if ((FLAGS_decompress || extract_to >= 0) && op->type == kCowReplaceOp) {
            if (reader.ReadData(op, buffer.data(), buffer.size()) < 0) {
                std::cerr << "Failed to decompress for :" << *op << "\n";
                success = false;
                if (FLAGS_show_bad_data) ShowBad(reader, op);
            }
            if (extract_to >= 0) {
                off_t offset = uint64_t(op->new_block) * header.block_size;
                if (!android::base::WriteFullyAtOffset(extract_to, buffer.data(), buffer.size(),
                                                       offset)) {
                    PLOG(ERROR) << "failed to write block " << op->new_block;
                    return false;
                }
            }
        } else if (extract_to >= 0 && !IsMetadataOp(*op) && op->type != kCowZeroOp) {
            PLOG(ERROR) << "Cannot extract op yet: " << *op;
            return false;
        }

        if (op->type == kCowSequenceOp && FLAGS_show_merge_sequence) {
            size_t read;
            std::vector<uint32_t> merge_op_blocks;
            size_t seq_len = op->data_length / sizeof(uint32_t);
            merge_op_blocks.resize(seq_len);
            if (!reader.GetRawBytes(op, merge_op_blocks.data(), op->data_length, &read)) {
                PLOG(ERROR) << "Failed to read sequence op!";
                return false;
            }
            if (!FLAGS_silent) {
                std::cout << "Sequence for " << *op << " is :\n";
                for (size_t i = 0; i < seq_len; i++) {
                    std::cout << std::setfill('0') << std::setw(6) << merge_op_blocks[i] << ", ";
                    if ((i + 1) % 10 == 0 || i + 1 == seq_len) std::cout << "\n";
                }
            }
        }

        if (op->type == kCowCopyOp) {
            copy_ops++;
        } else if (op->type == kCowReplaceOp) {
            replace_ops++;
        } else if (op->type == kCowZeroOp) {
            zero_ops++;
        } else if (op->type == kCowXorOp) {
            xor_ops++;
        }

        iter->Next();
    }

    if (!FLAGS_silent) {
        auto total_ops = replace_ops + zero_ops + copy_ops + xor_ops;
        std::cout << "Data ops: " << total_ops << "\n";
        std::cout << "Replace ops: " << replace_ops << "\n";
        std::cout << "Zero ops: " << zero_ops << "\n";
        std::cout << "Copy ops: " << copy_ops << "\n";
        std::cout << "Xor ops: " << xor_ops << "\n";
    }

    return success;
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    if (argc < 2) {
        gflags::ShowUsageWithFlags(argv[0]);
        return 1;
    }
    if (FLAGS_order != "" && FLAGS_order != "merge" && FLAGS_order != "reverse-merge") {
        std::cerr << "Order must either be \"merge\" or \"reverse-merge\".\n";
        return 1;
    }

    android::base::InitLogging(argv, android::snapshot::MyLogger);

    if (!android::snapshot::Inspect(argv[1])) {
        return 1;
    }
    return 0;
}
