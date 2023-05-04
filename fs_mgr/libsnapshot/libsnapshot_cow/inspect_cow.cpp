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

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

static void usage(void) {
    std::cerr << "Usage: inspect_cow [-sd] <COW_FILE>\n";
    std::cerr << "\t -s Run Silent\n";
    std::cerr << "\t -d Attempt to decompress\n";
    std::cerr << "\t -b Show data for failed decompress\n";
    std::cerr << "\t -l Show ops\n";
    std::cerr << "\t -m Show ops in reverse merge order\n";
    std::cerr << "\t -n Show ops in merge order\n";
    std::cerr << "\t -a Include merged ops in any merge order listing\n";
    std::cerr << "\t -o Shows sequence op block order\n";
    std::cerr << "\t -v Verifies merge order has no conflicts\n";
}

enum OpIter { Normal, RevMerge, Merge };

struct Options {
    bool silent;
    bool decompress;
    bool show_ops;
    bool show_bad;
    bool show_seq;
    bool verify_sequence;
    OpIter iter_type;
    bool include_merged;
};

static void ShowBad(CowReader& reader, const struct CowOperation* op) {
    size_t count;
    auto buffer = std::make_unique<uint8_t[]>(op->data_length);

    if (!reader.GetRawBytes(op->source, buffer.get(), op->data_length, &count)) {
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

static bool Inspect(const std::string& path, Options opt) {
    android::base::unique_fd fd(open(path.c_str(), O_RDONLY));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << path;
        return false;
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

    if (!opt.silent) {
        std::cout << "Version: " << header.major_version << "." << header.minor_version << "\n";
        std::cout << "Header size: " << header.header_size << "\n";
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

    if (!opt.silent) {
        std::cout << "Parse time: " << (parse_time.count() * 1000) << "ms\n";
    }

    if (opt.verify_sequence) {
        std::cout << "\n";
        if (reader.VerifyMergeOps()) {
            std::cout << "\nMerge sequence is consistent.\n";
        } else {
            std::cout << "\nMerge sequence is inconsistent!\n";
        }
    }

    std::unique_ptr<ICowOpIter> iter;
    if (opt.iter_type == Normal) {
        iter = reader.GetOpIter();
    } else if (opt.iter_type == RevMerge) {
        iter = reader.GetRevMergeOpIter(opt.include_merged);
    } else if (opt.iter_type == Merge) {
        iter = reader.GetMergeOpIter(opt.include_merged);
    }

    std::string buffer(header.block_size, '\0');

    bool success = true;
    uint64_t xor_ops = 0, copy_ops = 0, replace_ops = 0, zero_ops = 0;
    while (!iter->AtEnd()) {
        const CowOperation* op = iter->Get();

        if (!opt.silent && opt.show_ops) std::cout << *op << "\n";

        if (opt.decompress && op->type == kCowReplaceOp && op->compression != kCowCompressNone) {
            if (reader.ReadData(op, buffer.data(), buffer.size()) < 0) {
                std::cerr << "Failed to decompress for :" << *op << "\n";
                success = false;
                if (opt.show_bad) ShowBad(reader, op);
            }
        }

        if (op->type == kCowSequenceOp && opt.show_seq) {
            size_t read;
            std::vector<uint32_t> merge_op_blocks;
            size_t seq_len = op->data_length / sizeof(uint32_t);
            merge_op_blocks.resize(seq_len);
            if (!reader.GetRawBytes(op->source, merge_op_blocks.data(), op->data_length, &read)) {
                PLOG(ERROR) << "Failed to read sequence op!";
                return false;
            }
            if (!opt.silent) {
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

    if (!opt.silent) {
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
    int ch;
    struct android::snapshot::Options opt;
    opt.silent = false;
    opt.decompress = false;
    opt.show_bad = false;
    opt.iter_type = android::snapshot::Normal;
    opt.verify_sequence = false;
    opt.include_merged = false;
    while ((ch = getopt(argc, argv, "sdbmnolva")) != -1) {
        switch (ch) {
            case 's':
                opt.silent = true;
                break;
            case 'd':
                opt.decompress = true;
                break;
            case 'b':
                opt.show_bad = true;
                break;
            case 'm':
                opt.iter_type = android::snapshot::RevMerge;
                break;
            case 'n':
                opt.iter_type = android::snapshot::Merge;
                break;
            case 'o':
                opt.show_seq = true;
                break;
            case 'l':
                opt.show_ops = true;
                break;
            case 'v':
                opt.verify_sequence = true;
                break;
            case 'a':
                opt.include_merged = true;
                break;
            default:
                android::snapshot::usage();
                return 1;
        }
    }

    if (argc < optind + 1) {
        android::snapshot::usage();
        return 1;
    }

    android::base::InitLogging(argv, android::snapshot::MyLogger);

    if (!android::snapshot::Inspect(argv[optind], opt)) {
        return 1;
    }
    return 0;
}
