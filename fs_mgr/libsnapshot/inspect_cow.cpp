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

#include <iostream>
#include <string>

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
    LOG(ERROR) << "Usage: inspect_cow [-sd] <COW_FILE>";
    LOG(ERROR) << "\t -s Run Silent";
    LOG(ERROR) << "\t -d Attempt to decompress";
    LOG(ERROR) << "\t -b Show data for failed decompress\n";
}

// Sink that always appends to the end of a string.
class StringSink : public IByteSink {
  public:
    void* GetBuffer(size_t requested, size_t* actual) override {
        size_t old_size = stream_.size();
        stream_.resize(old_size + requested, '\0');
        *actual = requested;
        return stream_.data() + old_size;
    }
    bool ReturnData(void*, size_t) override { return true; }
    void Reset() { stream_.clear(); }

    std::string& stream() { return stream_; }

  private:
    std::string stream_;
};

static void ShowBad(CowReader& reader, const struct CowOperation& op) {
    size_t count;
    auto buffer = std::make_unique<uint8_t[]>(op.data_length);

    if (!reader.GetRawBytes(op.source, buffer.get(), op.data_length, &count)) {
        std::cerr << "Failed to read at all!\n";
    } else {
        std::cout << "The Block data is:\n";
        for (int i = 0; i < op.data_length; i++) {
            std::cout << std::hex << (int)buffer[i];
        }
        std::cout << std::dec << "\n\n";
        if (op.data_length >= sizeof(CowOperation)) {
            std::cout << "The start, as an op, would be " << *(CowOperation*)buffer.get() << "\n";
        }
    }
}

static bool Inspect(const std::string& path, bool silent, bool decompress, bool show_bad) {
    android::base::unique_fd fd(open(path.c_str(), O_RDONLY));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << path;
        return false;
    }

    CowReader reader;
    if (!reader.Parse(fd)) {
        LOG(ERROR) << "parse failed: " << path;
        return false;
    }

    CowHeader header;
    if (!reader.GetHeader(&header)) {
        LOG(ERROR) << "could not get header: " << path;
        return false;
    }
    CowFooter footer;
    bool has_footer = false;
    if (reader.GetFooter(&footer)) has_footer = true;

    if (!silent) {
        std::cout << "Major version: " << header.major_version << "\n";
        std::cout << "Minor version: " << header.minor_version << "\n";
        std::cout << "Header size: " << header.header_size << "\n";
        std::cout << "Footer size: " << header.footer_size << "\n";
        std::cout << "Block size: " << header.block_size << "\n";
        std::cout << "\n";
        if (has_footer) {
            std::cout << "Total Ops size: " << footer.op.ops_size << "\n";
            std::cout << "Number of Ops: " << footer.op.num_ops << "\n";
            std::cout << "\n";
        }
    }

    auto iter = reader.GetOpIter();
    StringSink sink;
    bool success = true;
    while (!iter->Done()) {
        const CowOperation& op = iter->Get();

        if (!silent) std::cout << op << "\n";

        if (decompress && op.type == kCowReplaceOp && op.compression != kCowCompressNone) {
            if (!reader.ReadData(op, &sink)) {
                std::cerr << "Failed to decompress for :" << op << "\n";
                success = false;
                if (show_bad) ShowBad(reader, op);
            }
            sink.Reset();
        }

        iter->Next();
    }

    return success;
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    int ch;
    bool silent = false;
    bool decompress = false;
    bool show_bad = false;
    while ((ch = getopt(argc, argv, "sdb")) != -1) {
        switch (ch) {
            case 's':
                silent = true;
                break;
            case 'd':
                decompress = true;
                break;
            case 'b':
                show_bad = true;
                break;
            default:
                android::snapshot::usage();
        }
    }
    android::base::InitLogging(argv, android::snapshot::MyLogger);

    if (argc < optind + 1) {
        android::snapshot::usage();
        return 1;
    }

    if (!android::snapshot::Inspect(argv[optind], silent, decompress, show_bad)) {
        return 1;
    }
    return 0;
}
