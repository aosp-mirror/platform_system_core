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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <gflags/gflags.h>
#include <libsnapshot/cow_writer.h>
#include <openssl/sha.h>
#include <sparse/sparse.h>
#include <ziparchive/zip_archive.h>

DEFINE_string(source_tf, "", "Source target files (dir or zip file)");
DEFINE_string(ota_tf, "", "Target files of the build for an OTA");
DEFINE_string(compression, "gz", "Compression (options: none, gz, brotli)");

namespace android {
namespace snapshot {

using android::base::borrowed_fd;
using android::base::unique_fd;

static constexpr size_t kBlockSize = 4096;

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

class TargetFilesPackage final {
  public:
    explicit TargetFilesPackage(const std::string& path);

    bool Open();
    bool HasFile(const std::string& path);
    std::unordered_set<std::string> GetDynamicPartitionNames();
    unique_fd OpenFile(const std::string& path);
    unique_fd OpenImage(const std::string& path);

  private:
    std::string path_;
    unique_fd fd_;
    std::unique_ptr<ZipArchive, decltype(&CloseArchive)> zip_;
};

TargetFilesPackage::TargetFilesPackage(const std::string& path)
    : path_(path), zip_(nullptr, &CloseArchive) {}

bool TargetFilesPackage::Open() {
    fd_.reset(open(path_.c_str(), O_RDONLY));
    if (fd_ < 0) {
        PLOG(ERROR) << "open failed: " << path_;
        return false;
    }

    struct stat s;
    if (fstat(fd_.get(), &s) < 0) {
        PLOG(ERROR) << "fstat failed: " << path_;
        return false;
    }
    if (S_ISDIR(s.st_mode)) {
        return true;
    }

    // Otherwise, assume it's a zip file.
    ZipArchiveHandle handle;
    if (OpenArchiveFd(fd_.get(), path_.c_str(), &handle, false)) {
        LOG(ERROR) << "Could not open " << path_ << " as a zip archive.";
        return false;
    }
    zip_.reset(handle);
    return true;
}

bool TargetFilesPackage::HasFile(const std::string& path) {
    if (zip_) {
        ZipEntry64 entry;
        return !FindEntry(zip_.get(), path, &entry);
    }

    auto full_path = path_ + "/" + path;
    return access(full_path.c_str(), F_OK) == 0;
}

unique_fd TargetFilesPackage::OpenFile(const std::string& path) {
    if (!zip_) {
        auto full_path = path_ + "/" + path;
        unique_fd fd(open(full_path.c_str(), O_RDONLY));
        if (fd < 0) {
            PLOG(ERROR) << "open failed: " << full_path;
            return {};
        }
        return fd;
    }

    ZipEntry64 entry;
    if (FindEntry(zip_.get(), path, &entry)) {
        LOG(ERROR) << path << " not found in archive: " << path_;
        return {};
    }

    TemporaryFile temp;
    if (temp.fd < 0) {
        PLOG(ERROR) << "mkstemp failed";
        return {};
    }

    LOG(INFO) << "Extracting " << path << " from " << path_ << " ...";
    if (ExtractEntryToFile(zip_.get(), &entry, temp.fd)) {
        LOG(ERROR) << "could not extract " << path << " from " << path_;
        return {};
    }
    if (lseek(temp.fd, 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return {};
    }
    return unique_fd{temp.release()};
}

unique_fd TargetFilesPackage::OpenImage(const std::string& path) {
    auto fd = OpenFile(path);
    if (fd < 0) {
        return {};
    }

    LOG(INFO) << "Unsparsing " << path << " ...";
    std::unique_ptr<struct sparse_file, decltype(&sparse_file_destroy)> s(
            sparse_file_import(fd.get(), false, false), &sparse_file_destroy);
    if (!s) {
        return fd;
    }

    TemporaryFile temp;
    if (temp.fd < 0) {
        PLOG(ERROR) << "mkstemp failed";
        return {};
    }
    if (sparse_file_write(s.get(), temp.fd, false, false, false) < 0) {
        LOG(ERROR) << "sparse_file_write failed";
        return {};
    }
    if (lseek(temp.fd, 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return {};
    }

    fd.reset(temp.release());
    return fd;
}

std::unordered_set<std::string> TargetFilesPackage::GetDynamicPartitionNames() {
    auto fd = OpenFile("META/misc_info.txt");
    if (fd < 0) {
        return {};
    }

    std::string contents;
    if (!android::base::ReadFdToString(fd, &contents)) {
        PLOG(ERROR) << "read failed";
        return {};
    }

    std::unordered_set<std::string> set;

    auto lines = android::base::Split(contents, "\n");
    for (const auto& line : lines) {
        auto parts = android::base::Split(line, "=");
        if (parts.size() == 2 && parts[0] == "dynamic_partition_list") {
            auto partitions = android::base::Split(parts[1], " ");
            for (const auto& name : partitions) {
                if (!name.empty()) {
                    set.emplace(name);
                }
            }
            break;
        }
    }
    return set;
}

class NonAbEstimator final {
  public:
    NonAbEstimator(const std::string& ota_tf_path, const std::string& source_tf_path)
        : ota_tf_path_(ota_tf_path), source_tf_path_(source_tf_path) {}

    bool Run();

  private:
    bool OpenPackages();
    bool AnalyzePartition(const std::string& partition_name);
    std::unordered_map<std::string, uint64_t> GetBlockMap(borrowed_fd fd);

    std::string ota_tf_path_;
    std::string source_tf_path_;
    std::unique_ptr<TargetFilesPackage> ota_tf_;
    std::unique_ptr<TargetFilesPackage> source_tf_;
    uint64_t size_ = 0;
};

bool NonAbEstimator::Run() {
    if (!OpenPackages()) {
        return false;
    }

    auto partitions = ota_tf_->GetDynamicPartitionNames();
    if (partitions.empty()) {
        LOG(ERROR) << "No dynamic partitions found in META/misc_info.txt";
        return false;
    }
    for (const auto& partition : partitions) {
        if (!AnalyzePartition(partition)) {
            return false;
        }
    }

    int64_t size_in_mb = int64_t(double(size_) / 1024.0 / 1024.0);

    std::cout << "Estimated COW size: " << size_ << " (" << size_in_mb << "MiB)\n";
    return true;
}

bool NonAbEstimator::OpenPackages() {
    ota_tf_ = std::make_unique<TargetFilesPackage>(ota_tf_path_);
    if (!ota_tf_->Open()) {
        return false;
    }
    if (!source_tf_path_.empty()) {
        source_tf_ = std::make_unique<TargetFilesPackage>(source_tf_path_);
        if (!source_tf_->Open()) {
            return false;
        }
    }
    return true;
}

static std::string SHA256(const std::string& input) {
    std::string hash(32, '\0');
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, input.data(), input.size());
    SHA256_Final(reinterpret_cast<unsigned char*>(hash.data()), &c);
    return hash;
}

bool NonAbEstimator::AnalyzePartition(const std::string& partition_name) {
    auto path = "IMAGES/" + partition_name + ".img";
    auto fd = ota_tf_->OpenImage(path);
    if (fd < 0) {
        return false;
    }

    unique_fd source_fd;
    uint64_t source_size = 0;
    std::unordered_map<std::string, uint64_t> source_blocks;
    if (source_tf_) {
        auto dap = source_tf_->GetDynamicPartitionNames();

        source_fd = source_tf_->OpenImage(path);
        if (source_fd >= 0) {
            struct stat s;
            if (fstat(source_fd.get(), &s)) {
                PLOG(ERROR) << "fstat failed";
                return false;
            }
            source_size = s.st_size;

            std::cout << "Hashing blocks for " << partition_name << "...\n";
            source_blocks = GetBlockMap(source_fd);
            if (source_blocks.empty()) {
                LOG(ERROR) << "Could not build a block map for source partition: "
                           << partition_name;
                return false;
            }
        } else {
            if (dap.count(partition_name)) {
                return false;
            }
            LOG(ERROR) << "Warning: " << partition_name
                       << " has no incremental diff since it's not in the source image.";
        }
    }

    TemporaryFile cow;
    if (cow.fd < 0) {
        PLOG(ERROR) << "mkstemp failed";
        return false;
    }

    CowOptions options;
    options.block_size = kBlockSize;
    options.compression = FLAGS_compression;

    auto writer = std::make_unique<CowWriter>(options);
    if (!writer->Initialize(borrowed_fd{cow.fd})) {
        LOG(ERROR) << "Could not initialize COW writer";
        return false;
    }

    LOG(INFO) << "Analyzing " << partition_name << " ...";

    std::string zeroes(kBlockSize, '\0');
    std::string chunk(kBlockSize, '\0');
    std::string src_chunk(kBlockSize, '\0');
    uint64_t next_block_number = 0;
    while (true) {
        if (!android::base::ReadFully(fd, chunk.data(), chunk.size())) {
            if (errno) {
                PLOG(ERROR) << "read failed";
                return false;
            }
            break;
        }

        uint64_t block_number = next_block_number++;
        if (chunk == zeroes) {
            if (!writer->AddZeroBlocks(block_number, 1)) {
                LOG(ERROR) << "Could not add zero block";
                return false;
            }
            continue;
        }

        uint64_t source_offset = block_number * kBlockSize;
        if (source_fd >= 0 && source_offset <= source_size) {
            off64_t offset = block_number * kBlockSize;
            if (android::base::ReadFullyAtOffset(source_fd, src_chunk.data(), src_chunk.size(),
                                                 offset)) {
                if (chunk == src_chunk) {
                    continue;
                }
            } else if (errno) {
                PLOG(ERROR) << "pread failed";
                return false;
            }
        }

        auto hash = SHA256(chunk);
        if (auto iter = source_blocks.find(hash); iter != source_blocks.end()) {
            if (!writer->AddCopy(block_number, iter->second)) {
                return false;
            }
            continue;
        }

        if (!writer->AddRawBlocks(block_number, chunk.data(), chunk.size())) {
            return false;
        }
    }

    if (!writer->Flush()) {
        return false;
    }

    struct stat s;
    if (fstat(cow.fd, &s) < 0) {
        PLOG(ERROR) << "fstat failed";
        return false;
    }

    size_ += s.st_size;
    return true;
}

std::unordered_map<std::string, uint64_t> NonAbEstimator::GetBlockMap(borrowed_fd fd) {
    std::string chunk(kBlockSize, '\0');

    std::unordered_map<std::string, uint64_t> block_map;
    uint64_t block_number = 0;
    while (true) {
        if (!android::base::ReadFully(fd, chunk.data(), chunk.size())) {
            if (errno) {
                PLOG(ERROR) << "read failed";
                return {};
            }
            break;
        }
        auto hash = SHA256(chunk);
        block_map[hash] = block_number;
        block_number++;
    }
    return block_map;
}

}  // namespace snapshot
}  // namespace android

using namespace android::snapshot;

int main(int argc, char** argv) {
    android::base::InitLogging(argv, android::snapshot::MyLogger);
    gflags::SetUsageMessage("Estimate VAB disk usage from Non A/B builds");
    gflags::ParseCommandLineFlags(&argc, &argv, false);

    if (FLAGS_ota_tf.empty()) {
        std::cerr << "Must specify -ota_tf on the command-line." << std::endl;
        return 1;
    }

    NonAbEstimator estimator(FLAGS_ota_tf, FLAGS_source_tf);
    if (!estimator.Run()) {
        return 1;
    }
    return 0;
}
