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

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <limits>
#include <string>
#include <unordered_set>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <bsdiff/bspatch.h>
#include <bzlib.h>
#include <gflags/gflags.h>
#include <libsnapshot/cow_writer.h>
#include <puffin/puffpatch.h>
#include <sparse/sparse.h>
#include <update_engine/update_metadata.pb.h>
#include <xz.h>
#include <ziparchive/zip_archive.h>

namespace android {
namespace snapshot {

using android::base::borrowed_fd;
using android::base::unique_fd;
using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::Extent;
using chromeos_update_engine::InstallOperation;
using chromeos_update_engine::PartitionUpdate;

static constexpr uint64_t kBlockSize = 4096;

DEFINE_string(source_tf, "", "Source target files (dir or zip file) for incremental payloads");
DEFINE_string(compression, "gz", "Compression type to use (none or gz)");
DEFINE_uint32(cluster_ops, 0, "Number of Cow Ops per cluster (0 or >1)");

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

uint64_t ToLittleEndian(uint64_t value) {
    union {
        uint64_t u64;
        char bytes[8];
    } packed;
    packed.u64 = value;
    std::swap(packed.bytes[0], packed.bytes[7]);
    std::swap(packed.bytes[1], packed.bytes[6]);
    std::swap(packed.bytes[2], packed.bytes[5]);
    std::swap(packed.bytes[3], packed.bytes[4]);
    return packed.u64;
}

class PayloadConverter final {
  public:
    PayloadConverter(const std::string& in_file, const std::string& out_dir)
        : in_file_(in_file), out_dir_(out_dir), source_tf_zip_(nullptr, &CloseArchive) {}

    bool Run();

  private:
    bool OpenPayload();
    bool OpenSourceTargetFiles();
    bool ProcessPartition(const PartitionUpdate& update);
    bool ProcessOperation(const InstallOperation& op);
    bool ProcessZero(const InstallOperation& op);
    bool ProcessCopy(const InstallOperation& op);
    bool ProcessReplace(const InstallOperation& op);
    bool ProcessDiff(const InstallOperation& op);
    borrowed_fd OpenSourceImage();

    std::string in_file_;
    std::string out_dir_;
    unique_fd in_fd_;
    uint64_t payload_offset_ = 0;
    DeltaArchiveManifest manifest_;
    std::unordered_set<std::string> dap_;
    unique_fd source_tf_fd_;
    std::unique_ptr<ZipArchive, decltype(&CloseArchive)> source_tf_zip_;

    // Updated during ProcessPartition().
    std::string partition_name_;
    std::unique_ptr<CowWriter> writer_;
    unique_fd source_image_;
};

bool PayloadConverter::Run() {
    if (!OpenPayload()) {
        return false;
    }

    if (manifest_.has_dynamic_partition_metadata()) {
        const auto& dpm = manifest_.dynamic_partition_metadata();
        for (const auto& group : dpm.groups()) {
            for (const auto& partition : group.partition_names()) {
                dap_.emplace(partition);
            }
        }
    }

    if (dap_.empty()) {
        LOG(ERROR) << "No dynamic partitions found.";
        return false;
    }

    if (!OpenSourceTargetFiles()) {
        return false;
    }

    for (const auto& update : manifest_.partitions()) {
        if (!ProcessPartition(update)) {
            return false;
        }
        writer_ = nullptr;
        source_image_.reset();
    }
    return true;
}

bool PayloadConverter::OpenSourceTargetFiles() {
    if (FLAGS_source_tf.empty()) {
        return true;
    }

    source_tf_fd_.reset(open(FLAGS_source_tf.c_str(), O_RDONLY));
    if (source_tf_fd_ < 0) {
        LOG(ERROR) << "open failed: " << FLAGS_source_tf;
        return false;
    }

    struct stat s;
    if (fstat(source_tf_fd_.get(), &s) < 0) {
        LOG(ERROR) << "fstat failed: " << FLAGS_source_tf;
        return false;
    }
    if (S_ISDIR(s.st_mode)) {
        return true;
    }

    // Otherwise, assume it's a zip file.
    ZipArchiveHandle handle;
    if (OpenArchiveFd(source_tf_fd_.get(), FLAGS_source_tf.c_str(), &handle, false)) {
        LOG(ERROR) << "Could not open " << FLAGS_source_tf << " as a zip archive.";
        return false;
    }
    source_tf_zip_.reset(handle);
    return true;
}

bool PayloadConverter::ProcessPartition(const PartitionUpdate& update) {
    auto partition_name = update.partition_name();
    if (dap_.find(partition_name) == dap_.end()) {
        // Skip non-DAP partitions.
        return true;
    }

    auto path = out_dir_ + "/" + partition_name + ".cow";
    unique_fd fd(open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
    if (fd < 0) {
        PLOG(ERROR) << "open failed: " << path;
        return false;
    }

    CowOptions options;
    options.block_size = kBlockSize;
    options.compression = FLAGS_compression;
    options.cluster_ops = FLAGS_cluster_ops;

    writer_ = std::make_unique<CowWriter>(options);
    if (!writer_->Initialize(std::move(fd))) {
        LOG(ERROR) << "Unable to initialize COW writer";
        return false;
    }

    partition_name_ = partition_name;

    for (const auto& op : update.operations()) {
        if (!ProcessOperation(op)) {
            return false;
        }
    }

    if (!writer_->Finalize()) {
        LOG(ERROR) << "Unable to finalize COW for " << partition_name;
        return false;
    }
    return true;
}

bool PayloadConverter::ProcessOperation(const InstallOperation& op) {
    switch (op.type()) {
        case InstallOperation::SOURCE_COPY:
            return ProcessCopy(op);
        case InstallOperation::BROTLI_BSDIFF:
        case InstallOperation::PUFFDIFF:
            return ProcessDiff(op);
        case InstallOperation::REPLACE:
        case InstallOperation::REPLACE_XZ:
        case InstallOperation::REPLACE_BZ:
            return ProcessReplace(op);
        case InstallOperation::ZERO:
            return ProcessZero(op);
        default:
            LOG(ERROR) << "Unsupported op: " << (int)op.type();
            return false;
    }
    return true;
}

bool PayloadConverter::ProcessZero(const InstallOperation& op) {
    for (const auto& extent : op.dst_extents()) {
        if (!writer_->AddZeroBlocks(extent.start_block(), extent.num_blocks())) {
            LOG(ERROR) << "Could not add zero operation";
            return false;
        }
    }
    return true;
}

template <typename T>
static uint64_t SizeOfAllExtents(const T& extents) {
    uint64_t total = 0;
    for (const auto& extent : extents) {
        total += extent.num_blocks() * kBlockSize;
    }
    return total;
}

class PuffInputStream final : public puffin::StreamInterface {
  public:
    PuffInputStream(uint8_t* buffer, size_t length) : buffer_(buffer), length_(length), pos_(0) {}

    bool GetSize(uint64_t* size) const override {
        *size = length_;
        return true;
    }
    bool GetOffset(uint64_t* offset) const override {
        *offset = pos_;
        return true;
    }
    bool Seek(uint64_t offset) override {
        if (offset > length_) return false;
        pos_ = offset;
        return true;
    }
    bool Read(void* buffer, size_t length) override {
        if (length_ - pos_ < length) return false;
        memcpy(buffer, buffer_ + pos_, length);
        pos_ += length;
        return true;
    }
    bool Write(const void*, size_t) override { return false; }
    bool Close() override { return true; }

  private:
    uint8_t* buffer_;
    size_t length_;
    size_t pos_;
};

class PuffOutputStream final : public puffin::StreamInterface {
  public:
    PuffOutputStream(std::vector<uint8_t>& stream) : stream_(stream), pos_(0) {}

    bool GetSize(uint64_t* size) const override {
        *size = stream_.size();
        return true;
    }
    bool GetOffset(uint64_t* offset) const override {
        *offset = pos_;
        return true;
    }
    bool Seek(uint64_t offset) override {
        if (offset > stream_.size()) {
            return false;
        }
        pos_ = offset;
        return true;
    }
    bool Read(void* buffer, size_t length) override {
        if (stream_.size() - pos_ < length) {
            return false;
        }
        memcpy(buffer, &stream_[0] + pos_, length);
        pos_ += length;
        return true;
    }
    bool Write(const void* buffer, size_t length) override {
        auto remaining = stream_.size() - pos_;
        if (remaining < length) {
            stream_.resize(stream_.size() + (length - remaining));
        }
        memcpy(&stream_[0] + pos_, buffer, length);
        pos_ += length;
        return true;
    }
    bool Close() override { return true; }

  private:
    std::vector<uint8_t>& stream_;
    size_t pos_;
};

bool PayloadConverter::ProcessDiff(const InstallOperation& op) {
    auto source_image = OpenSourceImage();
    if (source_image < 0) {
        return false;
    }

    uint64_t src_length = SizeOfAllExtents(op.src_extents());
    auto src = std::make_unique<uint8_t[]>(src_length);
    size_t src_pos = 0;

    // Read source bytes.
    for (const auto& extent : op.src_extents()) {
        uint64_t offset = extent.start_block() * kBlockSize;
        if (lseek(source_image.get(), offset, SEEK_SET) < 0) {
            PLOG(ERROR) << "lseek source image failed";
            return false;
        }

        uint64_t size = extent.num_blocks() * kBlockSize;
        CHECK(src_length - src_pos >= size);
        if (!android::base::ReadFully(source_image, src.get() + src_pos, size)) {
            PLOG(ERROR) << "read source image failed";
            return false;
        }
        src_pos += size;
    }
    CHECK(src_pos == src_length);

    // Read patch bytes.
    auto patch = std::make_unique<uint8_t[]>(op.data_length());
    if (lseek(in_fd_.get(), payload_offset_ + op.data_offset(), SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek payload failed";
        return false;
    }
    if (!android::base::ReadFully(in_fd_, patch.get(), op.data_length())) {
        PLOG(ERROR) << "read payload failed";
        return false;
    }

    std::vector<uint8_t> dest(SizeOfAllExtents(op.dst_extents()));

    // Apply the diff.
    if (op.type() == InstallOperation::BROTLI_BSDIFF) {
        size_t dest_pos = 0;
        auto sink = [&](const uint8_t* data, size_t length) -> size_t {
            CHECK(dest.size() - dest_pos >= length);
            memcpy(&dest[dest_pos], data, length);
            dest_pos += length;
            return length;
        };
        if (int rv = bsdiff::bspatch(src.get(), src_pos, patch.get(), op.data_length(), sink)) {
            LOG(ERROR) << "bspatch failed, error code " << rv;
            return false;
        }
    } else if (op.type() == InstallOperation::PUFFDIFF) {
        auto src_stream = std::make_unique<PuffInputStream>(src.get(), src_length);
        auto dest_stream = std::make_unique<PuffOutputStream>(dest);
        bool ok = PuffPatch(std::move(src_stream), std::move(dest_stream), patch.get(),
                            op.data_length());
        if (!ok) {
            LOG(ERROR) << "puffdiff operation failed to apply";
            return false;
        }
    } else {
        LOG(ERROR) << "unsupported diff operation: " << op.type();
        return false;
    }

    // Write the final blocks to the COW.
    size_t dest_pos = 0;
    for (const auto& extent : op.dst_extents()) {
        uint64_t size = extent.num_blocks() * kBlockSize;
        CHECK(dest.size() - dest_pos >= size);

        if (!writer_->AddRawBlocks(extent.start_block(), &dest[dest_pos], size)) {
            return false;
        }
        dest_pos += size;
    }
    return true;
}

borrowed_fd PayloadConverter::OpenSourceImage() {
    if (source_image_ >= 0) {
        return source_image_;
    }

    unique_fd unzip_fd;

    auto local_path = "IMAGES/" + partition_name_ + ".img";
    if (source_tf_zip_) {
        {
            TemporaryFile tmp;
            if (tmp.fd < 0) {
                PLOG(ERROR) << "mkstemp failed";
                return -1;
            }
            unzip_fd.reset(tmp.release());
        }

        ZipEntry64 entry;
        if (FindEntry(source_tf_zip_.get(), local_path, &entry)) {
            LOG(ERROR) << "not found in archive: " << local_path;
            return -1;
        }
        if (ExtractEntryToFile(source_tf_zip_.get(), &entry, unzip_fd.get())) {
            LOG(ERROR) << "could not extract " << local_path;
            return -1;
        }
        if (lseek(unzip_fd.get(), 0, SEEK_SET) < 0) {
            PLOG(ERROR) << "lseek failed";
            return -1;
        }
    } else if (source_tf_fd_ >= 0) {
        unzip_fd.reset(openat(source_tf_fd_.get(), local_path.c_str(), O_RDONLY));
        if (unzip_fd < 0) {
            PLOG(ERROR) << "open failed: " << FLAGS_source_tf << "/" << local_path;
            return -1;
        }
    } else {
        LOG(ERROR) << "No source target files package was specified; need -source_tf";
        return -1;
    }

    std::unique_ptr<struct sparse_file, decltype(&sparse_file_destroy)> s(
            sparse_file_import(unzip_fd.get(), false, false), &sparse_file_destroy);
    if (s) {
        TemporaryFile tmp;
        if (tmp.fd < 0) {
            PLOG(ERROR) << "mkstemp failed";
            return -1;
        }
        if (sparse_file_write(s.get(), tmp.fd, false, false, false) < 0) {
            LOG(ERROR) << "sparse_file_write failed";
            return -1;
        }
        source_image_.reset(tmp.release());
    } else {
        source_image_ = std::move(unzip_fd);
    }
    return source_image_;
}

template <typename ContainerType>
class ExtentIter final {
  public:
    ExtentIter(const ContainerType& container)
        : iter_(container.cbegin()), end_(container.cend()), dst_index_(0) {}

    bool GetNext(uint64_t* block) {
        while (iter_ != end_) {
            if (dst_index_ < iter_->num_blocks()) {
                break;
            }
            iter_++;
            dst_index_ = 0;
        }
        if (iter_ == end_) {
            return false;
        }
        *block = iter_->start_block() + dst_index_;
        dst_index_++;
        return true;
    }

  private:
    typename ContainerType::const_iterator iter_;
    typename ContainerType::const_iterator end_;
    uint64_t dst_index_;
};

bool PayloadConverter::ProcessCopy(const InstallOperation& op) {
    ExtentIter dst_blocks(op.dst_extents());

    for (const auto& extent : op.src_extents()) {
        for (uint64_t i = 0; i < extent.num_blocks(); i++) {
            uint64_t src_block = extent.start_block() + i;
            uint64_t dst_block;
            if (!dst_blocks.GetNext(&dst_block)) {
                LOG(ERROR) << "SOURCE_COPY contained mismatching extents";
                return false;
            }
            if (src_block == dst_block) continue;
            if (!writer_->AddCopy(dst_block, src_block)) {
                LOG(ERROR) << "Could not add copy operation";
                return false;
            }
        }
    }
    return true;
}

bool PayloadConverter::ProcessReplace(const InstallOperation& op) {
    auto buffer_size = op.data_length();
    auto buffer = std::make_unique<char[]>(buffer_size);
    uint64_t offs = payload_offset_ + op.data_offset();
    if (lseek(in_fd_.get(), offs, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek " << offs << " failed";
        return false;
    }
    if (!android::base::ReadFully(in_fd_, buffer.get(), buffer_size)) {
        PLOG(ERROR) << "read " << buffer_size << " bytes from offset " << offs << "failed";
        return false;
    }

    uint64_t dst_size = 0;
    for (const auto& extent : op.dst_extents()) {
        dst_size += extent.num_blocks() * kBlockSize;
    }

    if (op.type() == InstallOperation::REPLACE_BZ) {
        auto tmp = std::make_unique<char[]>(dst_size);

        uint32_t actual_size;
        if (dst_size > std::numeric_limits<typeof(actual_size)>::max()) {
            LOG(ERROR) << "too many bytes to decompress: " << dst_size;
            return false;
        }
        actual_size = static_cast<uint32_t>(dst_size);

        auto rv = BZ2_bzBuffToBuffDecompress(tmp.get(), &actual_size, buffer.get(), buffer_size, 0,
                                             0);
        if (rv) {
            LOG(ERROR) << "bz2 decompress failed: " << rv;
            return false;
        }
        if (actual_size != dst_size) {
            LOG(ERROR) << "bz2 returned " << actual_size << " bytes, expected " << dst_size;
            return false;
        }
        buffer = std::move(tmp);
        buffer_size = dst_size;
    } else if (op.type() == InstallOperation::REPLACE_XZ) {
        constexpr uint32_t kXzMaxDictSize = 64 * 1024 * 1024;

        if (dst_size > std::numeric_limits<size_t>::max()) {
            LOG(ERROR) << "too many bytes to decompress: " << dst_size;
            return false;
        }

        std::unique_ptr<struct xz_dec, decltype(&xz_dec_end)> s(
                xz_dec_init(XZ_DYNALLOC, kXzMaxDictSize), xz_dec_end);
        if (!s) {
            LOG(ERROR) << "xz_dec_init failed";
            return false;
        }

        auto tmp = std::make_unique<char[]>(dst_size);

        struct xz_buf args;
        args.in = reinterpret_cast<const uint8_t*>(buffer.get());
        args.in_pos = 0;
        args.in_size = buffer_size;
        args.out = reinterpret_cast<uint8_t*>(tmp.get());
        args.out_pos = 0;
        args.out_size = dst_size;

        auto rv = xz_dec_run(s.get(), &args);
        if (rv != XZ_STREAM_END) {
            LOG(ERROR) << "xz decompress failed: " << (int)rv;
            return false;
        }
        buffer = std::move(tmp);
        buffer_size = dst_size;
    }

    uint64_t buffer_pos = 0;
    for (const auto& extent : op.dst_extents()) {
        uint64_t extent_size = extent.num_blocks() * kBlockSize;
        if (buffer_size - buffer_pos < extent_size) {
            LOG(ERROR) << "replace op ran out of input buffer";
            return false;
        }
        if (!writer_->AddRawBlocks(extent.start_block(), buffer.get() + buffer_pos, extent_size)) {
            LOG(ERROR) << "failed to add raw blocks from replace op";
            return false;
        }
        buffer_pos += extent_size;
    }
    return true;
}

bool PayloadConverter::OpenPayload() {
    in_fd_.reset(open(in_file_.c_str(), O_RDONLY));
    if (in_fd_ < 0) {
        PLOG(ERROR) << "open " << in_file_;
        return false;
    }

    char magic[4];
    if (!android::base::ReadFully(in_fd_, magic, sizeof(magic))) {
        PLOG(ERROR) << "read magic";
        return false;
    }
    if (std::string(magic, sizeof(magic)) != "CrAU") {
        LOG(ERROR) << "Invalid magic in " << in_file_;
        return false;
    }

    uint64_t version;
    uint64_t manifest_size;
    uint32_t manifest_signature_size = 0;
    if (!android::base::ReadFully(in_fd_, &version, sizeof(version))) {
        PLOG(ERROR) << "read version";
        return false;
    }
    version = ToLittleEndian(version);
    if (version < 2) {
        LOG(ERROR) << "Only payload version 2 or higher is supported.";
        return false;
    }

    if (!android::base::ReadFully(in_fd_, &manifest_size, sizeof(manifest_size))) {
        PLOG(ERROR) << "read manifest_size";
        return false;
    }
    manifest_size = ToLittleEndian(manifest_size);
    if (!android::base::ReadFully(in_fd_, &manifest_signature_size,
                                  sizeof(manifest_signature_size))) {
        PLOG(ERROR) << "read manifest_signature_size";
        return false;
    }
    manifest_signature_size = ntohl(manifest_signature_size);

    auto manifest = std::make_unique<uint8_t[]>(manifest_size);
    if (!android::base::ReadFully(in_fd_, manifest.get(), manifest_size)) {
        PLOG(ERROR) << "read manifest";
        return false;
    }

    // Skip past manifest signature.
    auto offs = lseek(in_fd_, manifest_signature_size, SEEK_CUR);
    if (offs < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }
    payload_offset_ = offs;

    if (!manifest_.ParseFromArray(manifest.get(), manifest_size)) {
        LOG(ERROR) << "could not parse manifest";
        return false;
    }
    return true;
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    android::base::InitLogging(argv, android::snapshot::MyLogger);
    gflags::SetUsageMessage("Convert OTA payload to a Virtual A/B COW");
    int arg_start = gflags::ParseCommandLineFlags(&argc, &argv, false);

    xz_crc32_init();

    if (argc - arg_start != 2) {
        std::cerr << "Usage: [options] <payload.bin> <out-dir>\n";
        return 1;
    }

    android::snapshot::PayloadConverter pc(argv[arg_start], argv[arg_start + 1]);
    return pc.Run() ? 0 : 1;
}
