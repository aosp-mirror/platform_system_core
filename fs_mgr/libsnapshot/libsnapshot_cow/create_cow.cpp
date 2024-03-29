#include <linux/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <condition_variable>
#include <cstring>
#include <future>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <storage_literals/storage_literals.h>

#include <android-base/chrono_utils.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>

#include <gflags/gflags.h>
#include <libsnapshot/cow_writer.h>

#include <openssl/sha.h>

DEFINE_string(source, "", "Source partition image");
DEFINE_string(target, "", "Target partition image");
DEFINE_string(compression, "lz4",
              "Compression algorithm. Default is set to lz4. Available options: lz4, zstd, gz");

namespace android {
namespace snapshot {

using namespace android::storage_literals;
using namespace android;
using android::base::unique_fd;

using android::snapshot::CreateCowWriter;
using android::snapshot::ICowWriter;

class CreateSnapshot {
  public:
    CreateSnapshot(const std::string& src_file, const std::string& target_file,
                   const std::string& patch_file, const std::string& compression);
    bool CreateSnapshotPatch();

  private:
    /* source.img */
    std::string src_file_;
    /* target.img */
    std::string target_file_;
    /* snapshot-patch generated */
    std::string patch_file_;

    /*
     * Active file which is being parsed by this instance.
     * It will either be source.img or target.img.
     */
    std::string parsing_file_;
    bool create_snapshot_patch_ = false;

    const int kNumThreads = 6;
    const size_t kBlockSizeToRead = 1_MiB;
    const size_t compression_factor_ = 64_KiB;
    size_t replace_ops_ = 0, copy_ops_ = 0, zero_ops_ = 0, in_place_ops_ = 0;

    std::unordered_map<std::string, int> source_block_hash_;
    std::mutex source_block_hash_lock_;

    std::unique_ptr<ICowWriter> writer_;
    std::mutex write_lock_;

    std::unique_ptr<uint8_t[]> zblock_;

    std::string compression_ = "lz4";
    unique_fd cow_fd_;
    unique_fd target_fd_;

    std::vector<uint64_t> zero_blocks_;
    std::vector<uint64_t> replace_blocks_;
    std::unordered_map<uint64_t, uint64_t> copy_blocks_;

    const int BLOCK_SZ = 4_KiB;
    void SHA256(const void* data, size_t length, uint8_t out[32]);
    bool IsBlockAligned(uint64_t read_size) { return ((read_size & (BLOCK_SZ - 1)) == 0); }
    bool ReadBlocks(off_t offset, const int skip_blocks, const uint64_t dev_sz);
    std::string ToHexString(const uint8_t* buf, size_t len);

    bool CreateSnapshotFile();
    bool FindSourceBlockHash();
    bool PrepareParse(std::string& parsing_file, const bool createSnapshot);
    bool ParsePartition();
    void PrepareMergeBlock(const void* buffer, uint64_t block, std::string& block_hash);
    bool WriteV3Snapshots();
    size_t PrepareWrite(size_t* pending_ops, size_t start_index);

    bool CreateSnapshotWriter();
    bool WriteOrderedSnapshots();
    bool WriteNonOrderedSnapshots();
    bool VerifyMergeOrder();
};

void CreateSnapshotLogger(android::base::LogId, android::base::LogSeverity severity, const char*,
                          const char*, unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

CreateSnapshot::CreateSnapshot(const std::string& src_file, const std::string& target_file,
                               const std::string& patch_file, const std::string& compression)
    : src_file_(src_file), target_file_(target_file), patch_file_(patch_file) {
    if (!compression.empty()) {
        compression_ = compression;
    }
}

bool CreateSnapshot::PrepareParse(std::string& parsing_file, const bool createSnapshot) {
    parsing_file_ = parsing_file;
    create_snapshot_patch_ = createSnapshot;

    if (createSnapshot) {
        cow_fd_.reset(open(patch_file_.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666));
        if (cow_fd_ < 0) {
            PLOG(ERROR) << "Failed to open the snapshot-patch file: " << patch_file_;
            return false;
        }

        target_fd_.reset((open(parsing_file_.c_str(), O_RDONLY)));
        if (target_fd_ < 0) {
            LOG(ERROR) << "open failed: " << parsing_file_;
            return false;
        }
        zblock_ = std::make_unique<uint8_t[]>(BLOCK_SZ);
        std::memset(zblock_.get(), 0, BLOCK_SZ);
    }
    return true;
}

/*
 * Create per-block sha256 hash of source partition
 */
bool CreateSnapshot::FindSourceBlockHash() {
    if (!PrepareParse(src_file_, false)) {
        return false;
    }
    return ParsePartition();
}

/*
 * Create snapshot file by comparing sha256 per block
 * of target.img with the constructed per-block sha256 hash
 * of source partition.
 */
bool CreateSnapshot::CreateSnapshotFile() {
    if (!PrepareParse(target_file_, true)) {
        return false;
    }
    return ParsePartition();
}

/*
 * Creates snapshot patch file by comparing source.img and target.img
 */
bool CreateSnapshot::CreateSnapshotPatch() {
    if (!FindSourceBlockHash()) {
        return false;
    }
    return CreateSnapshotFile();
}

void CreateSnapshot::SHA256(const void* data, size_t length, uint8_t out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, length);
    SHA256_Final(out, &c);
}

std::string CreateSnapshot::ToHexString(const uint8_t* buf, size_t len) {
    char lookup[] = "0123456789abcdef";
    std::string out(len * 2 + 1, '\0');
    char* outp = out.data();
    for (; len > 0; len--, buf++) {
        *outp++ = (char)lookup[*buf >> 4];
        *outp++ = (char)lookup[*buf & 0xf];
    }
    return out;
}

void CreateSnapshot::PrepareMergeBlock(const void* buffer, uint64_t block,
                                       std::string& block_hash) {
    if (std::memcmp(zblock_.get(), buffer, BLOCK_SZ) == 0) {
        std::lock_guard<std::mutex> lock(write_lock_);
        zero_blocks_.push_back(block);
        return;
    }

    auto iter = source_block_hash_.find(block_hash);
    if (iter != source_block_hash_.end()) {
        std::lock_guard<std::mutex> lock(write_lock_);
        // In-place copy is skipped
        if (block != iter->second) {
            copy_blocks_[block] = iter->second;
        } else {
            in_place_ops_ += 1;
        }
        return;
    }
    std::lock_guard<std::mutex> lock(write_lock_);
    replace_blocks_.push_back(block);
}

size_t CreateSnapshot::PrepareWrite(size_t* pending_ops, size_t start_index) {
    size_t num_ops = *pending_ops;
    uint64_t start_block = replace_blocks_[start_index];
    size_t nr_consecutive = 1;
    num_ops -= 1;
    while (num_ops) {
        uint64_t next_block = replace_blocks_[start_index + nr_consecutive];
        if (next_block != start_block + nr_consecutive) {
            break;
        }
        nr_consecutive += 1;
        num_ops -= 1;
    }
    return nr_consecutive;
}

bool CreateSnapshot::CreateSnapshotWriter() {
    uint64_t dev_sz = lseek(target_fd_.get(), 0, SEEK_END);
    CowOptions options;
    options.compression = compression_;
    options.num_compress_threads = 2;
    options.batch_write = true;
    options.cluster_ops = 600;
    options.compression_factor = compression_factor_;
    options.max_blocks = {dev_sz / options.block_size};
    writer_ = CreateCowWriter(3, options, std::move(cow_fd_));
    return true;
}

bool CreateSnapshot::WriteNonOrderedSnapshots() {
    zero_ops_ = zero_blocks_.size();
    for (auto it = zero_blocks_.begin(); it != zero_blocks_.end(); it++) {
        if (!writer_->AddZeroBlocks(*it, 1)) {
            return false;
        }
    }
    std::string buffer(compression_factor_, '\0');

    replace_ops_ = replace_blocks_.size();
    size_t blocks_to_compress = replace_blocks_.size();
    size_t num_ops = 0;
    size_t block_index = 0;
    while (blocks_to_compress) {
        num_ops = std::min((compression_factor_ / BLOCK_SZ), blocks_to_compress);
        auto linear_blocks = PrepareWrite(&num_ops, block_index);
        if (!android::base::ReadFullyAtOffset(target_fd_.get(), buffer.data(),
                                              (linear_blocks * BLOCK_SZ),
                                              replace_blocks_[block_index] * BLOCK_SZ)) {
            LOG(ERROR) << "Failed to read at offset: " << replace_blocks_[block_index] * BLOCK_SZ
                       << " size: " << linear_blocks * BLOCK_SZ;
            return false;
        }
        if (!writer_->AddRawBlocks(replace_blocks_[block_index], buffer.data(),
                                   linear_blocks * BLOCK_SZ)) {
            LOG(ERROR) << "AddRawBlocks failed";
            return false;
        }

        block_index += linear_blocks;
        blocks_to_compress -= linear_blocks;
    }
    if (!writer_->Finalize()) {
        return false;
    }
    return true;
}

bool CreateSnapshot::WriteOrderedSnapshots() {
    std::unordered_map<uint64_t, uint64_t> overwritten_blocks;
    std::vector<std::pair<uint64_t, uint64_t>> merge_sequence;
    for (auto it = copy_blocks_.begin(); it != copy_blocks_.end(); it++) {
        if (overwritten_blocks.count(it->second)) {
            replace_blocks_.push_back(it->first);
            continue;
        }
        overwritten_blocks[it->first] = it->second;
        merge_sequence.emplace_back(std::make_pair(it->first, it->second));
    }
    // Sort the blocks so that if the blocks are contiguous, it would help
    // compress multiple blocks in one shot based on the compression factor.
    std::sort(replace_blocks_.begin(), replace_blocks_.end());

    copy_ops_ = merge_sequence.size();
    for (auto it = merge_sequence.begin(); it != merge_sequence.end(); it++) {
        if (!writer_->AddCopy(it->first, it->second, 1)) {
            return false;
        }
    }

    return true;
}

bool CreateSnapshot::VerifyMergeOrder() {
    unique_fd read_fd;
    read_fd.reset(open(patch_file_.c_str(), O_RDONLY));
    if (read_fd < 0) {
        PLOG(ERROR) << "Failed to open the snapshot-patch file: " << patch_file_;
        return false;
    }
    CowReader reader;
    if (!reader.Parse(read_fd)) {
        LOG(ERROR) << "Parse failed";
        return false;
    }

    if (!reader.VerifyMergeOps()) {
        LOG(ERROR) << "MergeOps Order is wrong";
        return false;
    }
    return true;
}

bool CreateSnapshot::WriteV3Snapshots() {
    if (!CreateSnapshotWriter()) {
        return false;
    }
    if (!WriteOrderedSnapshots()) {
        return false;
    }
    if (!WriteNonOrderedSnapshots()) {
        return false;
    }
    if (!VerifyMergeOrder()) {
        return false;
    }

    LOG(INFO) << "In-place: " << in_place_ops_ << " Zero: " << zero_ops_
              << " Replace: " << replace_ops_ << " copy: " << copy_ops_;
    return true;
}

bool CreateSnapshot::ReadBlocks(off_t offset, const int skip_blocks, const uint64_t dev_sz) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(parsing_file_.c_str(), O_RDONLY)));
    if (fd < 0) {
        LOG(ERROR) << "open failed: " << parsing_file_;
        return false;
    }

    loff_t file_offset = offset;
    const uint64_t read_sz = kBlockSizeToRead;
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(read_sz);

    while (true) {
        size_t to_read = std::min((dev_sz - file_offset), read_sz);

        if (!android::base::ReadFullyAtOffset(fd.get(), buffer.get(), to_read, file_offset)) {
            LOG(ERROR) << "Failed to read block from block device: " << parsing_file_
                       << " at offset: " << file_offset << " read-size: " << to_read
                       << " block-size: " << dev_sz;
            return false;
        }

        if (!IsBlockAligned(to_read)) {
            LOG(ERROR) << "unable to parse the un-aligned request: " << to_read;
            return false;
        }

        size_t num_blocks = to_read / BLOCK_SZ;
        uint64_t buffer_offset = 0;
        off_t foffset = file_offset;

        while (num_blocks) {
            const void* bufptr = (char*)buffer.get() + buffer_offset;
            uint64_t blkindex = foffset / BLOCK_SZ;

            uint8_t checksum[32];
            SHA256(bufptr, BLOCK_SZ, checksum);
            std::string hash = ToHexString(checksum, sizeof(checksum));

            if (create_snapshot_patch_) {
                PrepareMergeBlock(bufptr, blkindex, hash);
            } else {
                std::lock_guard<std::mutex> lock(source_block_hash_lock_);
                {
                    if (source_block_hash_.count(hash) == 0) {
                        source_block_hash_[hash] = blkindex;
                    }
                }
            }
            buffer_offset += BLOCK_SZ;
            foffset += BLOCK_SZ;
            num_blocks -= 1;
        }

        file_offset += (skip_blocks * to_read);
        if (file_offset >= dev_sz) {
            break;
        }
    }

    return true;
}

bool CreateSnapshot::ParsePartition() {
    unique_fd fd(TEMP_FAILURE_RETRY(open(parsing_file_.c_str(), O_RDONLY)));
    if (fd < 0) {
        LOG(ERROR) << "open failed: " << parsing_file_;
        return false;
    }

    uint64_t dev_sz = lseek(fd.get(), 0, SEEK_END);
    if (!dev_sz) {
        LOG(ERROR) << "Could not determine block device size: " << parsing_file_;
        return false;
    }

    if (!IsBlockAligned(dev_sz)) {
        LOG(ERROR) << "dev_sz: " << dev_sz << " is not block aligned";
        return false;
    }

    int num_threads = kNumThreads;

    std::vector<std::future<bool>> threads;
    off_t start_offset = 0;
    const int skip_blocks = num_threads;

    while (num_threads) {
        threads.emplace_back(std::async(std::launch::async, &CreateSnapshot::ReadBlocks, this,
                                        start_offset, skip_blocks, dev_sz));
        start_offset += kBlockSizeToRead;
        num_threads -= 1;
        if (start_offset >= dev_sz) {
            break;
        }
    }

    bool ret = true;
    for (auto& t : threads) {
        ret = t.get() && ret;
    }

    if (ret && create_snapshot_patch_ && !WriteV3Snapshots()) {
        LOG(ERROR) << "Snapshot Write failed";
        return false;
    }

    return ret;
}

}  // namespace snapshot
}  // namespace android

constexpr char kUsage[] = R"(
NAME
    create_snapshot - Create snapshot patches by comparing two partition images

SYNOPSIS
    create_snapshot --source=<source.img> --target=<target.img> --compression="<compression-algorithm"

    source.img -> Source partition image
    target.img -> Target partition image
    compressoin -> compression algorithm. Default set to lz4. Supported types are gz, lz4, zstd.

EXAMPLES

   $ create_snapshot $SOURCE_BUILD/system.img $TARGET_BUILD/system.img
   $ create_snapshot $SOURCE_BUILD/product.img $TARGET_BUILD/product.img --compression="zstd"

)";

int main(int argc, char* argv[]) {
    android::base::InitLogging(argv, &android::snapshot::CreateSnapshotLogger);
    ::gflags::SetUsageMessage(kUsage);
    ::gflags::ParseCommandLineFlags(&argc, &argv, true);

    if (FLAGS_source.empty() || FLAGS_target.empty()) {
        LOG(INFO) << kUsage;
        return 0;
    }

    std::string fname = android::base::Basename(FLAGS_target.c_str());
    auto parts = android::base::Split(fname, ".");
    std::string snapshotfile = parts[0] + ".patch";
    android::snapshot::CreateSnapshot snapshot(FLAGS_source, FLAGS_target, snapshotfile,
                                               FLAGS_compression);

    if (!snapshot.CreateSnapshotPatch()) {
        LOG(ERROR) << "Snapshot creation failed";
        return -1;
    }

    LOG(INFO) << "Snapshot patch: " << snapshotfile << " created successfully";
    return 0;
}
