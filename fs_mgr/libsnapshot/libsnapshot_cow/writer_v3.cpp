//
// Copyright (C) 2020 The Android Open Source_info Project
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

#include "writer_v3.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <brotli/encode.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <lz4.h>
#include <zlib.h>

#include <fcntl.h>
#include <libsnapshot/cow_compress.h>
#include <libsnapshot_cow/parser_v3.h>
#include <linux/fs.h>
#include <storage_literals/storage_literals.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <numeric>

// The info messages here are spammy, but as useful for update_engine. Disable
// them when running on the host.
#ifdef __ANDROID__
#define LOG_INFO LOG(INFO)
#else
#define LOG_INFO LOG(VERBOSE)
#endif

namespace android {
namespace snapshot {

static_assert(sizeof(off_t) == sizeof(uint64_t));

using namespace android::storage_literals;
using android::base::unique_fd;

// Divide |x| by |y| and round up to the nearest integer.
constexpr uint64_t DivRoundUp(uint64_t x, uint64_t y) {
    return (x + y - 1) / y;
}

CowWriterV3::CowWriterV3(const CowOptions& options, unique_fd&& fd)
    : CowWriterBase(options, std::move(fd)), batch_size_(std::max<size_t>(options.cluster_ops, 1)) {
    SetupHeaders();
}

void CowWriterV3::InitWorkers() {
    if (num_compress_threads_ <= 1) {
        LOG_INFO << "Not creating new threads for compression.";
        return;
    }
    compress_threads_.reserve(num_compress_threads_);
    compress_threads_.clear();
    threads_.reserve(num_compress_threads_);
    threads_.clear();
    for (size_t i = 0; i < num_compress_threads_; i++) {
        std::unique_ptr<ICompressor> compressor =
                ICompressor::Create(compression_, header_.max_compression_size);
        auto&& wt = compress_threads_.emplace_back(
                std::make_unique<CompressWorker>(std::move(compressor)));
        threads_.emplace_back(std::thread([wt = wt.get()]() { wt->RunThread(); }));
    }
    LOG(INFO) << num_compress_threads_ << " thread used for compression";
}

void CowWriterV3::SetupHeaders() {
    header_ = {};
    header_.prefix.magic = kCowMagicNumber;
    header_.prefix.major_version = 3;
    header_.prefix.minor_version = 0;
    header_.prefix.header_size = sizeof(CowHeaderV3);
    header_.footer_size = 0;
    header_.op_size = sizeof(CowOperationV3);
    header_.block_size = options_.block_size;
    header_.num_merge_ops = options_.num_merge_ops;
    header_.cluster_ops = 0;
    if (options_.scratch_space) {
        header_.buffer_size = BUFFER_REGION_DEFAULT_SIZE;
    }

    // v3 specific fields
    // WIP: not quite sure how some of these are calculated yet, assuming buffer_size is determined
    // during COW size estimation
    header_.sequence_data_count = 0;

    header_.resume_point_count = 0;
    header_.resume_point_max = kNumResumePoints;
    header_.op_count = 0;
    header_.op_count_max = 0;
    header_.compression_algorithm = kCowCompressNone;
    header_.max_compression_size = options_.compression_factor;
}

bool CowWriterV3::ParseOptions() {
    if (!header_.max_compression_size || !IsBlockAligned(header_.max_compression_size)) {
        LOG(ERROR) << "Invalid compression factor: " << header_.max_compression_size;
        return false;
    }

    num_compress_threads_ = std::max(int(options_.num_compress_threads), 1);
    auto parts = android::base::Split(options_.compression, ",");
    if (parts.size() > 2) {
        LOG(ERROR) << "failed to parse compression parameters: invalid argument count: "
                   << parts.size() << " " << options_.compression;
        return false;
    }
    auto algorithm = CompressionAlgorithmFromString(parts[0]);
    if (!algorithm) {
        LOG(ERROR) << "unrecognized compression: " << options_.compression;
        return false;
    }
    header_.compression_algorithm = *algorithm;
    header_.op_count_max = options_.op_count_max;

    if (!IsEstimating() && header_.op_count_max == 0) {
        if (!options_.max_blocks.has_value()) {
            LOG(ERROR) << "can't size op buffer size since op_count_max is 0 and max_blocks is not "
                          "set.";
            return false;
        }
        LOG(INFO) << "op count max is read in as 0. Setting to "
                     "num blocks in partition "
                  << options_.max_blocks.value();
        header_.op_count_max = options_.max_blocks.value();
    }

    if (parts.size() > 1) {
        if (!android::base::ParseUint(parts[1], &compression_.compression_level)) {
            LOG(ERROR) << "failed to parse compression level invalid type: " << parts[1];
            return false;
        }
    } else {
        compression_.compression_level =
                CompressWorker::GetDefaultCompressionLevel(algorithm.value());
    }

    compression_.algorithm = *algorithm;
    if (compression_.algorithm != kCowCompressNone) {
        compressor_ = ICompressor::Create(compression_, header_.max_compression_size);
        if (compressor_ == nullptr) {
            LOG(ERROR) << "Failed to create compressor for " << compression_.algorithm;
            return false;
        }
    }

    if (options_.cluster_ops &&
        (android::base::GetBoolProperty("ro.virtual_ab.batch_writes", false) ||
         options_.batch_write)) {
        batch_size_ = std::max<size_t>(options_.cluster_ops, 1);
        data_vec_.reserve(batch_size_);
        cached_data_.reserve(batch_size_);
        cached_ops_.reserve(batch_size_);
    }

    if (batch_size_ > 1) {
        LOG(INFO) << "Batch writes: enabled with batch size " << batch_size_;
    } else {
        LOG(INFO) << "Batch writes: disabled";
    }
    if (android::base::GetBoolProperty("ro.virtual_ab.compression.threads", false) &&
        options_.num_compress_threads) {
        num_compress_threads_ = options_.num_compress_threads;
    }
    InitWorkers();

    return true;
}

CowWriterV3::~CowWriterV3() {
    for (const auto& t : compress_threads_) {
        t->Finalize();
    }
    for (auto& t : threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
}

bool CowWriterV3::Initialize(std::optional<uint64_t> label) {
    if (!InitFd() || !ParseOptions()) {
        return false;
    }
    if (!label) {
        if (!OpenForWrite()) {
            return false;
        }
    } else {
        if (!OpenForAppend(*label)) {
            return false;
        }
    }
    return true;
}

bool CowWriterV3::OpenForWrite() {
    // This limitation is tied to the data field size in CowOperationV2.
    // Keeping this for V3 writer <- although we
    if (header_.block_size > std::numeric_limits<uint16_t>::max()) {
        LOG(ERROR) << "Block size is too large";
        return false;
    }

    if (lseek(fd_.get(), 0, SEEK_SET) < 0) {
        PLOG(ERROR) << "lseek failed";
        return false;
    }

    // Headers are not complete, but this ensures the file is at the right
    // position.
    if (!android::base::WriteFully(fd_, &header_, sizeof(header_))) {
        PLOG(ERROR) << "write failed";
        return false;
    }

    if (options_.scratch_space) {
        // Initialize the scratch space
        std::string data(header_.buffer_size, 0);
        if (!android::base::WriteFully(fd_, data.data(), header_.buffer_size)) {
            PLOG(ERROR) << "writing scratch space failed";
            return false;
        }
    }

    resume_points_ = std::make_shared<std::vector<ResumePoint>>();

    if (!Sync()) {
        LOG(ERROR) << "Header sync failed";
        return false;
    }
    next_data_pos_ = GetDataOffset(header_);
    return true;
}

bool CowWriterV3::OpenForAppend(uint64_t label) {
    CowHeaderV3 header_v3{};
    if (!ReadCowHeader(fd_, &header_v3)) {
        LOG(ERROR) << "Couldn't read Cow Header";
        return false;
    }

    header_ = header_v3;

    CHECK(label >= 0);
    CowParserV3 parser;
    if (!parser.Parse(fd_, header_, label)) {
        PLOG(ERROR) << "unable to parse with given label: " << label;
        return false;
    }

    resume_points_ = parser.resume_points();
    options_.block_size = header_.block_size;
    next_data_pos_ = GetDataOffset(header_);

    TranslatedCowOps ops;
    parser.Translate(&ops);
    header_.op_count = ops.ops->size();

    for (const auto& op : *ops.ops) {
        next_data_pos_ += op.data_length;
    }

    return true;
}

bool CowWriterV3::CheckOpCount(size_t op_count) {
    if (IsEstimating()) {
        return true;
    }
    if (header_.op_count + cached_ops_.size() + op_count > header_.op_count_max) {
        LOG(ERROR) << "Current number of ops on disk: " << header_.op_count
                   << ", number of ops cached in memory: " << cached_ops_.size()
                   << ", number of ops attempting to write: " << op_count
                   << ", this will exceed max op count " << header_.op_count_max;
        return false;
    }
    return true;
}

bool CowWriterV3::EmitCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks) {
    if (!CheckOpCount(num_blocks)) {
        return false;
    }
    for (size_t i = 0; i < num_blocks; i++) {
        CowOperationV3& op = cached_ops_.emplace_back();
        op.set_type(kCowCopyOp);
        op.new_block = new_block + i;
        op.set_source(old_block + i);
    }

    if (NeedsFlush()) {
        if (!FlushCacheOps()) {
            return false;
        }
    }
    return true;
}

bool CowWriterV3::EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) {
    return EmitBlocks(new_block_start, data, size, 0, 0, kCowReplaceOp);
}

bool CowWriterV3::EmitXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                                uint32_t old_block, uint16_t offset) {
    return EmitBlocks(new_block_start, data, size, old_block, offset, kCowXorOp);
}

bool CowWriterV3::NeedsFlush() const {
    // Allow bigger batch sizes for ops without data. A single CowOperationV3
    // struct uses 14 bytes of memory, even if we cache 200 * 16 ops in memory,
    // it's only ~44K.
    return cached_data_.size() >= batch_size_ || cached_ops_.size() >= batch_size_ * 16;
}

bool CowWriterV3::ConstructCowOpCompressedBuffers(uint64_t new_block_start, const void* data,
                                                  uint64_t old_block, uint16_t offset,
                                                  CowOperationType type, size_t blocks_to_write) {
    size_t compressed_bytes = 0;
    auto&& blocks = CompressBlocks(blocks_to_write, data, type);
    if (blocks.empty()) {
        LOG(ERROR) << "Failed to compress blocks " << new_block_start << ", " << blocks_to_write
                   << ", actual number of blocks received from compressor " << blocks.size();
        return false;
    }
    if (!CheckOpCount(blocks.size())) {
        return false;
    }
    size_t blocks_written = 0;
    for (size_t blk_index = 0; blk_index < blocks.size(); blk_index++) {
        CowOperation& op = cached_ops_.emplace_back();
        auto& vec = data_vec_.emplace_back();
        CompressedBuffer buffer = std::move(blocks[blk_index]);
        auto& compressed_data = cached_data_.emplace_back(std::move(buffer.compressed_data));
        op.new_block = new_block_start + blocks_written;

        op.set_type(type);
        op.set_compression_bits(std::log2(buffer.compression_factor / header_.block_size));

        if (type == kCowXorOp) {
            op.set_source((old_block + blocks_written) * header_.block_size + offset);
        } else {
            op.set_source(next_data_pos_ + compressed_bytes);
        }

        vec = {.iov_base = compressed_data.data(), .iov_len = compressed_data.size()};
        op.data_length = vec.iov_len;
        compressed_bytes += op.data_length;
        blocks_written += (buffer.compression_factor / header_.block_size);
    }
    if (blocks_written != blocks_to_write) {
        LOG(ERROR) << "Total compressed blocks: " << blocks_written
                   << " Expected: " << blocks_to_write;
        return false;
    }
    return true;
}

bool CowWriterV3::EmitBlocks(uint64_t new_block_start, const void* data, size_t size,
                             uint64_t old_block, uint16_t offset, CowOperationType type) {
    if (compression_.algorithm != kCowCompressNone && compressor_ == nullptr) {
        LOG(ERROR) << "Compression algorithm is " << compression_.algorithm
                   << " but compressor is uninitialized.";
        return false;
    }
    const auto bytes = reinterpret_cast<const uint8_t*>(data);
    const size_t num_blocks = (size / header_.block_size);
    for (size_t i = 0; i < num_blocks;) {
        const size_t blocks_to_write =
                std::min<size_t>(batch_size_ - cached_data_.size(), num_blocks - i);

        if (!ConstructCowOpCompressedBuffers(new_block_start + i, bytes + header_.block_size * i,
                                             old_block + i, offset, type, blocks_to_write)) {
            return false;
        }

        if (NeedsFlush() && !FlushCacheOps()) {
            LOG(ERROR) << "EmitBlocks with compression: write failed. new block: "
                       << new_block_start << " compression: " << compression_.algorithm
                       << ", op type: " << type;
            return false;
        }

        i += blocks_to_write;
    }

    return true;
}

bool CowWriterV3::EmitZeroBlocks(uint64_t new_block_start, const uint64_t num_blocks) {
    if (!CheckOpCount(num_blocks)) {
        return false;
    }
    for (uint64_t i = 0; i < num_blocks; i++) {
        auto& op = cached_ops_.emplace_back();
        op.set_type(kCowZeroOp);
        op.new_block = new_block_start + i;
    }
    if (NeedsFlush()) {
        if (!FlushCacheOps()) {
            return false;
        }
    }
    return true;
}

bool CowWriterV3::EmitLabel(uint64_t label) {
    // remove all labels greater than this current one. we want to avoid the situation of adding
    // in
    // duplicate labels with differing op values
    if (!FlushCacheOps()) {
        LOG(ERROR) << "Failed to flush cached ops before emitting label " << label;
        return false;
    }
    auto remove_if_callback = [&](const auto& resume_point) -> bool {
        if (resume_point.label >= label) return true;
        return false;
    };
    resume_points_->erase(
            std::remove_if(resume_points_->begin(), resume_points_->end(), remove_if_callback),
            resume_points_->end());

    resume_points_->push_back({label, header_.op_count});
    header_.resume_point_count++;
    // remove the oldest resume point if resume_buffer is full
    while (resume_points_->size() > header_.resume_point_max) {
        resume_points_->erase(resume_points_->begin());
    }

    CHECK_LE(resume_points_->size(), header_.resume_point_max);

    if (!android::base::WriteFullyAtOffset(fd_, resume_points_->data(),
                                           resume_points_->size() * sizeof(ResumePoint),
                                           GetResumeOffset(header_))) {
        PLOG(ERROR) << "writing resume buffer failed";
        return false;
    }
    return Finalize();
}

bool CowWriterV3::EmitSequenceData(size_t num_ops, const uint32_t* data) {
    if (header_.op_count > 0 || !cached_ops_.empty()) {
        LOG(ERROR) << "There's " << header_.op_count << " operations written to disk and "
                   << cached_ops_.size()
                   << " ops cached in memory. Writing sequence data is only allowed before all "
                      "operation writes.";
        return false;
    }

    header_.sequence_data_count = num_ops;

    // Ensure next_data_pos_ is updated as previously initialized + the newly added sequence buffer.
    CHECK_EQ(next_data_pos_ + header_.sequence_data_count * sizeof(uint32_t),
             GetDataOffset(header_));
    next_data_pos_ = GetDataOffset(header_);

    if (!android::base::WriteFullyAtOffset(fd_, data, sizeof(data[0]) * num_ops,
                                           GetSequenceOffset(header_))) {
        PLOG(ERROR) << "writing sequence buffer failed";
        return false;
    }
    return true;
}

bool CowWriterV3::FlushCacheOps() {
    if (cached_ops_.empty()) {
        if (!data_vec_.empty()) {
            LOG(ERROR) << "Cached ops is empty, but data iovec has size: " << data_vec_.size()
                       << " this is definitely a bug.";
            return false;
        }
        return true;
    }
    size_t bytes_written = 0;

    for (auto& op : cached_ops_) {
        if (op.type() == kCowReplaceOp) {
            op.set_source(next_data_pos_ + bytes_written);
        }
        bytes_written += op.data_length;
    }
    if (!WriteOperation(cached_ops_, data_vec_)) {
        LOG(ERROR) << "Failed to flush " << cached_ops_.size() << " ops to disk";
        return false;
    }
    cached_ops_.clear();
    cached_data_.clear();
    data_vec_.clear();
    return true;
}

size_t CowWriterV3::GetCompressionFactor(const size_t blocks_to_compress,
                                         CowOperationType type) const {
    // For XOR ops, we don't support bigger block size compression yet.
    // For bigger block size support, snapshot-merge also has to changed. We
    // aren't there yet; hence, just stick to 4k for now until
    // snapshot-merge is ready for XOR operation.
    if (type == kCowXorOp) {
        return header_.block_size;
    }

    size_t compression_factor = header_.max_compression_size;
    while (compression_factor > header_.block_size) {
        size_t num_blocks = compression_factor / header_.block_size;
        if (blocks_to_compress >= num_blocks) {
            return compression_factor;
        }
        compression_factor >>= 1;
    }
    return header_.block_size;
}

std::vector<CowWriterV3::CompressedBuffer> CowWriterV3::ProcessBlocksWithNoCompression(
        const size_t num_blocks, const void* data, CowOperationType type) {
    size_t blocks_to_compress = num_blocks;
    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);
    std::vector<CompressedBuffer> compressed_vec;

    while (blocks_to_compress) {
        CompressedBuffer buffer;

        const size_t compression_factor = GetCompressionFactor(blocks_to_compress, type);
        size_t num_blocks = compression_factor / header_.block_size;

        buffer.compression_factor = compression_factor;
        buffer.compressed_data.resize(compression_factor);

        // No compression. Just copy the data as-is.
        std::memcpy(buffer.compressed_data.data(), iter, compression_factor);

        compressed_vec.push_back(std::move(buffer));
        blocks_to_compress -= num_blocks;
        iter += compression_factor;
    }
    return compressed_vec;
}

std::vector<CowWriterV3::CompressedBuffer> CowWriterV3::ProcessBlocksWithCompression(
        const size_t num_blocks, const void* data, CowOperationType type) {
    size_t blocks_to_compress = num_blocks;
    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);
    std::vector<CompressedBuffer> compressed_vec;

    while (blocks_to_compress) {
        CompressedBuffer buffer;

        const size_t compression_factor = GetCompressionFactor(blocks_to_compress, type);
        size_t num_blocks = compression_factor / header_.block_size;

        buffer.compression_factor = compression_factor;
        // Compress the blocks
        buffer.compressed_data = compressor_->Compress(iter, compression_factor);
        if (buffer.compressed_data.empty()) {
            PLOG(ERROR) << "Compression failed";
            return {};
        }

        // Check if the buffer was indeed compressed
        if (buffer.compressed_data.size() >= compression_factor) {
            buffer.compressed_data.resize(compression_factor);
            std::memcpy(buffer.compressed_data.data(), iter, compression_factor);
        }

        compressed_vec.push_back(std::move(buffer));
        blocks_to_compress -= num_blocks;
        iter += compression_factor;
    }
    return compressed_vec;
}

std::vector<CowWriterV3::CompressedBuffer> CowWriterV3::ProcessBlocksWithThreadedCompression(
        const size_t num_blocks, const void* data, CowOperationType type) {
    const size_t num_threads = num_compress_threads_;
    const uint8_t* iter = reinterpret_cast<const uint8_t*>(data);

    // We will alternate which thread to send compress work to. E.g. alternate between T1 and T2
    // until all blocks are processed
    std::vector<CompressedBuffer> compressed_vec;
    int iteration = 0;
    int blocks_to_compress = static_cast<int>(num_blocks);
    while (blocks_to_compress) {
        CompressedBuffer buffer;
        CompressWorker* worker = compress_threads_[iteration % num_threads].get();

        const size_t compression_factor = GetCompressionFactor(blocks_to_compress, type);
        size_t num_blocks = compression_factor / header_.block_size;

        worker->EnqueueCompressBlocks(iter, compression_factor, 1);
        buffer.compression_factor = compression_factor;
        compressed_vec.push_back(std::move(buffer));

        iteration++;
        iter += compression_factor;
        blocks_to_compress -= num_blocks;
    }

    std::vector<std::vector<uint8_t>> compressed_buf;
    std::vector<std::vector<std::vector<uint8_t>>> worker_buffers(num_threads);
    compressed_buf.clear();
    for (size_t i = 0; i < num_threads; i++) {
        CompressWorker* worker = compress_threads_[i].get();
        if (!worker->GetCompressedBuffers(&worker_buffers[i])) {
            return {};
        }
    }
    // compressed_vec | CB 1 | CB 2 | CB 3 | CB 4 | <-compressed buffers
    //                   t1     t2     t1     t2    <- processed by these threads
    // Ordering is important here. We need to retrieve the compressed data in the same order we
    // processed it and assume that that we submit data beginning with the first thread and then
    // round robin the consecutive data calls. We need to Fetch compressed buffers from the threads
    // via the same ordering
    for (size_t i = 0; i < compressed_vec.size(); i++) {
        compressed_buf.emplace_back(worker_buffers[i % num_threads][i / num_threads]);
    }

    if (compressed_vec.size() != compressed_buf.size()) {
        LOG(ERROR) << "Compressed buffer size: " << compressed_buf.size()
                   << " - Expected: " << compressed_vec.size();
        return {};
    }

    iter = reinterpret_cast<const uint8_t*>(data);
    // Walk through all the compressed buffers
    for (size_t i = 0; i < compressed_buf.size(); i++) {
        auto& buffer = compressed_vec[i];
        auto& block = compressed_buf[i];
        size_t block_size = buffer.compression_factor;
        // Check if the blocks was indeed compressed
        if (block.size() >= block_size) {
            buffer.compressed_data.resize(block_size);
            std::memcpy(buffer.compressed_data.data(), iter, block_size);
        } else {
            // Compressed block
            buffer.compressed_data.resize(block.size());
            std::memcpy(buffer.compressed_data.data(), block.data(), block.size());
        }
        iter += block_size;
    }
    return compressed_vec;
}

std::vector<CowWriterV3::CompressedBuffer> CowWriterV3::CompressBlocks(const size_t num_blocks,
                                                                       const void* data,
                                                                       CowOperationType type) {
    if (compression_.algorithm == kCowCompressNone) {
        return ProcessBlocksWithNoCompression(num_blocks, data, type);
    }

    const size_t num_threads = (num_blocks == 1) ? 1 : num_compress_threads_;

    // If no threads are required, just compress the blocks inline.
    if (num_threads <= 1) {
        return ProcessBlocksWithCompression(num_blocks, data, type);
    }

    return ProcessBlocksWithThreadedCompression(num_blocks, data, type);
}

bool CowWriterV3::WriteOperation(std::span<const CowOperationV3> ops,
                                 std::span<const struct iovec> data) {
    const auto total_data_size =
            std::transform_reduce(data.begin(), data.end(), 0, std::plus<size_t>{},
                                  [](const struct iovec& a) { return a.iov_len; });
    if (IsEstimating()) {
        header_.op_count += ops.size();
        if (header_.op_count > header_.op_count_max) {
            // If we increment op_count_max, the offset of data section would
            // change. So need to update |next_data_pos_|
            next_data_pos_ += (header_.op_count - header_.op_count_max) * sizeof(CowOperationV3);
            header_.op_count_max = header_.op_count;
        }
        next_data_pos_ += total_data_size;
        return true;
    }

    if (header_.op_count + ops.size() > header_.op_count_max) {
        LOG(ERROR) << "Current op count " << header_.op_count << ", attempting to write "
                   << ops.size() << " ops will exceed the max of " << header_.op_count_max;
        return false;
    }
    const off_t offset = GetOpOffset(header_.op_count, header_);
    if (!android::base::WriteFullyAtOffset(fd_, ops.data(), ops.size() * sizeof(ops[0]), offset)) {
        PLOG(ERROR) << "Write failed for " << ops.size() << " ops at " << offset;
        return false;
    }
    if (!data.empty()) {
        const auto ret = pwritev(fd_, data.data(), data.size(), next_data_pos_);
        if (ret != total_data_size) {
            PLOG(ERROR) << "write failed for data of size: " << data.size()
                        << " at offset: " << next_data_pos_ << " " << ret;
            return false;
        }
    }
    header_.op_count += ops.size();
    next_data_pos_ += total_data_size;

    return true;
}

bool CowWriterV3::Finalize() {
    CHECK_GE(header_.prefix.header_size, sizeof(CowHeaderV3));
    CHECK_LE(header_.prefix.header_size, sizeof(header_));
    if (!FlushCacheOps()) {
        return false;
    }
    if (!android::base::WriteFullyAtOffset(fd_, &header_, header_.prefix.header_size, 0)) {
        return false;
    }
    return Sync();
}

CowSizeInfo CowWriterV3::GetCowSizeInfo() const {
    CowSizeInfo info;
    info.cow_size = next_data_pos_;
    info.op_count_max = header_.op_count_max;
    return info;
}

}  // namespace snapshot
}  // namespace android
