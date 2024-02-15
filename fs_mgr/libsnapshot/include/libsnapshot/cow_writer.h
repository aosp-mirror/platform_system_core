// copyright (c) 2019 the android open source project
//
// licensed under the apache license, version 2.0 (the "license");
// you may not use this file except in compliance with the license.
// you may obtain a copy of the license at
//
//      http://www.apache.org/licenses/license-2.0
//
// unless required by applicable law or agreed to in writing, software
// distributed under the license is distributed on an "as is" basis,
// without warranties or conditions of any kind, either express or implied.
// see the license for the specific language governing permissions and
// limitations under the license.

#pragma once

#include <libsnapshot/cow_compress.h>

#include <stdint.h>

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <vector>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {
struct CowSizeInfo {
    uint64_t cow_size;
    uint64_t op_count_max;
};
struct CowOptions {
    uint32_t block_size = 4096;
    std::string compression;

    // Maximum number of blocks that can be written.
    std::optional<uint64_t> max_blocks;

    // Number of CowOperations in a cluster. 0 for no clustering. Cannot be 1.
    uint32_t cluster_ops = 200;

    bool scratch_space = true;

    // Preset the number of merged ops. Only useful for testing.
    uint64_t num_merge_ops = 0;

    // Number of threads for compression
    uint16_t num_compress_threads = 0;

    // Batch write cluster ops
    bool batch_write = false;

    // Size of the cow operation buffer; used in v3 only.
    uint64_t op_count_max = 0;

    // Compression factor
    uint64_t compression_factor = 4096;
};

// Interface for writing to a snapuserd COW. All operations are ordered; merges
// will occur in the sequence they were added to the COW.
class ICowWriter {
  public:
    using FileDescriptor = chromeos_update_engine::FileDescriptor;

    virtual ~ICowWriter() {}

    // Encode an operation that copies the contents of |old_block| to the
    // location of |new_block|. 'num_blocks' is the number of contiguous
    // COPY operations from |old_block| to |new_block|.
    virtual bool AddCopy(uint64_t new_block, uint64_t old_block, uint64_t num_blocks = 1) = 0;

    // Encode a sequence of raw blocks. |size| must be a multiple of the block size.
    virtual bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size) = 0;

    // Add a sequence of xor'd blocks. |size| must be a multiple of the block size.
    virtual bool AddXorBlocks(uint32_t new_block_start, const void* data, size_t size,
                              uint32_t old_block, uint16_t offset) = 0;

    // Encode a sequence of zeroed blocks. |size| must be a multiple of the block size.
    virtual bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) = 0;

    // Add a label to the op sequence.
    virtual bool AddLabel(uint64_t label) = 0;

    // Add sequence data for op merging. Data is a list of the destination block numbers.
    virtual bool AddSequenceData(size_t num_ops, const uint32_t* data) = 0;

    // Flush all pending writes. This must be called before closing the writer
    // to ensure that the correct headers and footers are written.
    virtual bool Finalize() = 0;

    // Return number of bytes the cow image occupies on disk + the size of sequence && ops buffer
    // The latter two fields are used in v3 cow format and left as 0 for v2 cow format
    virtual CowSizeInfo GetCowSizeInfo() const = 0;

    virtual uint32_t GetBlockSize() const = 0;
    virtual std::optional<uint32_t> GetMaxBlocks() const = 0;

    // Open an ICowReader for this writer. The reader will be a snapshot of the
    // current operations in the writer; new writes after OpenReader() will not
    // be reflected.
    virtual std::unique_ptr<ICowReader> OpenReader() = 0;

    // Open a file descriptor. This allows reading and seeing through the cow
    // as if it were a normal file. The optional source_device must be a valid
    // path if the CowReader contains any copy or xor operations.
    virtual std::unique_ptr<FileDescriptor> OpenFileDescriptor(
            const std::optional<std::string>& source_device) = 0;
};

class CompressWorker {
  public:
    CompressWorker(std::unique_ptr<ICompressor>&& compressor);
    bool RunThread();
    void EnqueueCompressBlocks(const void* buffer, size_t block_size, size_t num_blocks);
    bool GetCompressedBuffers(std::vector<std::vector<uint8_t>>* compressed_buf);
    void Finalize();
    static uint32_t GetDefaultCompressionLevel(CowCompressionAlgorithm compression);

    static bool CompressBlocks(ICompressor* compressor, size_t block_size, const void* buffer,
                               size_t num_blocks,
                               std::vector<std::vector<uint8_t>>* compressed_data);

  private:
    struct CompressWork {
        const void* buffer;
        size_t num_blocks;
        size_t block_size;
        bool compression_status = false;
        std::vector<std::vector<uint8_t>> compressed_data;
    };

    std::unique_ptr<ICompressor> compressor_;

    std::queue<CompressWork> work_queue_;
    std::queue<CompressWork> compressed_queue_;
    std::mutex lock_;
    std::condition_variable cv_;
    bool stopped_ = false;
    size_t total_submitted_ = 0;
    size_t total_processed_ = 0;

    bool CompressBlocks(const void* buffer, size_t num_blocks, size_t block_size,
                        std::vector<std::vector<uint8_t>>* compressed_data);
};

// Create an ICowWriter not backed by any file. This is useful for estimating
// the final size of a cow file.
std::unique_ptr<ICowWriter> CreateCowEstimator(uint32_t version, const CowOptions& options);

// Create an ICowWriter of the given version and options. If a label is given,
// the writer is opened in append mode.
std::unique_ptr<ICowWriter> CreateCowWriter(uint32_t version, const CowOptions& options,
                                            android::base::unique_fd&& fd,
                                            std::optional<uint64_t> label = {});

}  // namespace snapshot
}  // namespace android
