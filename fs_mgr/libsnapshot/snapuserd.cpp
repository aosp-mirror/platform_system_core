/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/types.h>
#include <stdlib.h>

#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <libsnapshot/snapuserd.h>

namespace android {
namespace snapshot {

using namespace android;
using namespace android::dm;
using android::base::unique_fd;

#define DM_USER_MAP_READ 0
#define DM_USER_MAP_WRITE 1

static constexpr size_t PAYLOAD_SIZE = (1UL << 16);

static_assert(PAYLOAD_SIZE >= BLOCK_SIZE);

class Target {
  public:
    // Represents an already-created Target, which is referenced by UUID.
    Target(std::string uuid) : uuid_(uuid) {}

    const auto& uuid() { return uuid_; }
    std::string control_path() { return std::string("/dev/dm-user-") + uuid(); }

  private:
    const std::string uuid_;
};

class Daemon {
    // The Daemon class is a singleton to avoid
    // instantiating more than once
  public:
    static Daemon& Instance() {
        static Daemon instance;
        return instance;
    }

    bool IsRunning();

  private:
    bool is_running_;

    Daemon();
    Daemon(Daemon const&) = delete;
    void operator=(Daemon const&) = delete;

    static void SignalHandler(int signal);
};

Daemon::Daemon() {
    is_running_ = true;
    signal(SIGINT, Daemon::SignalHandler);
    signal(SIGTERM, Daemon::SignalHandler);
}

bool Daemon::IsRunning() {
    return is_running_;
}

void Daemon::SignalHandler(int signal) {
    LOG(DEBUG) << "Snapuserd received signal: " << signal;
    switch (signal) {
        case SIGINT:
        case SIGTERM: {
            Daemon::Instance().is_running_ = false;
            break;
        }
    }
}

class BufferSink : public IByteSink {
  public:
    void Initialize(size_t size) {
        buffer_size_ = size;
        buffer_offset_ = 0;
        buffer_ = std::make_unique<uint8_t[]>(size);
    }

    void* GetBufPtr() { return buffer_.get(); }

    void Clear() { memset(GetBufPtr(), 0, buffer_size_); }

    void* GetPayloadBuffer(size_t size) {
        if ((buffer_size_ - buffer_offset_) < size) return nullptr;

        char* buffer = reinterpret_cast<char*>(GetBufPtr());
        struct dm_user_message* msg = (struct dm_user_message*)(&(buffer[0]));
        return (char*)msg->payload.buf + buffer_offset_;
    }

    void* GetBuffer(size_t requested, size_t* actual) override {
        void* buf = GetPayloadBuffer(requested);
        if (!buf) {
            *actual = 0;
            return nullptr;
        }
        *actual = requested;
        return buf;
    }

    void UpdateBufferOffset(size_t size) { buffer_offset_ += size; }

    struct dm_user_header* GetHeaderPtr() {
        CHECK(sizeof(struct dm_user_header) <= buffer_size_);
        char* buf = reinterpret_cast<char*>(GetBufPtr());
        struct dm_user_header* header = (struct dm_user_header*)(&(buf[0]));
        return header;
    }

    bool ReturnData(void*, size_t) override { return true; }
    void ResetBufferOffset() { buffer_offset_ = 0; }

  private:
    std::unique_ptr<uint8_t[]> buffer_;
    loff_t buffer_offset_;
    size_t buffer_size_;
};

class Snapuserd final {
  public:
    Snapuserd(const std::string& in_cow_device, const std::string& in_backing_store_device)
        : in_cow_device_(in_cow_device),
          in_backing_store_device_(in_backing_store_device),
          metadata_read_done_(false) {}

    int Run();
    int ReadDmUserHeader();
    int WriteDmUserPayload(size_t size);
    int ConstructKernelCowHeader();
    int ReadMetadata();
    int ZerofillDiskExceptions(size_t read_size);
    int ReadDiskExceptions(chunk_t chunk, size_t size);
    int ReadData(chunk_t chunk, size_t size);

  private:
    int ProcessReplaceOp(const CowOperation* cow_op);
    int ProcessCopyOp(const CowOperation* cow_op);
    int ProcessZeroOp();

    std::string in_cow_device_;
    std::string in_backing_store_device_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;
    unique_fd ctrl_fd_;

    uint32_t exceptions_per_area_;

    std::unique_ptr<ICowOpIter> cowop_iter_;
    std::unique_ptr<CowReader> reader_;

    // Vector of disk exception which is a
    // mapping of old-chunk to new-chunk
    std::vector<std::unique_ptr<uint8_t[]>> vec_;

    // Index - Chunk ID
    // Value - cow operation
    std::vector<const CowOperation*> chunk_vec_;

    bool metadata_read_done_;
    BufferSink bufsink_;
};

// Construct kernel COW header in memory
// This header will be in sector 0. The IO
// request will always be 4k. After constructing
// the header, zero out the remaining block.
int Snapuserd::ConstructKernelCowHeader() {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SIZE);
    CHECK(buffer != nullptr);

    memset(buffer, 0, BLOCK_SIZE);

    struct disk_header* dh = reinterpret_cast<struct disk_header*>(buffer);

    dh->magic = SNAP_MAGIC;
    dh->valid = SNAPSHOT_VALID;
    dh->version = SNAPSHOT_DISK_VERSION;
    dh->chunk_size = CHUNK_SIZE;

    return BLOCK_SIZE;
}

// Start the replace operation. This will read the
// internal COW format and if the block is compressed,
// it will be de-compressed.
int Snapuserd::ProcessReplaceOp(const CowOperation* cow_op) {
    if (!reader_->ReadData(*cow_op, &bufsink_)) {
        LOG(ERROR) << "ReadData failed for chunk: " << cow_op->new_block;
        return -EIO;
    }

    return BLOCK_SIZE;
}

// Start the copy operation. This will read the backing
// block device which is represented by cow_op->source.
int Snapuserd::ProcessCopyOp(const CowOperation* cow_op) {
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SIZE);
    CHECK(buffer != nullptr);

    // Issue a single 4K IO. However, this can be optimized
    // if the successive blocks are contiguous.
    if (!android::base::ReadFullyAtOffset(backing_store_fd_, buffer, BLOCK_SIZE,
                                          cow_op->source * BLOCK_SIZE)) {
        LOG(ERROR) << "Copy-op failed. Read from backing store at: " << cow_op->source;
        return -1;
    }

    return BLOCK_SIZE;
}

int Snapuserd::ProcessZeroOp() {
    // Zero out the entire block
    void* buffer = bufsink_.GetPayloadBuffer(BLOCK_SIZE);
    CHECK(buffer != nullptr);

    memset(buffer, 0, BLOCK_SIZE);
    return BLOCK_SIZE;
}

/*
 * Read the data of size bytes from a given chunk.
 *
 * Kernel can potentially merge the blocks if the
 * successive chunks are contiguous. For chunk size of 8,
 * there can be 256 disk exceptions; and if
 * all 256 disk exceptions are contiguous, kernel can merge
 * them into a single IO.
 *
 * Since each chunk in the disk exception
 * mapping represents a 4k block, kernel can potentially
 * issue 256*4k = 1M IO in one shot.
 *
 * Even though kernel assumes that the blocks are
 * contiguous, we need to split the 1M IO into 4k chunks
 * as each operation represents 4k and it can either be:
 *
 * 1: Replace operation
 * 2: Copy operation
 * 3: Zero operation
 *
 */
int Snapuserd::ReadData(chunk_t chunk, size_t size) {
    int ret = 0;

    size_t read_size = size;

    chunk_t chunk_key = chunk;
    uint32_t stride;
    lldiv_t divresult;

    // Size should always be aligned
    CHECK((read_size & (BLOCK_SIZE - 1)) == 0);

    while (read_size > 0) {
        const CowOperation* cow_op = chunk_vec_[chunk_key];
        CHECK(cow_op != nullptr);
        int result;

        switch (cow_op->type) {
            case kCowReplaceOp: {
                result = ProcessReplaceOp(cow_op);
                break;
            }

            case kCowZeroOp: {
                result = ProcessZeroOp();
                break;
            }

            case kCowCopyOp: {
                result = ProcessCopyOp(cow_op);
                break;
            }

            default: {
                LOG(ERROR) << "Unknown operation-type found: " << cow_op->type;
                ret = -EIO;
                goto done;
            }
        }

        if (result < 0) {
            ret = result;
            goto done;
        }

        // Update the buffer offset
        bufsink_.UpdateBufferOffset(BLOCK_SIZE);

        read_size -= BLOCK_SIZE;
        ret += BLOCK_SIZE;

        // Start iterating the chunk incrementally; Since while
        // constructing the metadata, we know that the chunk IDs
        // are contiguous
        chunk_key += 1;

        // This is similar to the way when chunk IDs were assigned
        // in ReadMetadata().
        //
        // Skip if the chunk id represents a metadata chunk.
        stride = exceptions_per_area_ + 1;
        divresult = lldiv(chunk_key, stride);
        if (divresult.rem == NUM_SNAPSHOT_HDR_CHUNKS) {
            // Crossing exception boundary. Kernel will never
            // issue IO which is spanning between a data chunk
            // and a metadata chunk. This should be perfectly aligned.
            //
            // Since the input read_size is 4k aligned, we will
            // always end up reading all 256 data chunks in one area.
            // Thus, every multiple of 4K IO represents 256 data chunks
            CHECK(read_size == 0);
            break;
        }
    }

done:

    // Reset the buffer offset
    bufsink_.ResetBufferOffset();
    return ret;
}

/*
 * dm-snap does prefetch reads while reading disk-exceptions.
 * By default, prefetch value is set to 12; this means that
 * dm-snap will issue 12 areas wherein each area is a 4k page
 * of disk-exceptions.
 *
 * If during prefetch, if the chunk-id seen is beyond the
 * actual number of metadata page, fill the buffer with zero.
 * When dm-snap starts parsing the buffer, it will stop
 * reading metadata page once the buffer content is zero.
 */
int Snapuserd::ZerofillDiskExceptions(size_t read_size) {
    size_t size = exceptions_per_area_ * sizeof(struct disk_exception);

    if (read_size > size) return -EINVAL;

    void* buffer = bufsink_.GetPayloadBuffer(size);
    CHECK(buffer != nullptr);

    memset(buffer, 0, size);
    return size;
}

/*
 * A disk exception is a simple mapping of old_chunk to new_chunk.
 * When dm-snapshot device is created, kernel requests these mapping.
 *
 * Each disk exception is of size 16 bytes. Thus a single 4k page can
 * have:
 *
 * exceptions_per_area_ = 4096/16 = 256. This entire 4k page
 * is considered a metadata page and it is represented by chunk ID.
 *
 * Convert the chunk ID to index into the vector which gives us
 * the metadata page.
 */
int Snapuserd::ReadDiskExceptions(chunk_t chunk, size_t read_size) {
    uint32_t stride = exceptions_per_area_ + 1;
    size_t size;

    // ChunkID to vector index
    lldiv_t divresult = lldiv(chunk, stride);

    if (divresult.quot < vec_.size()) {
        size = exceptions_per_area_ * sizeof(struct disk_exception);

        if (read_size > size) return -EINVAL;

        void* buffer = bufsink_.GetPayloadBuffer(size);
        CHECK(buffer != nullptr);

        memcpy(buffer, vec_[divresult.quot].get(), size);
    } else {
        size = ZerofillDiskExceptions(read_size);
    }

    return size;
}

/*
 * Read the metadata from COW device and
 * construct the metadata as required by the kernel.
 *
 * Please see design on kernel COW format
 *
 * 1: Read the metadata from internal COW device
 * 2: There are 3 COW operations:
 *     a: Replace op
 *     b: Copy op
 *     c: Zero op
 * 3: For each of the 3 operations, op->new_block
 *    represents the block number in the base device
 *    for which one of the 3 operations have to be applied.
 *    This represents the old_chunk in the kernel COW format
 * 4: We need to assign new_chunk for a corresponding old_chunk
 * 5: The algorithm is similar to how kernel assigns chunk number
 *    while creating exceptions.
 * 6: Use a monotonically increasing chunk number to assign the
 *    new_chunk
 * 7: Each chunk-id represents either a: Metadata page or b: Data page
 * 8: Chunk-id representing a data page is stored in a vector. Index is the
 *    chunk-id and value is the pointer to the CowOperation
 * 9: Chunk-id representing a metadata page is converted into a vector
 *    index. We store this in vector as kernel requests metadata during
 *    two stage:
 *       a: When initial dm-snapshot device is created, kernel requests
 *          all the metadata and stores it in its internal data-structures.
 *       b: During merge, kernel once again requests the same metadata
 *          once-again.
 *    In both these cases, a quick lookup based on chunk-id is done.
 * 10: When chunk number is incremented, we need to make sure that
 *    if the chunk is representing a metadata page and skip.
 * 11: Each 4k page will contain 256 disk exceptions. We call this
 *    exceptions_per_area_
 * 12: Kernel will stop issuing metadata IO request when new-chunk ID is 0.
 */
int Snapuserd::ReadMetadata() {
    reader_ = std::make_unique<CowReader>();
    CowHeader header;

    if (!reader_->Parse(cow_fd_)) {
        LOG(ERROR) << "Failed to parse";
        return 1;
    }

    if (!reader_->GetHeader(&header)) {
        LOG(ERROR) << "Failed to get header";
        return 1;
    }

    CHECK(header.block_size == BLOCK_SIZE);

    LOG(DEBUG) << "Num-ops: " << std::hex << header.num_ops;
    LOG(DEBUG) << "ops-offset: " << std::hex << header.ops_offset;
    LOG(DEBUG) << "ops-size: " << std::hex << header.ops_size;

    cowop_iter_ = reader_->GetOpIter();

    if (cowop_iter_ == nullptr) {
        LOG(ERROR) << "Failed to get cowop_iter";
        return 1;
    }

    exceptions_per_area_ = (CHUNK_SIZE << SECTOR_SHIFT) / sizeof(struct disk_exception);

    // Start from chunk number 2. Chunk 0 represents header and chunk 1
    // represents first metadata page.
    chunk_t next_free = NUM_SNAPSHOT_HDR_CHUNKS + 1;
    chunk_vec_.push_back(nullptr);
    chunk_vec_.push_back(nullptr);

    loff_t offset = 0;
    std::unique_ptr<uint8_t[]> de_ptr =
            std::make_unique<uint8_t[]>(exceptions_per_area_ * sizeof(struct disk_exception));

    // This memset is important. Kernel will stop issuing IO when new-chunk ID
    // is 0. When Area is not filled completely will all 256 exceptions,
    // this memset will ensure that metadata read is completed.
    memset(de_ptr.get(), 0, (exceptions_per_area_ * sizeof(struct disk_exception)));
    size_t num_ops = 0;

    while (!cowop_iter_->Done()) {
        const CowOperation* cow_op = &cowop_iter_->Get();
        struct disk_exception* de =
                reinterpret_cast<struct disk_exception*>((char*)de_ptr.get() + offset);

        if (!(cow_op->type == kCowReplaceOp || cow_op->type == kCowZeroOp ||
              cow_op->type == kCowCopyOp)) {
            LOG(ERROR) << "Unknown operation-type found: " << cow_op->type;
            return 1;
        }

        // Construct the disk-exception
        de->old_chunk = cow_op->new_block;
        de->new_chunk = next_free;

        LOG(DEBUG) << "Old-chunk: " << de->old_chunk << "New-chunk: " << de->new_chunk;

        // Store operation pointer. Note, new-chunk ID is the index
        chunk_vec_.push_back(cow_op);
        CHECK(next_free == (chunk_vec_.size() - 1));

        offset += sizeof(struct disk_exception);

        cowop_iter_->Next();

        // Find the next free chunk-id to be assigned. Check if the next free
        // chunk-id represents a metadata page. If so, skip it.
        next_free += 1;
        uint32_t stride = exceptions_per_area_ + 1;
        lldiv_t divresult = lldiv(next_free, stride);
        num_ops += 1;

        if (divresult.rem == NUM_SNAPSHOT_HDR_CHUNKS) {
            CHECK(num_ops == exceptions_per_area_);
            // Store it in vector at the right index. This maps the chunk-id to
            // vector index.
            vec_.push_back(std::move(de_ptr));
            offset = 0;
            num_ops = 0;

            chunk_t metadata_chunk = (next_free - exceptions_per_area_ - NUM_SNAPSHOT_HDR_CHUNKS);

            LOG(DEBUG) << "Area: " << vec_.size() - 1;
            LOG(DEBUG) << "Metadata-chunk: " << metadata_chunk;
            LOG(DEBUG) << "Sector number of Metadata-chunk: " << (metadata_chunk << CHUNK_SHIFT);

            // Create buffer for next area
            de_ptr = std::make_unique<uint8_t[]>(exceptions_per_area_ *
                                                 sizeof(struct disk_exception));
            memset(de_ptr.get(), 0, (exceptions_per_area_ * sizeof(struct disk_exception)));

            // Since this is a metadata, store at this index
            chunk_vec_.push_back(nullptr);

            // Find the next free chunk-id
            next_free += 1;
            if (cowop_iter_->Done()) {
                vec_.push_back(std::move(de_ptr));
            }
        }
    }

    // Partially filled area
    if (num_ops) {
        LOG(DEBUG) << "Partially filled area num_ops: " << num_ops;
        vec_.push_back(std::move(de_ptr));
    }

    return 0;
}

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    if (severity == android::base::ERROR) {
        fprintf(stderr, "%s\n", message);
    } else {
        fprintf(stdout, "%s\n", message);
    }
}

// Read Header from dm-user misc device. This gives
// us the sector number for which IO is issued by dm-snapshot device
int Snapuserd::ReadDmUserHeader() {
    if (!android::base::ReadFully(ctrl_fd_, bufsink_.GetBufPtr(), sizeof(struct dm_user_header))) {
        PLOG(ERROR) << "Control read failed";
        return -1;
    }

    return sizeof(struct dm_user_header);
}

// Send the payload/data back to dm-user misc device.
int Snapuserd::WriteDmUserPayload(size_t size) {
    if (!android::base::WriteFully(ctrl_fd_, bufsink_.GetBufPtr(),
                                   sizeof(struct dm_user_header) + size)) {
        PLOG(ERROR) << "Write to dm-user failed";
        return -1;
    }

    return sizeof(struct dm_user_header) + size;
}

// Start the daemon.
// TODO: Handle signals
int Snapuserd::Run() {
    backing_store_fd_.reset(open(in_backing_store_device_.c_str(), O_RDONLY));
    if (backing_store_fd_ < 0) {
        LOG(ERROR) << "Open Failed: " << in_backing_store_device_;
        return 1;
    }

    cow_fd_.reset(open(in_cow_device_.c_str(), O_RDWR));
    if (cow_fd_ < 0) {
        LOG(ERROR) << "Open Failed: " << in_cow_device_;
        return 1;
    }

    std::string str(in_cow_device_);
    std::size_t found = str.find_last_of("/\\");
    CHECK(found != std::string::npos);
    std::string device_name = str.substr(found + 1);

    LOG(DEBUG) << "Fetching UUID for: " << device_name;

    auto& dm = dm::DeviceMapper::Instance();
    std::string uuid;
    if (!dm.GetDmDeviceUuidByName(device_name, &uuid)) {
        LOG(ERROR) << "Unable to find UUID for " << in_cow_device_;
        return 1;
    }

    LOG(DEBUG) << "UUID: " << uuid;
    Target t(uuid);

    ctrl_fd_.reset(open(t.control_path().c_str(), O_RDWR));
    if (ctrl_fd_ < 0) {
        LOG(ERROR) << "Unable to open " << t.control_path();
        return 1;
    }

    int ret = 0;

    // Allocate the buffer which is used to communicate between
    // daemon and dm-user. The buffer comprises of header and a fixed payload.
    // If the dm-user requests a big IO, the IO will be broken into chunks
    // of PAYLOAD_SIZE.
    size_t buf_size = sizeof(struct dm_user_header) + PAYLOAD_SIZE;
    bufsink_.Initialize(buf_size);

    while (true) {
        struct dm_user_header* header = bufsink_.GetHeaderPtr();

        bufsink_.Clear();

        ret = ReadDmUserHeader();
        if (ret < 0) return ret;

        LOG(DEBUG) << "dm-user returned " << ret << " bytes";

        LOG(DEBUG) << "msg->seq: " << std::hex << header->seq;
        LOG(DEBUG) << "msg->type: " << std::hex << header->type;
        LOG(DEBUG) << "msg->flags: " << std::hex << header->flags;
        LOG(DEBUG) << "msg->sector: " << std::hex << header->sector;
        LOG(DEBUG) << "msg->len: " << std::hex << header->len;

        switch (header->type) {
            case DM_USER_MAP_READ: {
                size_t remaining_size = header->len;
                loff_t offset = 0;
                header->io_in_progress = 0;
                ret = 0;
                do {
                    size_t read_size = std::min(PAYLOAD_SIZE, remaining_size);

                    // Request to sector 0 is always for kernel
                    // representation of COW header. This IO should be only
                    // once during dm-snapshot device creation. We should
                    // never see multiple IO requests. Additionally this IO
                    // will always be a single 4k.
                    if (header->sector == 0) {
                        // Read the metadata from internal COW device
                        // and build the in-memory data structures
                        // for all the operations in the internal COW.
                        if (!metadata_read_done_ && ReadMetadata()) {
                            LOG(ERROR) << "Metadata read failed";
                            return 1;
                        }
                        metadata_read_done_ = true;

                        CHECK(read_size == BLOCK_SIZE);
                        ret = ConstructKernelCowHeader();
                        if (ret < 0) return ret;
                    } else {
                        // Convert the sector number to a chunk ID.
                        //
                        // Check if the chunk ID represents a metadata
                        // page. If the chunk ID is not found in the
                        // vector, then it points to a metadata page.
                        chunk_t chunk = (header->sector >> CHUNK_SHIFT);

                        if (chunk >= chunk_vec_.size()) {
                            ret = ZerofillDiskExceptions(read_size);
                            if (ret < 0) {
                                LOG(ERROR) << "ZerofillDiskExceptions failed";
                                return ret;
                            }
                        } else if (chunk_vec_[chunk] == nullptr) {
                            ret = ReadDiskExceptions(chunk, read_size);
                            if (ret < 0) {
                                LOG(ERROR) << "ReadDiskExceptions failed";
                                return ret;
                            }
                        } else {
                            chunk_t num_chunks_read = (offset >> BLOCK_SHIFT);
                            ret = ReadData(chunk + num_chunks_read, read_size);
                            if (ret < 0) {
                                LOG(ERROR) << "ReadData failed";
                                return ret;
                            }
                        }
                    }

                    ssize_t written = WriteDmUserPayload(ret);
                    if (written < 0) return written;

                    remaining_size -= ret;
                    offset += ret;
                    if (remaining_size) {
                        LOG(DEBUG) << "Write done ret: " << ret
                                   << " remaining size: " << remaining_size;
                        bufsink_.GetHeaderPtr()->io_in_progress = 1;
                    }
                } while (remaining_size);

                break;
            }

            case DM_USER_MAP_WRITE: {
                // TODO: After merge operation is completed, kernel issues write
                // to flush all the exception mappings where the merge is
                // completed. If dm-user routes the WRITE IO, we need to clear
                // in-memory data structures representing those exception
                // mappings.
                abort();
                break;
            }
        }

        LOG(DEBUG) << "read() finished, next message";
    }

    return 0;
}

}  // namespace snapshot
}  // namespace android

void run_thread(std::string cow_device, std::string backing_device) {
    android::snapshot::Snapuserd snapd(cow_device, backing_device);
    snapd.Run();
}

int main([[maybe_unused]] int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);

    android::snapshot::Daemon& daemon = android::snapshot::Daemon::Instance();

    while (daemon.IsRunning()) {
        // TODO: This is hardcoded wherein:
        // argv[1] = system_cow, argv[2] = /dev/block/mapper/system_a
        // argv[3] = product_cow, argv[4] = /dev/block/mapper/product_a
        //
        // This should be fixed based on some kind of IPC or setup a
        // command socket and spin up the thread based when a new
        // partition is visible.
        std::thread system_a(run_thread, argv[1], argv[2]);
        std::thread product_a(run_thread, argv[3], argv[4]);

        system_a.join();
        product_a.join();
    }

    return 0;
}
