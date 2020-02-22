/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define TRACE_TAG ADB

#include "apk_archive.h"

#include <inttypes.h>

#include "adb_trace.h"
#include "sysdeps.h"

#include <android-base/endian.h>
#include <android-base/mapped_file.h>

#include <openssl/md5.h>

constexpr uint16_t kCompressStored = 0;

// mask value that signifies that the entry has a DD
static const uint32_t kGPBDDFlagMask = 0x0008;

namespace {
struct FileRegion {
    FileRegion(borrowed_fd fd, off64_t offset, size_t length)
        : mapped_(android::base::MappedFile::FromOsHandle(adb_get_os_handle(fd), offset, length,
                                                          PROT_READ)) {
        if (mapped_ != nullptr) {
            return;
        }

        // Mapped file failed, falling back to pread.
        buffer_.resize(length);
        if (auto err = adb_pread(fd.get(), buffer_.data(), length, offset); size_t(err) != length) {
            fprintf(stderr, "Unable to read %lld bytes at offset %" PRId64 " \n",
                    static_cast<long long>(length), offset);
            buffer_.clear();
            return;
        }
    }

    const char* data() const { return mapped_ ? mapped_->data() : buffer_.data(); }
    size_t size() const { return mapped_ ? mapped_->size() : buffer_.size(); }

  private:
    FileRegion() = default;
    DISALLOW_COPY_AND_ASSIGN(FileRegion);

    std::unique_ptr<android::base::MappedFile> mapped_;
    std::string buffer_;
};
}  // namespace

using com::android::fastdeploy::APKDump;

ApkArchive::ApkArchive(const std::string& path) : path_(path), size_(0) {
    fd_.reset(adb_open(path_.c_str(), O_RDONLY));
    if (fd_ == -1) {
        fprintf(stderr, "Unable to open file '%s'\n", path_.c_str());
        return;
    }

    struct stat st;
    if (stat(path_.c_str(), &st) == -1) {
        fprintf(stderr, "Unable to stat file '%s'\n", path_.c_str());
        return;
    }
    size_ = st.st_size;
}

ApkArchive::~ApkArchive() {}

APKDump ApkArchive::ExtractMetadata() {
    D("ExtractMetadata");
    if (!ready()) {
        return {};
    }

    Location cdLoc = GetCDLocation();
    if (!cdLoc.valid) {
        return {};
    }

    APKDump dump;
    dump.set_absolute_path(path_);
    dump.set_cd(ReadMetadata(cdLoc));

    Location sigLoc = GetSignatureLocation(cdLoc.offset);
    if (sigLoc.valid) {
        dump.set_signature(ReadMetadata(sigLoc));
    }
    return dump;
}

off_t ApkArchive::FindEndOfCDRecord() const {
    constexpr int endOfCDSignature = 0x06054b50;
    constexpr off_t endOfCDMinSize = 22;
    constexpr off_t endOfCDMaxSize = 65535 + endOfCDMinSize;

    auto sizeToRead = std::min(size_, endOfCDMaxSize);
    auto readOffset = size_ - sizeToRead;
    FileRegion mapped(fd_, readOffset, sizeToRead);

    // Start scanning from the end
    auto* start = mapped.data();
    auto* cursor = start + mapped.size() - sizeof(endOfCDSignature);

    // Search for End of Central Directory record signature.
    while (cursor >= start) {
        if (*(int32_t*)cursor == endOfCDSignature) {
            return readOffset + (cursor - start);
        }
        cursor--;
    }
    return -1;
}

ApkArchive::Location ApkArchive::FindCDRecord(const char* cursor) {
    struct ecdr_t {
        int32_t signature;
        uint16_t diskNumber;
        uint16_t numDisk;
        uint16_t diskEntries;
        uint16_t numEntries;
        uint32_t crSize;
        uint32_t offsetToCdHeader;
        uint16_t commentSize;
        uint8_t comment[0];
    } __attribute__((packed));
    ecdr_t* header = (ecdr_t*)cursor;

    Location location;
    location.offset = header->offsetToCdHeader;
    location.size = header->crSize;
    location.valid = true;
    return location;
}

ApkArchive::Location ApkArchive::GetCDLocation() {
    constexpr off_t cdEntryHeaderSizeBytes = 22;
    Location location;

    // Find End of Central Directory Record
    off_t eocdRecord = FindEndOfCDRecord();
    if (eocdRecord < 0) {
        fprintf(stderr, "Unable to find End of Central Directory record in file '%s'\n",
                path_.c_str());
        return location;
    }

    // Find Central Directory Record
    FileRegion mapped(fd_, eocdRecord, cdEntryHeaderSizeBytes);
    location = FindCDRecord(mapped.data());
    if (!location.valid) {
        fprintf(stderr, "Unable to find Central Directory File Header in file '%s'\n",
                path_.c_str());
        return location;
    }

    return location;
}

ApkArchive::Location ApkArchive::GetSignatureLocation(off_t cdRecordOffset) {
    Location location;

    // Signature constants.
    constexpr off_t endOfSignatureSize = 24;
    off_t signatureOffset = cdRecordOffset - endOfSignatureSize;
    if (signatureOffset < 0) {
        fprintf(stderr, "Unable to find signature in file '%s'\n", path_.c_str());
        return location;
    }

    FileRegion mapped(fd_, signatureOffset, endOfSignatureSize);

    uint64_t signatureSize = *(uint64_t*)mapped.data();
    auto* signature = mapped.data() + sizeof(signatureSize);
    // Check if there is a v2/v3 Signature block here.
    if (memcmp(signature, "APK Sig Block 42", 16)) {
        return location;
    }

    // This is likely a signature block.
    location.size = signatureSize;
    location.offset = cdRecordOffset - location.size - 8;
    location.valid = true;

    return location;
}

std::string ApkArchive::ReadMetadata(Location loc) const {
    FileRegion mapped(fd_, loc.offset, loc.size);
    return {mapped.data(), mapped.size()};
}

size_t ApkArchive::ParseCentralDirectoryRecord(const char* input, size_t size, std::string* md5Hash,
                                               int64_t* localFileHeaderOffset, int64_t* dataSize) {
    // A structure representing the fixed length fields for a single
    // record in the central directory of the archive. In addition to
    // the fixed length fields listed here, each central directory
    // record contains a variable length "file_name" and "extra_field"
    // whose lengths are given by |file_name_length| and |extra_field_length|
    // respectively.
    static constexpr int kCDFileHeaderMagic = 0x02014b50;
    struct CentralDirectoryRecord {
        // The start of record signature. Must be |kSignature|.
        uint32_t record_signature;
        // Source tool version. Top byte gives source OS.
        uint16_t version_made_by;
        // Tool version. Ignored by this implementation.
        uint16_t version_needed;
        // The "general purpose bit flags" for this entry. The only
        // flag value that we currently check for is the "data descriptor"
        // flag.
        uint16_t gpb_flags;
        // The compression method for this entry, one of |kCompressStored|
        // and |kCompressDeflated|.
        uint16_t compression_method;
        // The file modification time and date for this entry.
        uint16_t last_mod_time;
        uint16_t last_mod_date;
        // The CRC-32 checksum for this entry.
        uint32_t crc32;
        // The compressed size (in bytes) of this entry.
        uint32_t compressed_size;
        // The uncompressed size (in bytes) of this entry.
        uint32_t uncompressed_size;
        // The length of the entry file name in bytes. The file name
        // will appear immediately after this record.
        uint16_t file_name_length;
        // The length of the extra field info (in bytes). This data
        // will appear immediately after the entry file name.
        uint16_t extra_field_length;
        // The length of the entry comment (in bytes). This data will
        // appear immediately after the extra field.
        uint16_t comment_length;
        // The start disk for this entry. Ignored by this implementation).
        uint16_t file_start_disk;
        // File attributes. Ignored by this implementation.
        uint16_t internal_file_attributes;
        // File attributes. For archives created on Unix, the top bits are the
        // mode.
        uint32_t external_file_attributes;
        // The offset to the local file header for this entry, from the
        // beginning of this archive.
        uint32_t local_file_header_offset;

      private:
        CentralDirectoryRecord() = default;
        DISALLOW_COPY_AND_ASSIGN(CentralDirectoryRecord);
    } __attribute__((packed));

    const CentralDirectoryRecord* cdr;
    if (size < sizeof(*cdr)) {
        return 0;
    }

    auto begin = input;
    cdr = reinterpret_cast<const CentralDirectoryRecord*>(begin);
    if (cdr->record_signature != kCDFileHeaderMagic) {
        fprintf(stderr, "Invalid Central Directory Record signature\n");
        return 0;
    }
    auto end = begin + sizeof(*cdr) + cdr->file_name_length + cdr->extra_field_length +
               cdr->comment_length;

    uint8_t md5Digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)begin, end - begin, md5Digest);
    md5Hash->assign((const char*)md5Digest, sizeof(md5Digest));

    *localFileHeaderOffset = cdr->local_file_header_offset;
    *dataSize = (cdr->compression_method == kCompressStored) ? cdr->uncompressed_size
                                                             : cdr->compressed_size;

    return end - begin;
}

size_t ApkArchive::CalculateLocalFileEntrySize(int64_t localFileHeaderOffset,
                                               int64_t dataSize) const {
    // The local file header for a given entry. This duplicates information
    // present in the central directory of the archive. It is an error for
    // the information here to be different from the central directory
    // information for a given entry.
    static constexpr int kLocalFileHeaderMagic = 0x04034b50;
    struct LocalFileHeader {
        // The local file header signature, must be |kSignature|.
        uint32_t lfh_signature;
        // Tool version. Ignored by this implementation.
        uint16_t version_needed;
        // The "general purpose bit flags" for this entry. The only
        // flag value that we currently check for is the "data descriptor"
        // flag.
        uint16_t gpb_flags;
        // The compression method for this entry, one of |kCompressStored|
        // and |kCompressDeflated|.
        uint16_t compression_method;
        // The file modification time and date for this entry.
        uint16_t last_mod_time;
        uint16_t last_mod_date;
        // The CRC-32 checksum for this entry.
        uint32_t crc32;
        // The compressed size (in bytes) of this entry.
        uint32_t compressed_size;
        // The uncompressed size (in bytes) of this entry.
        uint32_t uncompressed_size;
        // The length of the entry file name in bytes. The file name
        // will appear immediately after this record.
        uint16_t file_name_length;
        // The length of the extra field info (in bytes). This data
        // will appear immediately after the entry file name.
        uint16_t extra_field_length;

      private:
        LocalFileHeader() = default;
        DISALLOW_COPY_AND_ASSIGN(LocalFileHeader);
    } __attribute__((packed));
    static constexpr int kLocalFileHeaderSize = sizeof(LocalFileHeader);
    CHECK(ready()) << path_;

    const LocalFileHeader* lfh;
    if (localFileHeaderOffset + kLocalFileHeaderSize > size_) {
        fprintf(stderr,
                "Invalid Local File Header offset in file '%s' at offset %lld, file size %lld\n",
                path_.c_str(), static_cast<long long>(localFileHeaderOffset),
                static_cast<long long>(size_));
        return 0;
    }

    FileRegion lfhMapped(fd_, localFileHeaderOffset, sizeof(LocalFileHeader));
    lfh = reinterpret_cast<const LocalFileHeader*>(lfhMapped.data());
    if (lfh->lfh_signature != kLocalFileHeaderMagic) {
        fprintf(stderr, "Invalid Local File Header signature in file '%s' at offset %lld\n",
                path_.c_str(), static_cast<long long>(localFileHeaderOffset));
        return 0;
    }

    // The *optional* data descriptor start signature.
    static constexpr int kOptionalDataDescriptorMagic = 0x08074b50;
    struct DataDescriptor {
        // CRC-32 checksum of the entry.
        uint32_t crc32;
        // Compressed size of the entry.
        uint32_t compressed_size;
        // Uncompressed size of the entry.
        uint32_t uncompressed_size;

      private:
        DataDescriptor() = default;
        DISALLOW_COPY_AND_ASSIGN(DataDescriptor);
    } __attribute__((packed));
    static constexpr int kDataDescriptorSize = sizeof(DataDescriptor);

    off_t ddOffset = localFileHeaderOffset + kLocalFileHeaderSize + lfh->file_name_length +
                     lfh->extra_field_length + dataSize;
    int64_t ddSize = 0;

    int64_t localDataSize;
    if (lfh->gpb_flags & kGPBDDFlagMask) {
        // There is trailing data descriptor.
        const DataDescriptor* dd;

        if (ddOffset + int(sizeof(uint32_t)) > size_) {
            fprintf(stderr,
                    "Error reading trailing data descriptor signature in file '%s' at offset %lld, "
                    "file size %lld\n",
                    path_.c_str(), static_cast<long long>(ddOffset), static_cast<long long>(size_));
            return 0;
        }

        FileRegion ddMapped(fd_, ddOffset, sizeof(uint32_t) + sizeof(DataDescriptor));

        off_t localDDOffset = 0;
        if (kOptionalDataDescriptorMagic == *(uint32_t*)ddMapped.data()) {
            ddOffset += sizeof(uint32_t);
            localDDOffset += sizeof(uint32_t);
            ddSize += sizeof(uint32_t);
        }
        if (ddOffset + kDataDescriptorSize > size_) {
            fprintf(stderr,
                    "Error reading trailing data descriptor in file '%s' at offset %lld, file size "
                    "%lld\n",
                    path_.c_str(), static_cast<long long>(ddOffset), static_cast<long long>(size_));
            return 0;
        }

        dd = reinterpret_cast<const DataDescriptor*>(ddMapped.data() + localDDOffset);
        localDataSize = (lfh->compression_method == kCompressStored) ? dd->uncompressed_size
                                                                     : dd->compressed_size;
        ddSize += sizeof(*dd);
    } else {
        localDataSize = (lfh->compression_method == kCompressStored) ? lfh->uncompressed_size
                                                                     : lfh->compressed_size;
    }
    if (localDataSize != dataSize) {
        fprintf(stderr,
                "Data sizes mismatch in file '%s' at offset %lld, CDr: %lld vs LHR/DD: %lld\n",
                path_.c_str(), static_cast<long long>(localFileHeaderOffset),
                static_cast<long long>(dataSize), static_cast<long long>(localDataSize));
        return 0;
    }

    return kLocalFileHeaderSize + lfh->file_name_length + lfh->extra_field_length + dataSize +
           ddSize;
}
