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

#include <libfiemap/split_fiemap_writer.h>

#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "utility.h"

namespace android {
namespace fiemap {

using android::base::unique_fd;

// We use a four-digit suffix at the end of filenames.
static const size_t kMaxFilePieces = 500;

std::unique_ptr<SplitFiemap> SplitFiemap::Create(const std::string& file_path, uint64_t file_size,
                                                 uint64_t max_piece_size,
                                                 ProgressCallback progress) {
    std::unique_ptr<SplitFiemap> ret;
    if (!Create(file_path, file_size, max_piece_size, &ret, progress).is_ok()) {
        return nullptr;
    }
    return ret;
}

FiemapStatus SplitFiemap::Create(const std::string& file_path, uint64_t file_size,
                                 uint64_t max_piece_size, std::unique_ptr<SplitFiemap>* out_val,
                                 ProgressCallback progress) {
    out_val->reset();

    if (!file_size) {
        LOG(ERROR) << "Cannot create a fiemap for a 0-length file: " << file_path;
        return FiemapStatus::Error();
    }

    if (!max_piece_size) {
        auto status = DetermineMaximumFileSize(file_path, &max_piece_size);
        if (!status.is_ok()) {
            LOG(ERROR) << "Could not determine maximum file size for " << file_path;
            return status;
        }
    }

    // Remove any existing file.
    RemoveSplitFiles(file_path);

    // Call |progress| only when the total percentage would significantly change.
    int permille = -1;
    uint64_t total_bytes_written = 0;
    auto on_progress = [&](uint64_t written, uint64_t) -> bool {
        uint64_t actual_written = total_bytes_written + written;
        int new_permille = (actual_written * 1000) / file_size;
        if (new_permille != permille && actual_written < file_size) {
            if (progress && !progress(actual_written, file_size)) {
                return false;
            }
            permille = new_permille;
        }
        return true;
    };
    std::unique_ptr<SplitFiemap> out(new SplitFiemap());
    out->creating_ = true;
    out->list_file_ = file_path;

    // Create the split files.
    uint64_t remaining_bytes = file_size;
    while (remaining_bytes) {
        if (out->files_.size() >= kMaxFilePieces) {
            LOG(ERROR) << "Requested size " << file_size << " created too many split files";
            out.reset();
            return FiemapStatus::Error();
        }
        std::string chunk_path =
                android::base::StringPrintf("%s.%04d", file_path.c_str(), (int)out->files_.size());
        uint64_t chunk_size = std::min(max_piece_size, remaining_bytes);
        FiemapUniquePtr writer;
        auto status = FiemapWriter::Open(chunk_path, chunk_size, &writer, true, on_progress);
        if (!status.is_ok()) {
            out.reset();
            return status;
        }

        // To make sure the alignment doesn't create too much inconsistency, we
        // account the *actual* size, not the requested size.
        total_bytes_written += writer->size();

        // writer->size() is block size aligned and could be bigger than remaining_bytes
        // If remaining_bytes is bigger, set remaining_bytes to 0 to avoid underflow error.
        remaining_bytes = remaining_bytes > writer->size() ? (remaining_bytes - writer->size()) : 0;

        out->AddFile(std::move(writer));
    }

    // Create the split file list.
    unique_fd fd(open(out->list_file_.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0660));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open " << file_path;
        out.reset();
        return FiemapStatus::FromErrno(errno);
    }

    for (const auto& writer : out->files_) {
        std::string line = android::base::Basename(writer->file_path()) + "\n";
        if (!android::base::WriteFully(fd, line.data(), line.size())) {
            PLOG(ERROR) << "Write failed " << file_path;
            out.reset();
            return FiemapStatus::FromErrno(errno);
        }
    }

    // Unset this bit, so we don't unlink on destruction.
    out->creating_ = false;
    *out_val = std::move(out);
    return FiemapStatus::Ok();
}

std::unique_ptr<SplitFiemap> SplitFiemap::Open(const std::string& file_path) {
    std::vector<std::string> files;
    if (!GetSplitFileList(file_path, &files)) {
        return nullptr;
    }

    std::unique_ptr<SplitFiemap> out(new SplitFiemap());
    out->list_file_ = file_path;

    for (const auto& file : files) {
        auto writer = FiemapWriter::Open(file, 0, false);
        if (!writer) {
            // Error was logged in Open().
            return nullptr;
        }
        out->AddFile(std::move(writer));
    }
    return out;
}

bool SplitFiemap::GetSplitFileList(const std::string& file_path, std::vector<std::string>* list) {
    // This is not the most efficient thing, but it is simple and recovering
    // the fiemap/fibmap is much more expensive.
    std::string contents;
    if (!android::base::ReadFileToString(file_path, &contents, true)) {
        PLOG(ERROR) << "Error reading file: " << file_path;
        return false;
    }

    std::vector<std::string> names = android::base::Split(contents, "\n");
    std::string dir = android::base::Dirname(file_path);
    for (const auto& name : names) {
        if (!name.empty()) {
            list->emplace_back(dir + "/" + name);
        }
    }
    return true;
}

bool SplitFiemap::RemoveSplitFiles(const std::string& file_path, std::string* message) {
    // Early exit if this does not exist, and do not report an error.
    if (access(file_path.c_str(), F_OK) && errno == ENOENT) {
        return true;
    }

    bool ok = true;
    std::vector<std::string> files;
    if (GetSplitFileList(file_path, &files)) {
        for (const auto& file : files) {
            ok &= android::base::RemoveFileIfExists(file, message);
        }
    }
    ok &= android::base::RemoveFileIfExists(file_path, message);
    return ok;
}

bool SplitFiemap::HasPinnedExtents() const {
    for (const auto& file : files_) {
        if (!FiemapWriter::HasPinnedExtents(file->file_path())) {
            return false;
        }
    }
    return true;
}

const std::vector<struct fiemap_extent>& SplitFiemap::extents() {
    if (extents_.empty()) {
        for (const auto& file : files_) {
            const auto& extents = file->extents();
            extents_.insert(extents_.end(), extents.begin(), extents.end());
        }
    }
    return extents_;
}

bool SplitFiemap::Write(const void* data, uint64_t bytes) {
    // Open the current file.
    FiemapWriter* file = files_[cursor_index_].get();

    const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(data);
    uint64_t bytes_remaining = bytes;
    while (bytes_remaining) {
        // How many bytes can we write into the current file?
        uint64_t file_bytes_left = file->size() - cursor_file_pos_;
        if (!file_bytes_left) {
            if (cursor_index_ == files_.size() - 1) {
                LOG(ERROR) << "write past end of file requested";
                return false;
            }

            // No space left in the current file, but we have more files to
            // use, so prep the next one.
            cursor_fd_ = {};
            cursor_file_pos_ = 0;
            file = files_[++cursor_index_].get();
            file_bytes_left = file->size();
        }

        // Open the current file if it's not open.
        if (cursor_fd_ < 0) {
            cursor_fd_.reset(open(file->file_path().c_str(), O_CLOEXEC | O_WRONLY));
            if (cursor_fd_ < 0) {
                PLOG(ERROR) << "open failed: " << file->file_path();
                return false;
            }
            CHECK(cursor_file_pos_ == 0);
        }

        if (!FiemapWriter::HasPinnedExtents(file->file_path())) {
            LOG(ERROR) << "file is no longer pinned: " << file->file_path();
            return false;
        }

        uint64_t bytes_to_write = std::min(file_bytes_left, bytes_remaining);
        if (!android::base::WriteFully(cursor_fd_, data_ptr, bytes_to_write)) {
            PLOG(ERROR) << "write failed: " << file->file_path();
            return false;
        }
        data_ptr += bytes_to_write;
        bytes_remaining -= bytes_to_write;
        cursor_file_pos_ += bytes_to_write;
    }

    // If we've reached the end of the current file, close it for sanity.
    if (cursor_file_pos_ == file->size()) {
        cursor_fd_ = {};
    }
    return true;
}

bool SplitFiemap::Flush() {
    for (const auto& file : files_) {
        unique_fd fd(open(file->file_path().c_str(), O_RDONLY | O_CLOEXEC));
        if (fd < 0) {
            PLOG(ERROR) << "open failed: " << file->file_path();
            return false;
        }
        if (fsync(fd)) {
            PLOG(ERROR) << "fsync failed: " << file->file_path();
            return false;
        }
    }
    return true;
}

SplitFiemap::~SplitFiemap() {
    if (!creating_) {
        return;
    }

    // We failed to finish creating, so unlink everything.
    unlink(list_file_.c_str());
    for (auto&& file : files_) {
        std::string path = file->file_path();
        file = nullptr;

        unlink(path.c_str());
    }
}

void SplitFiemap::AddFile(FiemapUniquePtr&& file) {
    total_size_ += file->size();
    files_.emplace_back(std::move(file));
}

uint32_t SplitFiemap::block_size() const {
    return files_[0]->block_size();
}

const std::string& SplitFiemap::bdev_path() const {
    return files_[0]->bdev_path();
}

}  // namespace fiemap
}  // namespace android
