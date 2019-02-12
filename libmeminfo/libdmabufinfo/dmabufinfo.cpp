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

#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <procinfo/process_map.h>

#include <dmabufinfo/dmabufinfo.h>

namespace android {
namespace dmabufinfo {

static bool FileIsDmaBuf(const std::string& path) {
    return ::android::base::StartsWith(path, "/dmabuf");
}

static bool ReadDmaBufFdInfo(pid_t pid, int fd, std::string* name, std::string* exporter,
                             uint64_t* count) {
    std::string fdinfo = ::android::base::StringPrintf("/proc/%d/fdinfo/%d", pid, fd);
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(fdinfo.c_str(), "re"), fclose};
    if (fp == nullptr) {
        LOG(ERROR) << "Failed to open dmabuf info from debugfs";
        return false;
    }

    char* line = nullptr;
    size_t len = 0;
    while (getline(&line, &len, fp.get()) > 0) {
        switch (line[0]) {
            case 'c':
                if (strncmp(line, "count:", 6) == 0) {
                    char* c = line + 6;
                    *count = strtoull(c, nullptr, 10);
                }
                break;
            case 'e':
                if (strncmp(line, "exp_name:", 9) == 0) {
                    char* c = line + 9;
                    *exporter = ::android::base::Trim(c);
                }
                break;
            case 'n':
                if (strncmp(line, "name:", 5) == 0) {
                    char* c = line + 5;
                    *name = ::android::base::Trim(std::string(c));
                }
                break;
        }
    }

    free(line);
    return true;
}

// TODO: std::filesystem::is_symlink fails to link on vendor code,
// forcing this workaround.
// Move back to libc++fs once it is vendor-available. See b/124012728
static bool is_symlink(const char *filename)
{
    struct stat p_statbuf;
    if (lstat(filename, &p_statbuf) < 0) {
        return false;
    }
    if (S_ISLNK(p_statbuf.st_mode) == 1) {
        return true;
    }
    return false;
}

static bool ReadDmaBufFdRefs(pid_t pid, std::vector<DmaBuffer>* dmabufs) {
    std::string fdpath = ::android::base::StringPrintf("/proc/%d/fd", pid);

    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(fdpath.c_str()), closedir);
    if (!dir) {
        LOG(ERROR) << "Failed to open " << fdpath << " directory" << std::endl;
        return false;
    }
    struct dirent* dent;
    while ((dent = readdir(dir.get()))) {
        std::string path =
            ::android::base::StringPrintf("%s/%s", fdpath.c_str(), dent->d_name);

        if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..") ||
            !is_symlink(path.c_str())) {
            continue;
        }

        std::string target;
        if (!::android::base::Readlink(path, &target)) {
            LOG(ERROR) << "Failed to find target for symlink: " << path;
            return false;
        }

        if (!FileIsDmaBuf(target)) {
            continue;
        }

        int fd;
        if (!::android::base::ParseInt(dent->d_name, &fd)) {
            LOG(ERROR) << "Dmabuf fd: " << path << " is invalid";
            return false;
        }

        // Set defaults in case the kernel doesn't give us the information
        // we need in fdinfo
        std::string name = "<unknown>";
        std::string exporter = "<unknown>";
        uint64_t count = 0;
        if (!ReadDmaBufFdInfo(pid, fd, &name, &exporter, &count)) {
            LOG(ERROR) << "Failed to read fdinfo for: " << path;
            return false;
        }

        struct stat sb;
        if (stat(path.c_str(), &sb) < 0) {
            PLOG(ERROR) << "Failed to stat: " << path;
            return false;
        }

        uint64_t inode = sb.st_ino;
        auto buf = std::find_if(dmabufs->begin(), dmabufs->end(),
                                [&inode](const DmaBuffer& dbuf) { return dbuf.inode() == inode; });
        if (buf != dmabufs->end()) {
            if (buf->name() == "" || buf->name() == "<unknown>")
                buf->SetName(name);
            if (buf->exporter() == "" || buf->exporter() == "<unknown>")
                buf->SetExporter(exporter);
            if (buf->count() == 0)
                buf->SetCount(count);
            buf->AddFdRef(pid);
            continue;
        }

        DmaBuffer& db =
                dmabufs->emplace_back(sb.st_ino, sb.st_blocks * 512, count, exporter, name);
        db.AddFdRef(pid);
    }

    return true;
}

static bool ReadDmaBufMapRefs(pid_t pid, std::vector<DmaBuffer>* dmabufs) {
    std::string mapspath = ::android::base::StringPrintf("/proc/%d/maps", pid);
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(mapspath.c_str(), "re"), fclose};
    if (fp == nullptr) {
        LOG(ERROR) << "Failed to open maps for pid: " << pid;
        return false;
    }

    char* line = nullptr;
    size_t len = 0;

    // Process the map if it is dmabuf. Add map reference to existing object in 'dmabufs'
    // if it was already found. If it wasn't create a new one and append it to 'dmabufs'
    auto account_dmabuf = [&](uint64_t start, uint64_t end, uint16_t /* flags */,
                              uint64_t /* pgoff */, const char* name) {
        // no need to look into this mapping if it is not dmabuf
        if (!FileIsDmaBuf(std::string(name))) {
            return;
        }

        // TODO (b/123532375) : Add inode number to the callback of ReadMapFileContent.
        //
        // Workaround: we know 'name' points to the name at the end of 'line'.
        // We use that to backtrack and pick up the inode number from the line as well.
        // start    end      flag pgoff    mj:mn inode   name
        // 00400000-00409000 r-xp 00000000 00:00 426998  /dmabuf (deleted)
        const char* p = name;
        p--;
        // skip spaces
        while (p != line && *p == ' ') {
            p--;
        }
        // walk backwards to the beginning of inode number
        while (p != line && isdigit(*p)) {
            p--;
        }
        uint64_t inode = strtoull(p, nullptr, 10);
        auto buf = std::find_if(dmabufs->begin(), dmabufs->end(),
                                [&inode](const DmaBuffer& dbuf) { return dbuf.inode() == inode; });
        if (buf != dmabufs->end()) {
            buf->AddMapRef(pid);
            return;
        }

        // We have a new buffer, but unknown count and name
        DmaBuffer& dbuf = dmabufs->emplace_back(inode, end - start, 0, "<unknown>", "<unknown>");
        dbuf.AddMapRef(pid);
    };

    while (getline(&line, &len, fp.get()) > 0) {
        if (!::android::procinfo::ReadMapFileContent(line, account_dmabuf)) {
            LOG(ERROR) << "Failed t parse maps for pid: " << pid;
            return false;
        }
    }

    free(line);
    return true;
}

// Public methods
bool ReadDmaBufInfo(std::vector<DmaBuffer>* dmabufs, const std::string& path) {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (fp == nullptr) {
        LOG(ERROR) << "Failed to open dmabuf info from debugfs";
        return false;
    }

    char* line = nullptr;
    size_t len = 0;
    dmabufs->clear();
    while (getline(&line, &len, fp.get()) > 0) {
        // The new dmabuf bufinfo format adds inode number and a name at the end
        // We are looking for lines as follows:
        // size     flags       mode        count  exp_name ino         name
        // 01048576 00000002    00000007    00000001    ion 00018758    CAMERA
        // 01048576 00000002    00000007    00000001    ion 00018758
        uint64_t size, count;
        char* exporter_name = nullptr;
        ino_t inode;
        char* name = nullptr;
        int matched = sscanf(line, "%" SCNu64 "%*x %*x %" SCNu64 " %ms %lu %ms", &size, &count,
                             &exporter_name, &inode, &name);
        if (matched < 4) {
            continue;
        }
        dmabufs->emplace_back(inode, size, count, exporter_name, matched > 4 ? name : "");
        free(exporter_name);
        free(name);
    }

    free(line);

    return true;
}

bool ReadDmaBufInfo(pid_t pid, std::vector<DmaBuffer>* dmabufs) {
    dmabufs->clear();
    return AppendDmaBufInfo(pid, dmabufs);
}

bool AppendDmaBufInfo(pid_t pid, std::vector<DmaBuffer>* dmabufs) {
    if (!ReadDmaBufFdRefs(pid, dmabufs)) {
        LOG(ERROR) << "Failed to read dmabuf fd references";
        return false;
    }

    if (!ReadDmaBufMapRefs(pid, dmabufs)) {
        LOG(ERROR) << "Failed to read dmabuf map references";
        return false;
    }
    return true;
}

}  // namespace dmabufinfo
}  // namespace android
