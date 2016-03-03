/*
 * Copyright (C) 2007 The Android Open Source Project
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
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include <functional>
#include <memory>
#include <vector>

#include "sysdeps.h"

#include "adb.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "file_sync_service.h"
#include "line_printer.h"

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>

struct syncsendbuf {
    unsigned id;
    unsigned size;
    char data[SYNC_DATA_MAX];
};

static void ensure_trailing_separators(std::string& local_path, std::string& remote_path) {
    if (!adb_is_separator(local_path.back())) {
        local_path.push_back(OS_PATH_SEPARATOR);
    }
    if (remote_path.back() != '/') {
        remote_path.push_back('/');
    }
}

static bool should_pull_file(mode_t mode) {
    return mode & (S_IFREG | S_IFBLK | S_IFCHR);
}

static bool should_push_file(mode_t mode) {
    mode_t mask = S_IFREG;
#if !defined(_WIN32)
    mask |= S_IFLNK;
#endif
    return mode & mask;
}

struct copyinfo {
    std::string lpath;
    std::string rpath;
    unsigned int time = 0;
    unsigned int mode;
    uint64_t size = 0;
    bool skip = false;

    copyinfo(const std::string& local_path,
             const std::string& remote_path,
             const std::string& name,
             unsigned int mode)
            : lpath(local_path), rpath(remote_path), mode(mode) {
        ensure_trailing_separators(lpath, rpath);
        lpath.append(name);
        rpath.append(name);
        if (S_ISDIR(mode)) {
            ensure_trailing_separators(lpath, rpath);
        }
    }
};

class SyncConnection {
  public:
    SyncConnection()
            : total_bytes_(0),
              start_time_ms_(CurrentTimeMs()),
              expected_total_bytes_(0),
              expect_multiple_files_(false),
              expect_done_(false) {
        max = SYNC_DATA_MAX; // TODO: decide at runtime.

        std::string error;
        fd = adb_connect("sync:", &error);
        if (fd < 0) {
            Error("connect failed: %s", error.c_str());
        }
    }

    ~SyncConnection() {
        if (!IsValid()) return;

        if (SendQuit()) {
            // We sent a quit command, so the server should be doing orderly
            // shutdown soon. But if we encountered an error while we were using
            // the connection, the server might still be sending data (before
            // doing orderly shutdown), in which case we won't wait for all of
            // the data nor the coming orderly shutdown. In the common success
            // case, this will wait for the server to do orderly shutdown.
            ReadOrderlyShutdown(fd);
        }
        adb_close(fd);

        line_printer_.KeepInfoLine();
    }

    bool IsValid() { return fd >= 0; }

    bool ReceivedError(const char* from, const char* to) {
        adb_pollfd pfd = {.fd = fd, .events = POLLIN};
        int rc = adb_poll(&pfd, 1, 0);
        if (rc < 0) {
            Error("failed to poll: %s", strerror(errno));
            return true;
        }
        return rc != 0;
    }

    bool SendRequest(int id, const char* path_and_mode) {
        size_t path_length = strlen(path_and_mode);
        if (path_length > 1024) {
            Error("SendRequest failed: path too long: %zu", path_length);
            errno = ENAMETOOLONG;
            return false;
        }

        // Sending header and payload in a single write makes a noticeable
        // difference to "adb sync" performance.
        std::vector<char> buf(sizeof(SyncRequest) + path_length);
        SyncRequest* req = reinterpret_cast<SyncRequest*>(&buf[0]);
        req->id = id;
        req->path_length = path_length;
        char* data = reinterpret_cast<char*>(req + 1);
        memcpy(data, path_and_mode, path_length);

        return WriteFdExactly(fd, &buf[0], buf.size());
    }

    // Sending header, payload, and footer in a single write makes a huge
    // difference to "adb sync" performance.
    bool SendSmallFile(const char* path_and_mode,
                       const char* lpath, const char* rpath,
                       unsigned mtime,
                       const char* data, size_t data_length) {
        size_t path_length = strlen(path_and_mode);
        if (path_length > 1024) {
            Error("SendSmallFile failed: path too long: %zu", path_length);
            errno = ENAMETOOLONG;
            return false;
        }

        std::vector<char> buf(sizeof(SyncRequest) + path_length +
                              sizeof(SyncRequest) + data_length +
                              sizeof(SyncRequest));
        char* p = &buf[0];

        SyncRequest* req_send = reinterpret_cast<SyncRequest*>(p);
        req_send->id = ID_SEND;
        req_send->path_length = path_length;
        p += sizeof(SyncRequest);
        memcpy(p, path_and_mode, path_length);
        p += path_length;

        SyncRequest* req_data = reinterpret_cast<SyncRequest*>(p);
        req_data->id = ID_DATA;
        req_data->path_length = data_length;
        p += sizeof(SyncRequest);
        memcpy(p, data, data_length);
        p += data_length;

        SyncRequest* req_done = reinterpret_cast<SyncRequest*>(p);
        req_done->id = ID_DONE;
        req_done->path_length = mtime;
        p += sizeof(SyncRequest);

        WriteOrDie(lpath, rpath, &buf[0], (p - &buf[0]));
        expect_done_ = true;
        total_bytes_ += data_length;
        ReportProgress(rpath, data_length, data_length);
        return true;
    }

    bool SendLargeFile(const char* path_and_mode,
                       const char* lpath, const char* rpath,
                       unsigned mtime) {
        if (!SendRequest(ID_SEND, path_and_mode)) {
            Error("failed to send ID_SEND message '%s': %s", path_and_mode, strerror(errno));
            return false;
        }

        struct stat st;
        if (stat(lpath, &st) == -1) {
            Error("cannot stat '%s': %s", lpath, strerror(errno));
            return false;
        }

        uint64_t total_size = st.st_size;
        uint64_t bytes_copied = 0;

        int lfd = adb_open(lpath, O_RDONLY);
        if (lfd < 0) {
            Error("opening '%s' locally failed: %s", lpath, strerror(errno));
            return false;
        }

        syncsendbuf sbuf;
        sbuf.id = ID_DATA;
        while (true) {
            int bytes_read = adb_read(lfd, sbuf.data, max);
            if (bytes_read == -1) {
                Error("reading '%s' locally failed: %s", lpath, strerror(errno));
                adb_close(lfd);
                return false;
            } else if (bytes_read == 0) {
                break;
            }

            sbuf.size = bytes_read;
            WriteOrDie(lpath, rpath, &sbuf, sizeof(SyncRequest) + bytes_read);

            total_bytes_ += bytes_read;
            bytes_copied += bytes_read;

            // Check to see if we've received an error from the other side.
            if (ReceivedError(lpath, rpath)) {
                break;
            }

            ReportProgress(rpath, bytes_copied, total_size);
        }

        adb_close(lfd);

        syncmsg msg;
        msg.data.id = ID_DONE;
        msg.data.size = mtime;
        expect_done_ = true;
        return WriteOrDie(lpath, rpath, &msg.data, sizeof(msg.data));
    }

    bool CopyDone(const char* from, const char* to) {
        syncmsg msg;
        if (!ReadFdExactly(fd, &msg.status, sizeof(msg.status))) {
            Error("failed to copy '%s' to '%s': couldn't read from device", from, to);
            return false;
        }
        if (msg.status.id == ID_OKAY) {
            if (expect_done_) {
                expect_done_ = false;
                return true;
            } else {
                Error("failed to copy '%s' to '%s': received premature success", from, to);
                return true;
            }
        }
        if (msg.status.id != ID_FAIL) {
            Error("failed to copy '%s' to '%s': unknown reason %d", from, to, msg.status.id);
            return false;
        }
        return ReportCopyFailure(from, to, msg);
    }

    bool ReportCopyFailure(const char* from, const char* to, const syncmsg& msg) {
        std::vector<char> buf(msg.status.msglen + 1);
        if (!ReadFdExactly(fd, &buf[0], msg.status.msglen)) {
            Error("failed to copy '%s' to '%s'; failed to read reason (!): %s",
                  from, to, strerror(errno));
            return false;
        }
        buf[msg.status.msglen] = 0;
        Error("failed to copy '%s' to '%s': %s", from, to, &buf[0]);
        return false;
    }

    std::string TransferRate() {
        uint64_t ms = CurrentTimeMs() - start_time_ms_;
        if (total_bytes_ == 0 || ms == 0) return "";

        double s = static_cast<double>(ms) / 1000LL;
        double rate = (static_cast<double>(total_bytes_) / s) / (1024*1024);
        return android::base::StringPrintf(" %.1f MB/s (%" PRId64 " bytes in %.3fs)",
                                           rate, total_bytes_, s);
    }

    void ReportProgress(const char* file, uint64_t file_copied_bytes, uint64_t file_total_bytes) {
        char overall_percentage_str[5] = "?";
        if (expected_total_bytes_ != 0) {
            int overall_percentage = static_cast<int>(total_bytes_ * 100 / expected_total_bytes_);
            // If we're pulling symbolic links, we'll pull the target of the link rather than
            // just create a local link, and that will cause us to go over 100%.
            if (overall_percentage <= 100) {
                snprintf(overall_percentage_str, sizeof(overall_percentage_str), "%d%%",
                         overall_percentage);
            }
        }

        if (file_copied_bytes > file_total_bytes || file_total_bytes == 0) {
            // This case can happen if we're racing against something that wrote to the file
            // between our stat and our read, or if we're reading a magic file that lies about
            // its size. Just show how much we've copied.
            Printf("[%4s] %s: %" PRId64 "/?", overall_percentage_str, file, file_copied_bytes);
        } else {
            // If we're transferring multiple files, we want to know how far through the current
            // file we are, as well as the overall percentage.
            if (expect_multiple_files_) {
                int file_percentage = static_cast<int>(file_copied_bytes * 100 / file_total_bytes);
                Printf("[%4s] %s: %d%%", overall_percentage_str, file, file_percentage);
            } else {
                Printf("[%4s] %s", overall_percentage_str, file);
            }
        }
    }

    void Printf(const char* fmt, ...) __attribute__((__format__(ADB_FORMAT_ARCHETYPE, 2, 3))) {
        std::string s;

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::INFO);
    }

    void Error(const char* fmt, ...) __attribute__((__format__(ADB_FORMAT_ARCHETYPE, 2, 3))) {
        std::string s = "adb: error: ";

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::ERROR);
    }

    void Warning(const char* fmt, ...) __attribute__((__format__(ADB_FORMAT_ARCHETYPE, 2, 3))) {
        std::string s = "adb: warning: ";

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::WARNING);
    }

    void ComputeExpectedTotalBytes(const std::vector<copyinfo>& file_list) {
        expected_total_bytes_ = 0;
        for (const copyinfo& ci : file_list) {
            // Unfortunately, this doesn't work for symbolic links, because we'll copy the
            // target of the link rather than just creating a link. (But ci.size is the link size.)
            if (!ci.skip) expected_total_bytes_ += ci.size;
        }
        expect_multiple_files_ = true;
    }

    void SetExpectedTotalBytes(uint64_t expected_total_bytes) {
        expected_total_bytes_ = expected_total_bytes;
        expect_multiple_files_ = false;
    }

    uint64_t total_bytes_;

    // TODO: add a char[max] buffer here, to replace syncsendbuf...
    int fd;
    size_t max;

  private:
    uint64_t start_time_ms_;

    uint64_t expected_total_bytes_;
    bool expect_multiple_files_;
    bool expect_done_;

    LinePrinter line_printer_;

    bool SendQuit() {
        return SendRequest(ID_QUIT, ""); // TODO: add a SendResponse?
    }

    bool WriteOrDie(const char* from, const char* to, const void* data, size_t data_length) {
        if (!WriteFdExactly(fd, data, data_length)) {
            if (errno == ECONNRESET) {
                // Assume adbd told us why it was closing the connection, and
                // try to read failure reason from adbd.
                syncmsg msg;
                if (!ReadFdExactly(fd, &msg.status, sizeof(msg.status))) {
                    Error("failed to copy '%s' to '%s': no response: %s", from, to, strerror(errno));
                } else if (msg.status.id != ID_FAIL) {
                    Error("failed to copy '%s' to '%s': not ID_FAIL: %d", from, to, msg.status.id);
                } else {
                    ReportCopyFailure(from, to, msg);
                }
            } else {
                Error("%zu-byte write failed: %s", data_length, strerror(errno));
            }
            _exit(1);
        }
        return true;
    }

    static uint64_t CurrentTimeMs() {
        struct timeval tv;
        gettimeofday(&tv, 0); // (Not clock_gettime because of Mac/Windows.)
        return static_cast<uint64_t>(tv.tv_sec) * 1000 + tv.tv_usec / 1000;
    }
};

typedef void (sync_ls_cb)(unsigned mode, unsigned size, unsigned time, const char* name);

static bool sync_ls(SyncConnection& sc, const char* path,
                    std::function<sync_ls_cb> func) {
    if (!sc.SendRequest(ID_LIST, path)) return false;

    while (true) {
        syncmsg msg;
        if (!ReadFdExactly(sc.fd, &msg.dent, sizeof(msg.dent))) return false;

        if (msg.dent.id == ID_DONE) return true;
        if (msg.dent.id != ID_DENT) return false;

        size_t len = msg.dent.namelen;
        if (len > 256) return false; // TODO: resize buffer? continue?

        char buf[257];
        if (!ReadFdExactly(sc.fd, buf, len)) return false;
        buf[len] = 0;

        func(msg.dent.mode, msg.dent.size, msg.dent.time, buf);
    }
}

static bool sync_finish_stat(SyncConnection& sc, unsigned int* timestamp,
                             unsigned int* mode, unsigned int* size) {
    syncmsg msg;
    if (!ReadFdExactly(sc.fd, &msg.stat, sizeof(msg.stat)) || msg.stat.id != ID_STAT) {
        return false;
    }

    if (timestamp) *timestamp = msg.stat.time;
    if (mode) *mode = msg.stat.mode;
    if (size) *size = msg.stat.size;

    return true;
}

static bool sync_stat(SyncConnection& sc, const char* path,
                      unsigned int* timestamp, unsigned int* mode, unsigned int* size) {
    return sc.SendRequest(ID_STAT, path) && sync_finish_stat(sc, timestamp, mode, size);
}

static bool sync_send(SyncConnection& sc, const char* lpath, const char* rpath,
                      unsigned mtime, mode_t mode)
{
    std::string path_and_mode = android::base::StringPrintf("%s,%d", rpath, mode);

    if (S_ISLNK(mode)) {
#if !defined(_WIN32)
        char buf[PATH_MAX];
        ssize_t data_length = readlink(lpath, buf, PATH_MAX - 1);
        if (data_length == -1) {
            sc.Error("readlink '%s' failed: %s", lpath, strerror(errno));
            return false;
        }
        buf[data_length++] = '\0';

        if (!sc.SendSmallFile(path_and_mode.c_str(), lpath, rpath, mtime, buf, data_length)) {
            return false;
        }
        return sc.CopyDone(lpath, rpath);
#endif
    }

    struct stat st;
    if (stat(lpath, &st) == -1) {
        sc.Error("failed to stat local file '%s': %s", lpath, strerror(errno));
        return false;
    }
    if (st.st_size < SYNC_DATA_MAX) {
        std::string data;
        if (!android::base::ReadFileToString(lpath, &data)) {
            sc.Error("failed to read all of '%s': %s", lpath, strerror(errno));
            return false;
        }
        if (!sc.SendSmallFile(path_and_mode.c_str(), lpath, rpath, mtime,
                              data.data(), data.size())) {
            return false;
        }
    } else {
        if (!sc.SendLargeFile(path_and_mode.c_str(), lpath, rpath, mtime)) {
            return false;
        }
    }
    return sc.CopyDone(lpath, rpath);
}

static bool sync_recv(SyncConnection& sc, const char* rpath, const char* lpath) {
    unsigned size = 0;
    if (!sync_stat(sc, rpath, nullptr, nullptr, &size)) return false;

    if (!sc.SendRequest(ID_RECV, rpath)) return false;

    adb_unlink(lpath);
    int lfd = adb_creat(lpath, 0644);
    if (lfd < 0) {
        sc.Error("cannot create '%s': %s", lpath, strerror(errno));
        return false;
    }

    uint64_t bytes_copied = 0;
    while (true) {
        syncmsg msg;
        if (!ReadFdExactly(sc.fd, &msg.data, sizeof(msg.data))) {
            adb_close(lfd);
            adb_unlink(lpath);
            return false;
        }

        if (msg.data.id == ID_DONE) break;

        if (msg.data.id != ID_DATA) {
            adb_close(lfd);
            adb_unlink(lpath);
            sc.ReportCopyFailure(rpath, lpath, msg);
            return false;
        }

        if (msg.data.size > sc.max) {
            sc.Error("msg.data.size too large: %u (max %zu)", msg.data.size, sc.max);
            adb_close(lfd);
            adb_unlink(lpath);
            return false;
        }

        char buffer[SYNC_DATA_MAX];
        if (!ReadFdExactly(sc.fd, buffer, msg.data.size)) {
            adb_close(lfd);
            adb_unlink(lpath);
            return false;
        }

        if (!WriteFdExactly(lfd, buffer, msg.data.size)) {
            sc.Error("cannot write '%s': %s", lpath, strerror(errno));
            adb_close(lfd);
            adb_unlink(lpath);
            return false;
        }

        sc.total_bytes_ += msg.data.size;

        bytes_copied += msg.data.size;

        sc.ReportProgress(rpath, bytes_copied, size);
    }

    adb_close(lfd);
    return true;
}

bool do_sync_ls(const char* path) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    return sync_ls(sc, path, [](unsigned mode, unsigned size, unsigned time,
                                const char* name) {
        printf("%08x %08x %08x %s\n", mode, size, time, name);
    });
}

static bool IsDotOrDotDot(const char* name) {
    return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static bool local_build_list(SyncConnection& sc, std::vector<copyinfo>* file_list,
                             const std::string& lpath,
                             const std::string& rpath) {
    std::vector<copyinfo> dirlist;
    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(lpath.c_str()), closedir);
    if (!dir) {
        sc.Error("cannot open '%s': %s", lpath.c_str(), strerror(errno));
        return false;
    }

    bool empty_dir = true;
    dirent* de;
    while ((de = readdir(dir.get()))) {
        if (IsDotOrDotDot(de->d_name)) {
            continue;
        }

        empty_dir = false;
        std::string stat_path = lpath + de->d_name;

        struct stat st;
        if (lstat(stat_path.c_str(), &st) == -1) {
            sc.Error("cannot lstat '%s': %s", stat_path.c_str(),
                     strerror(errno));
            continue;
        }

        copyinfo ci(lpath, rpath, de->d_name, st.st_mode);
        if (S_ISDIR(st.st_mode)) {
            dirlist.push_back(ci);
        } else {
            if (!should_push_file(st.st_mode)) {
                sc.Warning("skipping special file '%s' (mode = 0o%o)", lpath.c_str(), st.st_mode);
                ci.skip = true;
            }
            ci.time = st.st_mtime;
            ci.size = st.st_size;
            file_list->push_back(ci);
        }
    }

    // Close this directory and recurse.
    dir.reset();

    // Add the current directory to the list if it was empty, to ensure that
    // it gets created.
    if (empty_dir) {
        // TODO(b/25566053): Make pushing empty directories work.
        // TODO(b/25457350): We don't preserve permissions on directories.
        sc.Warning("skipping empty directory '%s'", lpath.c_str());
        copyinfo ci(adb_dirname(lpath), adb_dirname(rpath), adb_basename(lpath), S_IFDIR);
        ci.skip = true;
        file_list->push_back(ci);
        return true;
    }

    for (const copyinfo& ci : dirlist) {
        local_build_list(sc, file_list, ci.lpath, ci.rpath);
    }

    return true;
}

static bool copy_local_dir_remote(SyncConnection& sc, std::string lpath,
                                  std::string rpath, bool check_timestamps,
                                  bool list_only) {
    // Make sure that both directory paths end in a slash.
    // Both paths are known to be nonempty, so we don't need to check.
    ensure_trailing_separators(lpath, rpath);

    // Recursively build the list of files to copy.
    std::vector<copyinfo> file_list;
    int pushed = 0;
    int skipped = 0;
    if (!local_build_list(sc, &file_list, lpath, rpath)) {
        return false;
    }

    if (check_timestamps) {
        for (const copyinfo& ci : file_list) {
            if (!sc.SendRequest(ID_STAT, ci.rpath.c_str())) {
                return false;
            }
        }
        for (copyinfo& ci : file_list) {
            unsigned int timestamp, mode, size;
            if (!sync_finish_stat(sc, &timestamp, &mode, &size)) {
                return false;
            }
            if (size == ci.size) {
                // For links, we cannot update the atime/mtime.
                if ((S_ISREG(ci.mode & mode) && timestamp == ci.time) ||
                        (S_ISLNK(ci.mode & mode) && timestamp >= ci.time)) {
                    ci.skip = true;
                }
            }
        }
    }

    sc.ComputeExpectedTotalBytes(file_list);

    for (const copyinfo& ci : file_list) {
        if (!ci.skip) {
            if (list_only) {
                sc.Error("would push: %s -> %s", ci.lpath.c_str(), ci.rpath.c_str());
            } else {
                if (!sync_send(sc, ci.lpath.c_str(), ci.rpath.c_str(), ci.time, ci.mode)) {
                    return false;
                }
            }
            pushed++;
        } else {
            skipped++;
        }
    }

    sc.Printf("%s: %d file%s pushed. %d file%s skipped.%s", rpath.c_str(),
              pushed, (pushed == 1) ? "" : "s", skipped,
              (skipped == 1) ? "" : "s", sc.TransferRate().c_str());
    return true;
}

bool do_sync_push(const std::vector<const char*>& srcs, const char* dst) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    bool success = true;
    unsigned dst_mode;
    if (!sync_stat(sc, dst, nullptr, &dst_mode, nullptr)) return false;
    bool dst_exists = (dst_mode != 0);
    bool dst_isdir = S_ISDIR(dst_mode);

    if (!dst_isdir) {
        if (srcs.size() > 1) {
            sc.Error("target '%s' is not a directory", dst);
            return false;
        } else {
            size_t dst_len = strlen(dst);

            // A path that ends with a slash doesn't have to be a directory if
            // it doesn't exist yet.
            if (dst[dst_len - 1] == '/' && dst_exists) {
                sc.Error("failed to access '%s': Not a directory", dst);
                return false;
            }
        }
    }

    for (const char* src_path : srcs) {
        const char* dst_path = dst;
        struct stat st;
        if (stat(src_path, &st) == -1) {
            sc.Error("cannot stat '%s': %s", src_path, strerror(errno));
            success = false;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            std::string dst_dir = dst;

            // If the destination path existed originally, the source directory
            // should be copied as a child of the destination.
            if (dst_exists) {
                if (!dst_isdir) {
                    sc.Error("target '%s' is not a directory", dst);
                    return false;
                }
                // dst is a POSIX path, so we don't want to use the sysdeps
                // helpers here.
                if (dst_dir.back() != '/') {
                    dst_dir.push_back('/');
                }
                dst_dir.append(adb_basename(src_path));
            }

            success &= copy_local_dir_remote(sc, src_path, dst_dir.c_str(),
                                             false, false);
            continue;
        } else if (!should_push_file(st.st_mode)) {
            sc.Warning("skipping special file '%s' (mode = 0o%o)", src_path, st.st_mode);
            continue;
        }

        std::string path_holder;
        if (dst_isdir) {
            // If we're copying a local file to a remote directory,
            // we really want to copy to remote_dir + "/" + local_filename.
            path_holder = dst_path;
            if (path_holder.back() != '/') {
                path_holder.push_back('/');
            }
            path_holder += adb_basename(src_path);
            dst_path = path_holder.c_str();
        }
        sc.SetExpectedTotalBytes(st.st_size);
        success &= sync_send(sc, src_path, dst_path, st.st_mtime, st.st_mode);
    }

    return success;
}

static bool remote_symlink_isdir(SyncConnection& sc, const std::string& rpath) {
    unsigned mode;
    std::string dir_path = rpath;
    dir_path.push_back('/');
    if (!sync_stat(sc, dir_path.c_str(), nullptr, &mode, nullptr)) {
        sc.Error("failed to stat remote symlink '%s'", dir_path.c_str());
        return false;
    }
    return S_ISDIR(mode);
}

static bool remote_build_list(SyncConnection& sc, std::vector<copyinfo>* file_list,
                              const std::string& rpath, const std::string& lpath) {
    std::vector<copyinfo> dirlist;
    std::vector<copyinfo> linklist;

    // Add an entry for the current directory to ensure it gets created before pulling its contents.
    copyinfo ci(adb_dirname(lpath), adb_dirname(rpath), adb_basename(lpath), S_IFDIR);
    file_list->push_back(ci);

    // Put the files/dirs in rpath on the lists.
    auto callback = [&](unsigned mode, unsigned size, unsigned time, const char* name) {
        if (IsDotOrDotDot(name)) {
            return;
        }

        copyinfo ci(lpath, rpath, name, mode);
        if (S_ISDIR(mode)) {
            dirlist.push_back(ci);
        } else if (S_ISLNK(mode)) {
            linklist.push_back(ci);
        } else {
            if (!should_pull_file(ci.mode)) {
                sc.Warning("skipping special file '%s' (mode = 0o%o)", ci.rpath.c_str(), ci.mode);
                ci.skip = true;
            }
            ci.time = time;
            ci.size = size;
            file_list->push_back(ci);
        }
    };

    if (!sync_ls(sc, rpath.c_str(), callback)) {
        return false;
    }

    // Check each symlink we found to see whether it's a file or directory.
    for (copyinfo& link_ci : linklist) {
        if (remote_symlink_isdir(sc, link_ci.rpath)) {
            dirlist.emplace_back(std::move(link_ci));
        } else {
            file_list->emplace_back(std::move(link_ci));
        }
    }

    // Recurse into each directory we found.
    while (!dirlist.empty()) {
        copyinfo current = dirlist.back();
        dirlist.pop_back();
        if (!remote_build_list(sc, file_list, current.rpath, current.lpath)) {
            return false;
        }
    }

    return true;
}

static int set_time_and_mode(const std::string& lpath, time_t time,
                             unsigned int mode) {
    struct utimbuf times = { time, time };
    int r1 = utime(lpath.c_str(), &times);

    /* use umask for permissions */
    mode_t mask = umask(0000);
    umask(mask);
    int r2 = chmod(lpath.c_str(), mode & ~mask);

    return r1 ? r1 : r2;
}

static bool copy_remote_dir_local(SyncConnection& sc, std::string rpath,
                                  std::string lpath, bool copy_attrs) {
    // Make sure that both directory paths end in a slash.
    // Both paths are known to be nonempty, so we don't need to check.
    ensure_trailing_separators(lpath, rpath);

    // Recursively build the list of files to copy.
    sc.Printf("pull: building file list...");
    std::vector<copyinfo> file_list;
    if (!remote_build_list(sc, &file_list, rpath.c_str(), lpath.c_str())) {
        return false;
    }

    sc.ComputeExpectedTotalBytes(file_list);

    int pulled = 0;
    int skipped = 0;
    for (const copyinfo &ci : file_list) {
        if (!ci.skip) {
            if (S_ISDIR(ci.mode)) {
                // Entry is for an empty directory, create it and continue.
                // TODO(b/25457350): We don't preserve permissions on directories.
                if (!mkdirs(ci.lpath))  {
                    sc.Error("failed to create directory '%s': %s",
                             ci.lpath.c_str(), strerror(errno));
                    return false;
                }
                pulled++;
                continue;
            }

            if (!sync_recv(sc, ci.rpath.c_str(), ci.lpath.c_str())) {
                return false;
            }

            if (copy_attrs && set_time_and_mode(ci.lpath, ci.time, ci.mode)) {
                return false;
            }
            pulled++;
        } else {
            skipped++;
        }
    }

    sc.Printf("%s: %d file%s pulled. %d file%s skipped.%s", rpath.c_str(),
              pulled, (pulled == 1) ? "" : "s", skipped,
              (skipped == 1) ? "" : "s", sc.TransferRate().c_str());
    return true;
}

bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst,
                  bool copy_attrs) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    bool success = true;
    struct stat st;
    bool dst_exists = true;

    if (stat(dst, &st) == -1) {
        dst_exists = false;

        // If we're only pulling one path, the destination path might point to
        // a path that doesn't exist yet.
        if (srcs.size() == 1 && errno == ENOENT) {
            // However, its parent must exist.
            struct stat parent_st;
            if (stat(adb_dirname(dst).c_str(), &parent_st) == -1) {
                sc.Error("cannot create file/directory '%s': %s", dst, strerror(errno));
                return false;
            }
        } else {
            sc.Error("failed to access '%s': %s", dst, strerror(errno));
            return false;
        }
    }

    bool dst_isdir = dst_exists && S_ISDIR(st.st_mode);
    if (!dst_isdir) {
        if (srcs.size() > 1) {
            sc.Error("target '%s' is not a directory", dst);
            return false;
        } else {
            size_t dst_len = strlen(dst);

            // A path that ends with a slash doesn't have to be a directory if
            // it doesn't exist yet.
            if (adb_is_separator(dst[dst_len - 1]) && dst_exists) {
                sc.Error("failed to access '%s': Not a directory", dst);
                return false;
            }
        }
    }

    for (const char* src_path : srcs) {
        const char* dst_path = dst;
        unsigned src_mode, src_time, src_size;
        if (!sync_stat(sc, src_path, &src_time, &src_mode, &src_size)) {
            sc.Error("failed to stat remote object '%s'", src_path);
            return false;
        }
        if (src_mode == 0) {
            sc.Error("remote object '%s' does not exist", src_path);
            success = false;
            continue;
        }

        bool src_isdir = S_ISDIR(src_mode);
        if (S_ISLNK(src_mode)) {
            src_isdir = remote_symlink_isdir(sc, src_path);
        }

        if (src_isdir) {
            std::string dst_dir = dst;

            // If the destination path existed originally, the source directory
            // should be copied as a child of the destination.
            if (dst_exists) {
                if (!dst_isdir) {
                    sc.Error("target '%s' is not a directory", dst);
                    return false;
                }
                if (!adb_is_separator(dst_dir.back())) {
                    dst_dir.push_back(OS_PATH_SEPARATOR);
                }
                dst_dir.append(adb_basename(src_path));
            }

            success &= copy_remote_dir_local(sc, src_path, dst_dir.c_str(), copy_attrs);
            continue;
        } else if (!should_pull_file(src_mode)) {
            sc.Warning("skipping special file '%s' (mode = 0o%o)", src_path, src_mode);
            continue;
        }

        std::string path_holder;
        if (dst_isdir) {
            // If we're copying a remote file to a local directory, we
            // really want to copy to local_dir + OS_PATH_SEPARATOR +
            // basename(remote).
            path_holder = android::base::StringPrintf("%s%c%s", dst_path, OS_PATH_SEPARATOR,
                                                      adb_basename(src_path).c_str());
            dst_path = path_holder.c_str();
        }

        sc.SetExpectedTotalBytes(src_size);
        if (!sync_recv(sc, src_path, dst_path)) {
            success = false;
            continue;
        }

        if (copy_attrs && set_time_and_mode(dst_path, src_time, src_mode) != 0) {
            success = false;
            continue;
        }
    }

    return success;
}

bool do_sync_sync(const std::string& lpath, const std::string& rpath, bool list_only) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    return copy_local_dir_remote(sc, lpath, rpath, true, list_only);
}
