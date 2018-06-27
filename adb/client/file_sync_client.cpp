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
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include <chrono>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "sysdeps.h"

#include "adb.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "file_sync_service.h"
#include "line_printer.h"
#include "sysdeps/errno.h"
#include "sysdeps/stat.h"

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
    return S_ISREG(mode) || S_ISBLK(mode) || S_ISCHR(mode);
}

static bool should_push_file(mode_t mode) {
    return S_ISREG(mode) || S_ISLNK(mode);
}

struct copyinfo {
    std::string lpath;
    std::string rpath;
    int64_t time = 0;
    uint32_t mode;
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

enum class TransferDirection {
    push,
    pull,
};

struct TransferLedger {
    std::chrono::steady_clock::time_point start_time;
    uint64_t files_transferred;
    uint64_t files_skipped;
    uint64_t bytes_transferred;
    uint64_t bytes_expected;
    bool expect_multiple_files;

    TransferLedger() {
        Reset();
    }

    bool operator==(const TransferLedger& other) const {
        return files_transferred == other.files_transferred &&
               files_skipped == other.files_skipped && bytes_transferred == other.bytes_transferred;
    }

    bool operator!=(const TransferLedger& other) const {
        return !(*this == other);
    }

    void Reset() {
        start_time = std::chrono::steady_clock::now();
        files_transferred = 0;
        files_skipped = 0;
        bytes_transferred = 0;
        bytes_expected = 0;
    }

    std::string TransferRate() {
        if (bytes_transferred == 0) return "";

        std::chrono::duration<double> duration;
        duration = std::chrono::steady_clock::now() - start_time;

        double s = duration.count();
        if (s == 0) {
            return "";
        }
        double rate = (static_cast<double>(bytes_transferred) / s) / (1024 * 1024);
        return android::base::StringPrintf(" %.1f MB/s (%" PRIu64 " bytes in %.3fs)", rate,
                                           bytes_transferred, s);
    }

    void ReportProgress(LinePrinter& lp, const std::string& file, uint64_t file_copied_bytes,
                        uint64_t file_total_bytes) {
        char overall_percentage_str[5] = "?";
        if (bytes_expected != 0 && bytes_transferred <= bytes_expected) {
            int overall_percentage = static_cast<int>(bytes_transferred * 100 / bytes_expected);
            // If we're pulling symbolic links, we'll pull the target of the link rather than
            // just create a local link, and that will cause us to go over 100%.
            if (overall_percentage <= 100) {
                snprintf(overall_percentage_str, sizeof(overall_percentage_str), "%d%%",
                         overall_percentage);
            }
        }

        std::string output;
        if (file_copied_bytes > file_total_bytes || file_total_bytes == 0) {
            // This case can happen if we're racing against something that wrote to the file
            // between our stat and our read, or if we're reading a magic file that lies about
            // its size. Just show how much we've copied.
            output = android::base::StringPrintf("[%4s] %s: %" PRId64 "/?", overall_percentage_str,
                                                 file.c_str(), file_copied_bytes);
        } else {
            // If we're transferring multiple files, we want to know how far through the current
            // file we are, as well as the overall percentage.
            if (expect_multiple_files) {
                int file_percentage = static_cast<int>(file_copied_bytes * 100 / file_total_bytes);
                output = android::base::StringPrintf("[%4s] %s: %d%%", overall_percentage_str,
                                                     file.c_str(), file_percentage);
            } else {
                output =
                    android::base::StringPrintf("[%4s] %s", overall_percentage_str, file.c_str());
            }
        }
        lp.Print(output, LinePrinter::LineType::INFO);
    }

    void ReportTransferRate(LinePrinter& lp, const std::string& name, TransferDirection direction) {
        const char* direction_str = (direction == TransferDirection::push) ? "pushed" : "pulled";
        std::stringstream ss;
        if (!name.empty()) {
            ss << name << ": ";
        }
        ss << files_transferred << " file" << ((files_transferred == 1) ? "" : "s") << " "
           << direction_str << ".";
        if (files_skipped > 0) {
            ss << " " << files_skipped << " file" << ((files_skipped == 1) ? "" : "s")
               << " skipped.";
        }
        ss << TransferRate();

        lp.Print(ss.str(), LinePrinter::LineType::INFO);
        lp.KeepInfoLine();
    }
};

class SyncConnection {
  public:
    SyncConnection() : expect_done_(false) {
        max = SYNC_DATA_MAX; // TODO: decide at runtime.

        std::string error;
        FeatureSet features;
        if (!adb_get_feature_set(&features, &error)) {
            fd = -1;
            Error("failed to get feature set: %s", error.c_str());
        } else {
            have_stat_v2_ = CanUseFeature(features, kFeatureStat2);
            fd = adb_connect("sync:", &error);
            if (fd < 0) {
                Error("connect failed: %s", error.c_str());
            }
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

    void NewTransfer() {
        current_ledger_.Reset();
    }

    void RecordBytesTransferred(size_t bytes) {
        current_ledger_.bytes_transferred += bytes;
        global_ledger_.bytes_transferred += bytes;
    }

    void RecordFilesTransferred(size_t files) {
        current_ledger_.files_transferred += files;
        global_ledger_.files_transferred += files;
    }

    void RecordFilesSkipped(size_t files) {
        current_ledger_.files_skipped += files;
        global_ledger_.files_skipped += files;
    }

    void ReportProgress(const std::string& file, uint64_t file_copied_bytes,
                        uint64_t file_total_bytes) {
        current_ledger_.ReportProgress(line_printer_, file, file_copied_bytes, file_total_bytes);
    }

    void ReportTransferRate(const std::string& file, TransferDirection direction) {
        current_ledger_.ReportTransferRate(line_printer_, file, direction);
    }

    void ReportOverallTransferRate(TransferDirection direction) {
        if (current_ledger_ != global_ledger_) {
            global_ledger_.ReportTransferRate(line_printer_, "", direction);
        }
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

    bool SendStat(const char* path_and_mode) {
        if (!have_stat_v2_) {
            errno = ENOTSUP;
            return false;
        }
        return SendRequest(ID_STAT_V2, path_and_mode);
    }

    bool SendLstat(const char* path_and_mode) {
        if (have_stat_v2_) {
            return SendRequest(ID_LSTAT_V2, path_and_mode);
        } else {
            return SendRequest(ID_LSTAT_V1, path_and_mode);
        }
    }

    bool FinishStat(struct stat* st) {
        syncmsg msg;

        memset(st, 0, sizeof(*st));
        if (have_stat_v2_) {
            if (!ReadFdExactly(fd, &msg.stat_v2, sizeof(msg.stat_v2))) {
                fatal_errno("protocol fault: failed to read stat response");
            }

            if (msg.stat_v2.id != ID_LSTAT_V2 && msg.stat_v2.id != ID_STAT_V2) {
                fatal_errno("protocol fault: stat response has wrong message id: %" PRIx32,
                            msg.stat_v2.id);
            }

            if (msg.stat_v2.error != 0) {
                errno = errno_from_wire(msg.stat_v2.error);
                return false;
            }

            st->st_dev = msg.stat_v2.dev;
            st->st_ino = msg.stat_v2.ino;
            st->st_mode = msg.stat_v2.mode;
            st->st_nlink = msg.stat_v2.nlink;
            st->st_uid = msg.stat_v2.uid;
            st->st_gid = msg.stat_v2.gid;
            st->st_size = msg.stat_v2.size;
            st->st_atime = msg.stat_v2.atime;
            st->st_mtime = msg.stat_v2.mtime;
            st->st_ctime = msg.stat_v2.ctime;
            return true;
        } else {
            if (!ReadFdExactly(fd, &msg.stat_v1, sizeof(msg.stat_v1))) {
                fatal_errno("protocol fault: failed to read stat response");
            }

            if (msg.stat_v1.id != ID_LSTAT_V1) {
                fatal_errno("protocol fault: stat response has wrong message id: %" PRIx32,
                            msg.stat_v1.id);
            }

            if (msg.stat_v1.mode == 0 && msg.stat_v1.size == 0 && msg.stat_v1.time == 0) {
                // There's no way for us to know what the error was.
                errno = ENOPROTOOPT;
                return false;
            }

            st->st_mode = msg.stat_v1.mode;
            st->st_size = msg.stat_v1.size;
            st->st_ctime = msg.stat_v1.time;
            st->st_mtime = msg.stat_v1.time;
        }

        return true;
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

        // RecordFilesTransferred gets called in CopyDone.
        RecordBytesTransferred(data_length);
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
            int bytes_read = adb_read(lfd, sbuf.data, max - sizeof(SyncRequest));
            if (bytes_read == -1) {
                Error("reading '%s' locally failed: %s", lpath, strerror(errno));
                adb_close(lfd);
                return false;
            } else if (bytes_read == 0) {
                break;
            }

            sbuf.size = bytes_read;
            WriteOrDie(lpath, rpath, &sbuf, sizeof(SyncRequest) + bytes_read);

            RecordBytesTransferred(bytes_read);
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

        // RecordFilesTransferred gets called in CopyDone.
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
                RecordFilesTransferred(1);
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
        Error("failed to copy '%s' to '%s': remote %s", from, to, &buf[0]);
        return false;
    }

    void Printf(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s;

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::INFO);
    }

    void Println(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s;

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::INFO);
        line_printer_.KeepInfoLine();
    }

    void Error(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s = "adb: error: ";

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::ERROR);
    }

    void Warning(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s = "adb: warning: ";

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::WARNING);
    }

    void ComputeExpectedTotalBytes(const std::vector<copyinfo>& file_list) {
        current_ledger_.bytes_expected = 0;
        for (const copyinfo& ci : file_list) {
            // Unfortunately, this doesn't work for symbolic links, because we'll copy the
            // target of the link rather than just creating a link. (But ci.size is the link size.)
            if (!ci.skip) current_ledger_.bytes_expected += ci.size;
        }
        current_ledger_.expect_multiple_files = true;
    }

    void SetExpectedTotalBytes(uint64_t expected_total_bytes) {
        current_ledger_.bytes_expected = expected_total_bytes;
        current_ledger_.expect_multiple_files = false;
    }

    // TODO: add a char[max] buffer here, to replace syncsendbuf...
    int fd;
    size_t max;

  private:
    bool expect_done_;
    bool have_stat_v2_;

    TransferLedger global_ledger_;
    TransferLedger current_ledger_;
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
};

typedef void (sync_ls_cb)(unsigned mode, unsigned size, unsigned time, const char* name);

static bool sync_ls(SyncConnection& sc, const char* path,
                    const std::function<sync_ls_cb>& func) {
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

static bool sync_stat(SyncConnection& sc, const char* path, struct stat* st) {
    return sc.SendStat(path) && sc.FinishStat(st);
}

static bool sync_lstat(SyncConnection& sc, const char* path, struct stat* st) {
    return sc.SendLstat(path) && sc.FinishStat(st);
}

static bool sync_stat_fallback(SyncConnection& sc, const char* path, struct stat* st) {
    if (sync_stat(sc, path, st)) {
        return true;
    }

    if (errno != ENOTSUP) {
        return false;
    }

    // Try to emulate the parts we can when talking to older adbds.
    bool lstat_result = sync_lstat(sc, path, st);
    if (!lstat_result) {
        return false;
    }

    if (S_ISLNK(st->st_mode)) {
        // If the target is a symlink, figure out whether it's a file or a directory.
        // Also, zero out the st_size field, since no one actually cares what the path length is.
        st->st_size = 0;
        std::string dir_path = path;
        dir_path.push_back('/');
        struct stat tmp_st;

        st->st_mode &= ~S_IFMT;
        if (sync_lstat(sc, dir_path.c_str(), &tmp_st)) {
            st->st_mode |= S_IFDIR;
        } else {
            st->st_mode |= S_IFREG;
        }
    }
    return true;
}

static bool sync_send(SyncConnection& sc, const char* lpath, const char* rpath, unsigned mtime,
                      mode_t mode, bool sync) {
    std::string path_and_mode = android::base::StringPrintf("%s,%d", rpath, mode);

    if (sync) {
        struct stat st;
        if (sync_lstat(sc, rpath, &st)) {
            // For links, we cannot update the atime/mtime.
            if ((S_ISREG(mode & st.st_mode) && st.st_mtime == static_cast<time_t>(mtime)) ||
                (S_ISLNK(mode & st.st_mode) && st.st_mtime >= static_cast<time_t>(mtime))) {
                sc.RecordFilesSkipped(1);
                return true;
            }
        }
    }

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
        if (!android::base::ReadFileToString(lpath, &data, true)) {
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

static bool sync_recv(SyncConnection& sc, const char* rpath, const char* lpath,
                      const char* name, uint64_t expected_size) {
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

        bytes_copied += msg.data.size;

        sc.RecordBytesTransferred(msg.data.size);
        sc.ReportProgress(name != nullptr ? name : rpath, bytes_copied, expected_size);
    }

    sc.RecordFilesTransferred(1);
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
        copyinfo ci(android::base::Dirname(lpath), android::base::Dirname(rpath),
                    android::base::Basename(lpath), S_IFDIR);
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
    sc.NewTransfer();

    // Make sure that both directory paths end in a slash.
    // Both paths are known to be nonempty, so we don't need to check.
    ensure_trailing_separators(lpath, rpath);

    // Recursively build the list of files to copy.
    std::vector<copyinfo> file_list;
    int skipped = 0;
    if (!local_build_list(sc, &file_list, lpath, rpath)) {
        return false;
    }

    if (check_timestamps) {
        for (const copyinfo& ci : file_list) {
            if (!sc.SendLstat(ci.rpath.c_str())) {
                sc.Error("failed to send lstat");
                return false;
            }
        }
        for (copyinfo& ci : file_list) {
            struct stat st;
            if (sc.FinishStat(&st)) {
                if (st.st_size == static_cast<off_t>(ci.size)) {
                    // For links, we cannot update the atime/mtime.
                    if ((S_ISREG(ci.mode & st.st_mode) && st.st_mtime == ci.time) ||
                        (S_ISLNK(ci.mode & st.st_mode) && st.st_mtime >= ci.time)) {
                        ci.skip = true;
                    }
                }
            }
        }
    }

    sc.ComputeExpectedTotalBytes(file_list);

    for (const copyinfo& ci : file_list) {
        if (!ci.skip) {
            if (list_only) {
                sc.Println("would push: %s -> %s", ci.lpath.c_str(), ci.rpath.c_str());
            } else {
                if (!sync_send(sc, ci.lpath.c_str(), ci.rpath.c_str(), ci.time, ci.mode, false)) {
                    return false;
                }
            }
        } else {
            skipped++;
        }
    }

    sc.RecordFilesSkipped(skipped);
    sc.ReportTransferRate(lpath, TransferDirection::push);
    return true;
}

bool do_sync_push(const std::vector<const char*>& srcs, const char* dst, bool sync) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    bool success = true;
    bool dst_exists;
    bool dst_isdir;

    struct stat st;
    if (sync_stat_fallback(sc, dst, &st)) {
        dst_exists = true;
        dst_isdir = S_ISDIR(st.st_mode);
    } else {
        if (errno == ENOENT || errno == ENOPROTOOPT) {
            dst_exists = false;
            dst_isdir = false;
        } else {
            sc.Error("stat failed when trying to push to %s: %s", dst, strerror(errno));
            return false;
        }
    }

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
                dst_dir.append(android::base::Basename(src_path));
            }

            success &= copy_local_dir_remote(sc, src_path, dst_dir.c_str(), sync, false);
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
            path_holder += android::base::Basename(src_path);
            dst_path = path_holder.c_str();
        }

        sc.NewTransfer();
        sc.SetExpectedTotalBytes(st.st_size);
        success &= sync_send(sc, src_path, dst_path, st.st_mtime, st.st_mode, sync);
        sc.ReportTransferRate(src_path, TransferDirection::push);
    }

    sc.ReportOverallTransferRate(TransferDirection::push);
    return success;
}

static bool remote_build_list(SyncConnection& sc, std::vector<copyinfo>* file_list,
                              const std::string& rpath, const std::string& lpath) {
    std::vector<copyinfo> dirlist;
    std::vector<copyinfo> linklist;

    // Add an entry for the current directory to ensure it gets created before pulling its contents.
    copyinfo ci(android::base::Dirname(lpath), android::base::Dirname(rpath),
                android::base::Basename(lpath), S_IFDIR);
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
        struct stat st;
        if (!sync_stat_fallback(sc, link_ci.rpath.c_str(), &st)) {
            sc.Warning("stat failed for path %s: %s", link_ci.rpath.c_str(), strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
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
    sc.NewTransfer();

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
                continue;
            }

            if (!sync_recv(sc, ci.rpath.c_str(), ci.lpath.c_str(), nullptr, ci.size)) {
                return false;
            }

            if (copy_attrs && set_time_and_mode(ci.lpath, ci.time, ci.mode)) {
                return false;
            }
        } else {
            skipped++;
        }
    }

    sc.RecordFilesSkipped(skipped);
    sc.ReportTransferRate(rpath, TransferDirection::pull);
    return true;
}

bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst,
                  bool copy_attrs, const char* name) {
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
            if (stat(android::base::Dirname(dst).c_str(), &parent_st) == -1) {
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
        struct stat src_st;
        if (!sync_stat_fallback(sc, src_path, &src_st)) {
            if (errno == ENOPROTOOPT) {
                sc.Error("remote object '%s' does not exist", src_path);
            } else {
                sc.Error("failed to stat remote object '%s': %s", src_path, strerror(errno));
            }

            success = false;
            continue;
        }

        bool src_isdir = S_ISDIR(src_st.st_mode);
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
                dst_dir.append(android::base::Basename(src_path));
            }

            success &= copy_remote_dir_local(sc, src_path, dst_dir.c_str(), copy_attrs);
            continue;
        } else if (!should_pull_file(src_st.st_mode)) {
            sc.Warning("skipping special file '%s' (mode = 0o%o)", src_path, src_st.st_mode);
            continue;
        }

        std::string path_holder;
        if (dst_isdir) {
            // If we're copying a remote file to a local directory, we
            // really want to copy to local_dir + OS_PATH_SEPARATOR +
            // basename(remote).
            path_holder = android::base::StringPrintf("%s%c%s", dst_path, OS_PATH_SEPARATOR,
                                                      android::base::Basename(src_path).c_str());
            dst_path = path_holder.c_str();
        }

        sc.NewTransfer();
        sc.SetExpectedTotalBytes(src_st.st_size);
        if (!sync_recv(sc, src_path, dst_path, name, src_st.st_size)) {
            success = false;
            continue;
        }

        if (copy_attrs && set_time_and_mode(dst_path, src_st.st_mtime, src_st.st_mode) != 0) {
            success = false;
            continue;
        }
        sc.ReportTransferRate(src_path, TransferDirection::pull);
    }

    sc.ReportOverallTransferRate(TransferDirection::pull);
    return success;
}

bool do_sync_sync(const std::string& lpath, const std::string& rpath, bool list_only) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    bool success = copy_local_dir_remote(sc, lpath, rpath, true, list_only);
    if (!list_only) {
        sc.ReportOverallTransferRate(TransferDirection::push);
    }
    return success;
}
