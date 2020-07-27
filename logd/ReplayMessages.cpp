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

#include <inttypes.h>

#include <chrono>
#include <map>

#include <android-base/file.h>
#include <android-base/mapped_file.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/log.h>
#include <log/log_time.h>
#include <log/logprint.h>

#include "ChattyLogBuffer.h"
#include "LogBuffer.h"
#include "LogStatistics.h"
#include "RecordedLogMessage.h"
#include "SerializedLogBuffer.h"
#include "SimpleLogBuffer.h"

using android::base::MappedFile;
using android::base::ParseInt;
using android::base::ParseUint;
using android::base::Split;

char* android::uidToName(uid_t) {
    return nullptr;
}

static size_t GetPrivateDirty() {
    // Allocate once and hope that we don't need to reallocate >40000, to prevent heap fragmentation
    static std::string smaps(40000, '\0');
    android::base::ReadFileToString("/proc/self/smaps", &smaps);

    size_t result = 0;
    size_t base = 0;
    size_t found;
    while (true) {
        found = smaps.find("Private_Dirty:", base);
        if (found == smaps.npos) break;

        found += sizeof("Private_Dirty:");

        result += atoi(&smaps[found]);

        base = found + 1;
    }

    return result;
}

static AndroidLogFormat* GetLogFormat() {
    static AndroidLogFormat* format = [] {
        auto* format = android_log_format_new();
        android_log_setPrintFormat(format, android_log_formatFromString("threadtime"));
        android_log_setPrintFormat(format, android_log_formatFromString("uid"));
        return format;
    }();
    return format;
}

static void PrintMessage(struct log_msg* buf) {
    bool is_binary =
            buf->id() == LOG_ID_EVENTS || buf->id() == LOG_ID_STATS || buf->id() == LOG_ID_SECURITY;

    AndroidLogEntry entry;
    int err;
    if (is_binary) {
        char binaryMsgBuf[1024];
        err = android_log_processBinaryLogBuffer(&buf->entry, &entry, nullptr, binaryMsgBuf,
                                                 sizeof(binaryMsgBuf));
    } else {
        err = android_log_processLogBuffer(&buf->entry, &entry);
    }
    if (err < 0) {
        fprintf(stderr, "Error parsing log message\n");
    }

    android_log_printLogLine(GetLogFormat(), STDOUT_FILENO, &entry);
}

static log_time GetFirstTimeStamp(const MappedFile& recorded_messages) {
    if (sizeof(RecordedLogMessage) >= recorded_messages.size()) {
        fprintf(stderr, "At least one log message must be present in the input\n");
        exit(1);
    }

    auto* meta = reinterpret_cast<RecordedLogMessage*>(recorded_messages.data());
    return meta->realtime;
}

class StdoutWriter : public LogWriter {
  public:
    StdoutWriter() : LogWriter(0, true) {}
    bool Write(const logger_entry& entry, const char* message) override {
        struct log_msg log_msg;
        log_msg.entry = entry;
        if (log_msg.entry.len > LOGGER_ENTRY_MAX_PAYLOAD) {
            fprintf(stderr, "payload too large %" PRIu16, log_msg.entry.len);
            exit(1);
        }
        memcpy(log_msg.msg(), message, log_msg.entry.len);

        PrintMessage(&log_msg);

        return true;
    }

    std::string name() const override { return "stdout writer"; }
};

class Operation {
  public:
    virtual ~Operation() {}

    virtual void Begin() {}
    virtual void Log(const RecordedLogMessage& meta, const char* msg) = 0;
    virtual void End() {}
};

class PrintInteresting : public Operation {
  public:
    PrintInteresting(log_time first_log_timestamp)
        : stats_simple_{false, false, first_log_timestamp},
          stats_chatty_{false, false, first_log_timestamp},
          stats_serialized_{false, true, first_log_timestamp} {}

    void Begin() override {
        printf("message_count,simple_main_lines,simple_radio_lines,simple_events_lines,simple_"
               "system_lines,simple_crash_lines,simple_stats_lines,simple_security_lines,simple_"
               "kernel_lines,simple_main_size,simple_radio_size,simple_events_size,simple_system_"
               "size,simple_crash_size,simple_stats_size,simple_security_size,simple_kernel_size,"
               "simple_main_overhead,simple_radio_overhead,simple_events_overhead,simple_system_"
               "overhead,simple_crash_overhead,simple_stats_overhead,simple_security_overhead,"
               "simple_kernel_overhead,simple_main_range,simple_radio_range,simple_events_range,"
               "simple_system_range,simple_crash_range,simple_stats_range,simple_security_range,"
               "simple_kernel_range,chatty_main_lines,chatty_radio_lines,chatty_events_lines,"
               "chatty_system_lines,chatty_crash_lines,chatty_stats_lines,chatty_security_lines,"
               "chatty_"
               "kernel_lines,chatty_main_size,chatty_radio_size,chatty_events_size,chatty_system_"
               "size,chatty_crash_size,chatty_stats_size,chatty_security_size,chatty_kernel_size,"
               "chatty_main_overhead,chatty_radio_overhead,chatty_events_overhead,chatty_system_"
               "overhead,chatty_crash_overhead,chatty_stats_overhead,chatty_security_overhead,"
               "chatty_kernel_overhead,chatty_main_range,chatty_radio_range,chatty_events_range,"
               "chatty_system_range,chatty_crash_range,chatty_stats_range,chatty_security_range,"
               "chatty_kernel_range,serialized_main_lines,serialized_radio_lines,serialized_events_"
               "lines,serialized_"
               "system_lines,serialized_crash_lines,serialized_stats_lines,serialized_security_"
               "lines,serialized_"
               "kernel_lines,serialized_main_size,serialized_radio_size,serialized_events_size,"
               "serialized_system_"
               "size,serialized_crash_size,serialized_stats_size,serialized_security_size,"
               "serialized_kernel_size,"
               "serialized_main_overhead,serialized_radio_overhead,serialized_events_overhead,"
               "serialized_system_"
               "overhead,serialized_crash_overhead,serialized_stats_overhead,serialized_security_"
               "overhead,"
               "serialized_kernel_overhead,serialized_main_range,serialized_radio_range,serialized_"
               "events_range,"
               "serialized_system_range,serialized_crash_range,serialized_stats_range,serialized_"
               "security_range,"
               "serialized_kernel_range\n");
    }

    void Log(const RecordedLogMessage& meta, const char* msg) override {
        simple_log_buffer_.Log(static_cast<log_id_t>(meta.log_id), meta.realtime, meta.uid,
                               meta.pid, meta.tid, msg, meta.msg_len);

        chatty_log_buffer_.Log(static_cast<log_id_t>(meta.log_id), meta.realtime, meta.uid,
                               meta.pid, meta.tid, msg, meta.msg_len);

        serialized_log_buffer_.Log(static_cast<log_id_t>(meta.log_id), meta.realtime, meta.uid,
                                   meta.pid, meta.tid, msg, meta.msg_len);

        if (num_message_ % 10000 == 0) {
            printf("%" PRIu64 ",%s,%s,%s\n", num_message_,
                   stats_simple_.ReportInteresting().c_str(),
                   stats_chatty_.ReportInteresting().c_str(),
                   stats_serialized_.ReportInteresting().c_str());
        }

        num_message_++;
    }

  private:
    uint64_t num_message_ = 1;

    LogReaderList reader_list_;
    LogTags tags_;
    PruneList prune_list_;

    LogStatistics stats_simple_;
    SimpleLogBuffer simple_log_buffer_{&reader_list_, &tags_, &stats_simple_};

    LogStatistics stats_chatty_;
    ChattyLogBuffer chatty_log_buffer_{&reader_list_, &tags_, &prune_list_, &stats_chatty_};

    LogStatistics stats_serialized_;
    SerializedLogBuffer serialized_log_buffer_{&reader_list_, &tags_, &stats_serialized_};
};

class SingleBufferOperation : public Operation {
  public:
    SingleBufferOperation(log_time first_log_timestamp, const char* buffer) {
        if (!strcmp(buffer, "simple")) {
            stats_.reset(new LogStatistics{false, false, first_log_timestamp});
            log_buffer_.reset(new SimpleLogBuffer(&reader_list_, &tags_, stats_.get()));
        } else if (!strcmp(buffer, "chatty")) {
            stats_.reset(new LogStatistics{false, false, first_log_timestamp});
            log_buffer_.reset(
                    new ChattyLogBuffer(&reader_list_, &tags_, &prune_list_, stats_.get()));
        } else if (!strcmp(buffer, "serialized")) {
            stats_.reset(new LogStatistics{false, true, first_log_timestamp});
            log_buffer_.reset(new SerializedLogBuffer(&reader_list_, &tags_, stats_.get()));
        } else {
            fprintf(stderr, "invalid log buffer type '%s'\n", buffer);
            abort();
        }
    }

    void Log(const RecordedLogMessage& meta, const char* msg) override {
        PreOperation();
        log_buffer_->Log(static_cast<log_id_t>(meta.log_id), meta.realtime, meta.uid, meta.pid,
                         meta.tid, msg, meta.msg_len);

        Operation();

        num_message_++;
    }

    virtual void PreOperation() {}
    virtual void Operation() {}

  protected:
    uint64_t num_message_ = 1;

    LogReaderList reader_list_;
    LogTags tags_;
    PruneList prune_list_;

    std::unique_ptr<LogStatistics> stats_;
    std::unique_ptr<LogBuffer> log_buffer_;
};

class PrintMemory : public SingleBufferOperation {
  public:
    PrintMemory(log_time first_log_timestamp, const char* buffer)
        : SingleBufferOperation(first_log_timestamp, buffer) {}

    void Operation() override {
        if (num_message_ % 100000 == 0) {
            printf("%" PRIu64 ",%s\n", num_message_,
                   std::to_string(GetPrivateDirty() - baseline_memory_).c_str());
        }
    }

  private:
    size_t baseline_memory_ = GetPrivateDirty();
};

class PrintLogs : public SingleBufferOperation {
  public:
    PrintLogs(log_time first_log_timestamp, const char* buffer, const char* buffers,
              const char* print_point)
        : SingleBufferOperation(first_log_timestamp, buffer) {
        if (buffers != nullptr) {
            if (strcmp(buffers, "all") != 0) {
                std::vector<int> buffer_ids;
                auto string_ids = Split(buffers, ",");
                for (const auto& string_id : string_ids) {
                    int result;
                    if (!ParseInt(string_id, &result, 0, 7)) {
                        fprintf(stderr, "Could not parse buffer_id '%s'\n", string_id.c_str());
                        exit(1);
                    }
                    buffer_ids.emplace_back(result);
                }
                mask_ = 0;
                for (const auto& buffer_id : buffer_ids) {
                    mask_ |= 1 << buffer_id;
                }
            }
        }
        if (print_point != nullptr) {
            uint64_t result = 0;
            if (!ParseUint(print_point, &result)) {
                fprintf(stderr, "Could not parse print point '%s'\n", print_point);
                exit(1);
            }
            print_point_ = result;
        }
    }

    void Operation() override {
        if (print_point_ && num_message_ >= *print_point_) {
            End();
            exit(0);
        }
    }

    void End() {
        std::unique_ptr<LogWriter> test_writer(new StdoutWriter());
        std::unique_ptr<FlushToState> flush_to_state = log_buffer_->CreateFlushToState(1, mask_);
        log_buffer_->FlushTo(test_writer.get(), *flush_to_state, nullptr);

        auto stats_string = stats_->Format(0, 0, mask_);
        printf("%s\n", stats_string.c_str());
    }

  private:
    LogMask mask_ = kLogMaskAll;
    std::optional<uint64_t> print_point_;
};

class PrintLatency : public SingleBufferOperation {
  public:
    PrintLatency(log_time first_log_timestamp, const char* buffer)
        : SingleBufferOperation(first_log_timestamp, buffer) {}

    void PreOperation() override { operation_start_ = std::chrono::steady_clock::now(); }

    void Operation() override {
        auto end = std::chrono::steady_clock::now();
        auto duration = (end - operation_start_).count();
        durations_.emplace_back(duration);
    }

    void End() {
        std::sort(durations_.begin(), durations_.end());
        auto q1 = durations_.size() / 4;
        auto q2 = durations_.size() / 2;
        auto q3 = 3 * durations_.size() / 4;

        auto p95 = 95 * durations_.size() / 100;
        auto p99 = 99 * durations_.size() / 100;
        auto p9999 = 9999 * durations_.size() / 10000;

        printf("q1: %lld q2: %lld q3: %lld  p95: %lld p99: %lld p99.99: %lld  max: %lld\n",
               durations_[q1], durations_[q2], durations_[q3], durations_[p95], durations_[p99],
               durations_[p9999], durations_.back());
    }

  private:
    std::chrono::steady_clock::time_point operation_start_;
    std::vector<long long> durations_;
};

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s FILE OPERATION [BUFFER] [OPTIONS]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[2], "interesting") != 0 && argc < 4) {
        fprintf(stderr, "Operations other than 'interesting' require a BUFFER argument\n");
        return 1;
    }

    int recorded_messages_fd = open(argv[1], O_RDONLY);
    if (recorded_messages_fd == -1) {
        fprintf(stderr, "Couldn't open input file\n");
        return 1;
    }
    struct stat fd_stat;
    if (fstat(recorded_messages_fd, &fd_stat) != 0) {
        fprintf(stderr, "Couldn't fstat input file\n");
        return 1;
    }
    auto recorded_messages = MappedFile::FromFd(recorded_messages_fd, 0,
                                                static_cast<size_t>(fd_stat.st_size), PROT_READ);
    if (recorded_messages == nullptr) {
        fprintf(stderr, "Couldn't mmap input file\n");
        return 1;
    }

    // LogStatistics typically uses 'now()' to initialize its log range state, but this doesn't work
    // when replaying older logs, so we instead give it the timestamp from the first log.
    log_time first_log_timestamp = GetFirstTimeStamp(*recorded_messages);

    std::unique_ptr<Operation> operation;
    if (!strcmp(argv[2], "interesting")) {
        operation.reset(new PrintInteresting(first_log_timestamp));
    } else if (!strcmp(argv[2], "memory_usage")) {
        operation.reset(new PrintMemory(first_log_timestamp, argv[3]));
    } else if (!strcmp(argv[2], "latency")) {
        operation.reset(new PrintLatency(first_log_timestamp, argv[3]));
    } else if (!strcmp(argv[2], "print_logs")) {
        operation.reset(new PrintLogs(first_log_timestamp, argv[3], argc > 4 ? argv[4] : nullptr,
                                      argc > 5 ? argv[5] : nullptr));
    } else if (!strcmp(argv[2], "nothing")) {
        operation.reset(new SingleBufferOperation(first_log_timestamp, argv[3]));
    } else {
        fprintf(stderr, "unknown operation '%s'\n", argv[2]);
        return 1;
    }

    // LogBuffer::Log() won't log without this on host.
    __android_log_set_minimum_priority(ANDROID_LOG_VERBOSE);
    // But we still want to suppress messages <= error to not interrupt the rest of the output.
    __android_log_set_logger([](const struct __android_log_message* log_message) {
        if (log_message->priority < ANDROID_LOG_ERROR) {
            return;
        }
        __android_log_stderr_logger(log_message);
    });

    operation->Begin();

    uint64_t read_position = 0;
    while (read_position + sizeof(RecordedLogMessage) < recorded_messages->size()) {
        auto* meta =
                reinterpret_cast<RecordedLogMessage*>(recorded_messages->data() + read_position);
        if (read_position + sizeof(RecordedLogMessage) + meta->msg_len >=
            recorded_messages->size()) {
            break;
        }
        char* msg = recorded_messages->data() + read_position + sizeof(RecordedLogMessage);
        read_position += sizeof(RecordedLogMessage) + meta->msg_len;

        operation->Log(*meta, msg);
    }

    operation->End();

    return 0;
}
