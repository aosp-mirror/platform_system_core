/*
 * Copyright (C) 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <log/log_event_list.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif
void reset_log_context(android_log_context ctx);
int write_to_logger(android_log_context context, log_id_t id);
void note_log_drop(int error, int atom_tag);
void stats_log_close();
int android_log_write_char_array(android_log_context ctx, const char* value, size_t len);
extern int (*write_to_statsd)(struct iovec* vec, size_t nr);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/**
 * A copy of android_log_event_list class.
 *
 * android_log_event_list is going to be deprecated soon, so copy it here to
 * avoid creating dependency on upstream code. TODO(b/78304629): Rewrite this
 * code.
 */
class stats_event_list {
  private:
    android_log_context ctx;
    int ret;

    stats_event_list(const stats_event_list&) = delete;
    void operator=(const stats_event_list&) = delete;

  public:
    explicit stats_event_list(int tag) : ret(0) {
        ctx = create_android_logger(static_cast<uint32_t>(tag));
    }
    ~stats_event_list() { android_log_destroy(&ctx); }

    int close() {
        int retval = android_log_destroy(&ctx);
        if (retval < 0) {
            ret = retval;
        }
        return retval;
    }

    /* To allow above C calls to use this class as parameter */
    operator android_log_context() const { return ctx; }

    /* return errors or transmit status */
    int status() const { return ret; }

    int begin() {
        int retval = android_log_write_list_begin(ctx);
        if (retval < 0) {
            ret = retval;
        }
        return ret;
    }
    int end() {
        int retval = android_log_write_list_end(ctx);
        if (retval < 0) {
            ret = retval;
        }
        return ret;
    }

    stats_event_list& operator<<(int32_t value) {
        int retval = android_log_write_int32(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    stats_event_list& operator<<(uint32_t value) {
        int retval = android_log_write_int32(ctx, static_cast<int32_t>(value));
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    stats_event_list& operator<<(bool value) {
        int retval = android_log_write_int32(ctx, value ? 1 : 0);
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    stats_event_list& operator<<(int64_t value) {
        int retval = android_log_write_int64(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    stats_event_list& operator<<(uint64_t value) {
        int retval = android_log_write_int64(ctx, static_cast<int64_t>(value));
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    stats_event_list& operator<<(const char* value) {
        int retval = android_log_write_string8(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    stats_event_list& operator<<(const std::string& value) {
        int retval = android_log_write_string8_len(ctx, value.data(), value.length());
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    stats_event_list& operator<<(float value) {
        int retval = android_log_write_float32(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return *this;
    }

    int write(log_id_t id = LOG_ID_EVENTS) {
        /* facilitate -EBUSY retry */
        if ((ret == -EBUSY) || (ret > 0)) {
            ret = 0;
        }
        int retval = write_to_logger(ctx, id);
        /* existing errors trump transmission errors */
        if (!ret) {
            ret = retval;
        }
        return ret;
    }

    /*
     * Append<Type> methods removes any integer promotion
     * confusion, and adds access to string with length.
     * Append methods are also added for all types for
     * convenience.
     */

    bool AppendInt(int32_t value) {
        int retval = android_log_write_int32(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return ret >= 0;
    }

    bool AppendLong(int64_t value) {
        int retval = android_log_write_int64(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return ret >= 0;
    }

    bool AppendString(const char* value) {
        int retval = android_log_write_string8(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return ret >= 0;
    }

    bool AppendString(const char* value, size_t len) {
        int retval = android_log_write_string8_len(ctx, value, len);
        if (retval < 0) {
            ret = retval;
        }
        return ret >= 0;
    }

    bool AppendString(const std::string& value) {
        int retval = android_log_write_string8_len(ctx, value.data(), value.length());
        if (retval < 0) {
            ret = retval;
        }
        return ret;
    }

    bool Append(const std::string& value) {
        int retval = android_log_write_string8_len(ctx, value.data(), value.length());
        if (retval < 0) {
            ret = retval;
        }
        return ret;
    }

    bool AppendFloat(float value) {
        int retval = android_log_write_float32(ctx, value);
        if (retval < 0) {
            ret = retval;
        }
        return ret >= 0;
    }

    template <typename Tvalue>
    bool Append(Tvalue value) {
        *this << value;
        return ret >= 0;
    }

    bool Append(const char* value, size_t len) {
        int retval = android_log_write_string8_len(ctx, value, len);
        if (retval < 0) {
            ret = retval;
        }
        return ret >= 0;
    }

    bool AppendCharArray(const char* value, size_t len) {
        int retval = android_log_write_char_array(ctx, value, len);
        if (retval < 0) {
            ret = retval;
        }
        return ret >= 0;
    }
};

#endif
