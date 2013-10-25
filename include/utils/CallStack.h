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

#ifndef ANDROID_CALLSTACK_H
#define ANDROID_CALLSTACK_H

#include <android/log.h>
#include <utils/String8.h>
#include <corkscrew/backtrace.h>

#include <stdint.h>
#include <sys/types.h>

namespace android {

class Printer;

// Collect/print the call stack (function, file, line) traces for a single thread.
class CallStack {
public:
    enum {
        // Prune the lowest-most stack frames until we have at most MAX_DEPTH.
        MAX_DEPTH = 31,
        // Placeholder for specifying the current thread when updating the stack.
        CURRENT_THREAD = -1,
    };

    // Create an empty call stack. No-op.
    CallStack();
    // Create a callstack with the current thread's stack trace.
    // Immediately dump it to logcat using the given logtag.
    CallStack(const char* logtag, int32_t ignoreDepth=1,
            int32_t maxDepth=MAX_DEPTH);
    // Copy the existing callstack (no other side effects).
    CallStack(const CallStack& rhs);
    ~CallStack();

    // Copy the existing callstack (no other side effects).
    CallStack& operator = (const CallStack& rhs);

    // Compare call stacks by their backtrace frame memory.
    bool operator == (const CallStack& rhs) const;
    bool operator != (const CallStack& rhs) const;
    bool operator < (const CallStack& rhs) const;
    bool operator >= (const CallStack& rhs) const;
    bool operator > (const CallStack& rhs) const;
    bool operator <= (const CallStack& rhs) const;

    // Get the PC address for the stack frame specified by index.
    const void* operator [] (int index) const;

    // Reset the stack frames (same as creating an empty call stack).
    void clear();

    // Immediately collect the stack traces for the specified thread.
    void update(int32_t ignoreDepth=1, int32_t maxDepth=MAX_DEPTH, pid_t tid=CURRENT_THREAD);

    // Dump a stack trace to the log using the supplied logtag.
    void log(const char* logtag,
             android_LogPriority priority = ANDROID_LOG_DEBUG,
             const char* prefix = 0) const;

    // Dump a stack trace to the specified file descriptor.
    void dump(int fd, int indent = 0, const char* prefix = 0) const;

    // Return a string (possibly very long) containing the complete stack trace.
    String8 toString(const char* prefix = 0) const;

    // Dump a serialized representation of the stack trace to the specified printer.
    void print(Printer& printer) const;

    // Get the count of stack frames that are in this call stack.
    size_t size() const { return mCount; }

private:
    size_t mCount;
    backtrace_frame_t mStack[MAX_DEPTH];
};

}; // namespace android

#endif // ANDROID_CALLSTACK_H
