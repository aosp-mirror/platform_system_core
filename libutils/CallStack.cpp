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

#define LOG_TAG "CallStack"

#include <utils/CallStack.h>
#include <utils/Printer.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <corkscrew/backtrace.h>

namespace android {

CallStack::CallStack() :
        mCount(0) {
}

CallStack::CallStack(const char* logtag, int32_t ignoreDepth, int32_t maxDepth) {
    this->update(ignoreDepth+1, maxDepth, CURRENT_THREAD);
    this->log(logtag);
}

CallStack::CallStack(const CallStack& rhs) :
        mCount(rhs.mCount) {
    if (mCount) {
        memcpy(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t));
    }
}

CallStack::~CallStack() {
}

CallStack& CallStack::operator = (const CallStack& rhs) {
    mCount = rhs.mCount;
    if (mCount) {
        memcpy(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t));
    }
    return *this;
}

bool CallStack::operator == (const CallStack& rhs) const {
    if (mCount != rhs.mCount)
        return false;
    return !mCount || memcmp(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t)) == 0;
}

bool CallStack::operator != (const CallStack& rhs) const {
    return !operator == (rhs);
}

bool CallStack::operator < (const CallStack& rhs) const {
    if (mCount != rhs.mCount)
        return mCount < rhs.mCount;
    return memcmp(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t)) < 0;
}

bool CallStack::operator >= (const CallStack& rhs) const {
    return !operator < (rhs);
}

bool CallStack::operator > (const CallStack& rhs) const {
    if (mCount != rhs.mCount)
        return mCount > rhs.mCount;
    return memcmp(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t)) > 0;
}

bool CallStack::operator <= (const CallStack& rhs) const {
    return !operator > (rhs);
}

const void* CallStack::operator [] (int index) const {
    if (index >= int(mCount))
        return 0;
    return reinterpret_cast<const void*>(mStack[index].absolute_pc);
}

void CallStack::clear() {
    mCount = 0;
}

void CallStack::update(int32_t ignoreDepth, int32_t maxDepth, pid_t tid) {
    if (maxDepth > MAX_DEPTH) {
        maxDepth = MAX_DEPTH;
    }
    ssize_t count;

    if (tid >= 0) {
        count = unwind_backtrace_thread(tid, mStack, ignoreDepth + 1, maxDepth);
    } else if (tid == CURRENT_THREAD) {
        count = unwind_backtrace(mStack, ignoreDepth + 1, maxDepth);
    } else {
        ALOGE("%s: Invalid tid specified (%d)", __FUNCTION__, tid);
        count = 0;
    }

    mCount = count > 0 ? count : 0;
}

void CallStack::log(const char* logtag, android_LogPriority priority, const char* prefix) const {
    LogPrinter printer(logtag, priority, prefix, /*ignoreBlankLines*/false);
    print(printer);
}

void CallStack::dump(int fd, int indent, const char* prefix) const {
    FdPrinter printer(fd, indent, prefix);
    print(printer);
}

String8 CallStack::toString(const char* prefix) const {
    String8 str;

    String8Printer printer(&str, prefix);
    print(printer);

    return str;
}

void CallStack::print(Printer& printer) const {
    backtrace_symbol_t symbols[mCount];

    get_backtrace_symbols(mStack, mCount, symbols);
    for (size_t i = 0; i < mCount; i++) {
        char line[MAX_BACKTRACE_LINE_LENGTH];
        format_backtrace_line(i, &mStack[i], &symbols[i],
                line, MAX_BACKTRACE_LINE_LENGTH);
        printer.printLine(line);
    }
    free_backtrace_symbols(symbols, mCount);
}

}; // namespace android
