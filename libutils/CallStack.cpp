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

#include <utils/Printer.h>
#include <utils/Errors.h>
#include <log/log.h>

#include <unwindstack/AndroidUnwinder.h>

#define CALLSTACK_WEAK  // Don't generate weak definitions.
#include <utils/CallStack.h>

namespace android {

CallStack::CallStack() {
}

CallStack::CallStack(const char* logtag, int32_t ignoreDepth) {
    this->update(ignoreDepth+1);
    this->log(logtag);
}

CallStack::~CallStack() {
}

void CallStack::update(int32_t ignoreDepth, pid_t tid) {
    if (ignoreDepth < 0) {
        ignoreDepth = 0;
    }

    mFrameLines.clear();

    unwindstack::AndroidLocalUnwinder unwinder;
    unwindstack::AndroidUnwinderData data;
    std::optional<pid_t> tid_val;
    if (tid != -1) {
        tid_val = tid;
    }
    if (!unwinder.Unwind(tid_val, data)) {
        ALOGW("%s: Failed to unwind callstack: %s", __FUNCTION__, data.GetErrorString().c_str());
    }
    for (size_t i = ignoreDepth; i < data.frames.size(); i++) {
        auto& frame = data.frames[i];
        frame.num -= ignoreDepth;
        mFrameLines.push_back(String8(unwinder.FormatFrame(frame).c_str()));
    }
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
    for (size_t i = 0; i < mFrameLines.size(); i++) {
        printer.printLine(mFrameLines[i].c_str());
    }
}

// The following four functions may be used via weak symbol references from libutils.
// Clients assume that if any of these symbols are available, then deleteStack() is.

// Apple and Windows does not support this, so only compile on other platforms.
#if !defined(__APPLE__) && !defined(_WIN32)

CallStack::CallStackUPtr CallStack::getCurrentInternal(int ignoreDepth) {
    CallStack::CallStackUPtr stack(new CallStack());
    stack->update(ignoreDepth + 1);
    return stack;
}

void CallStack::logStackInternal(const char* logtag, const CallStack* stack,
                                 android_LogPriority priority) {
    stack->log(logtag, priority);
}

String8 CallStack::stackToStringInternal(const char* prefix, const CallStack* stack) {
    return stack->toString(prefix);
}

void CallStack::deleteStack(CallStack* stack) {
    delete stack;
}

#endif  // !defined(__APPLE__) && !defined(_WIN32)

}; // namespace android
