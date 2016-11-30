/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "sysdeps/errno.h"

#include <windows.h>

#include <string>

// Overrides strerror() to handle error codes not supported by the Windows C
// Runtime (MSVCRT.DLL).
char* adb_strerror(int err) {
// sysdeps.h defines strerror to adb_strerror, but in this function, we
// want to call the real C Runtime strerror().
#pragma push_macro("strerror")
#undef strerror
    const int saved_err = errno;  // Save because we overwrite it later.

    // Lookup the string for an unknown error.
    char* errmsg = strerror(-1);
    const std::string unknown_error = (errmsg == nullptr) ? "" : errmsg;

    // Lookup the string for this error to see if the C Runtime has it.
    errmsg = strerror(err);
    if (errmsg != nullptr && unknown_error != errmsg) {
        // The CRT returned an error message and it is different than the error
        // message for an unknown error, so it is probably valid, so use it.
    } else {
        // Check if we have a string for this error code.
        const char* custom_msg = nullptr;
        switch (err) {
#pragma push_macro("ERR")
#undef ERR
#define ERR(errnum, desc) case errnum: custom_msg = desc; break
            // These error strings are from AOSP bionic/libc/include/sys/_errdefs.h.
            // Note that these cannot be longer than 94 characters because we
            // pass this to _strerror() which has that requirement.
            ERR(ECONNRESET,    "Connection reset by peer");
            ERR(EHOSTUNREACH,  "No route to host");
            ERR(ENETDOWN,      "Network is down");
            ERR(ENETRESET,     "Network dropped connection because of reset");
            ERR(ENOBUFS,       "No buffer space available");
            ERR(ENOPROTOOPT,   "Protocol not available");
            ERR(ENOTCONN,      "Transport endpoint is not connected");
            ERR(ENOTSOCK,      "Socket operation on non-socket");
            ERR(EOPNOTSUPP,    "Operation not supported on transport endpoint");
#pragma pop_macro("ERR")
        }

        if (custom_msg != nullptr) {
            // Use _strerror() to write our string into the writable per-thread
            // buffer used by strerror()/_strerror(). _strerror() appends the
            // msg for the current value of errno, so set errno to a consistent
            // value for every call so that our code-path is always the same.
            errno = 0;
            errmsg = _strerror(custom_msg);
            const size_t custom_msg_len = strlen(custom_msg);
            // Just in case _strerror() returned a read-only string, check if
            // the returned string starts with our custom message because that
            // implies that the string is not read-only.
            if ((errmsg != nullptr) && !strncmp(custom_msg, errmsg, custom_msg_len)) {
                // _strerror() puts other text after our custom message, so
                // remove that by terminating after our message.
                errmsg[custom_msg_len] = '\0';
            } else {
                // For some reason nullptr was returned or a pointer to a
                // read-only string was returned, so fallback to whatever
                // strerror() can muster (probably "Unknown error" or some
                // generic CRT error string).
                errmsg = strerror(err);
            }
        } else {
            // We don't have a custom message, so use whatever strerror(err)
            // returned earlier.
        }
    }

    errno = saved_err;  // restore

    return errmsg;
#pragma pop_macro("strerror")
}
