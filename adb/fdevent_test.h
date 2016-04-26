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

#include <gtest/gtest.h>

#include "socket.h"
#include "sysdeps.h"

class FdeventTest : public ::testing::Test {
  protected:
    int dummy = -1;

    static void SetUpTestCase() {
#if !defined(_WIN32)
        ASSERT_NE(SIG_ERR, signal(SIGPIPE, SIG_IGN));
#endif
    }

    void SetUp() override {
        fdevent_reset();
        ASSERT_EQ(0u, fdevent_installed_count());
    }

    // Register a dummy socket used to wake up the fdevent loop to tell it to die.
    void PrepareThread() {
        int dummy_fds[2];
        if (adb_socketpair(dummy_fds) != 0) {
            FAIL() << "failed to create socketpair: " << strerror(errno);
        }

        asocket* dummy_socket = create_local_socket(dummy_fds[1]);
        if (!dummy_socket) {
            FAIL() << "failed to create local socket: " << strerror(errno);
        }
        dummy_socket->ready(dummy_socket);
        dummy = dummy_fds[0];
    }

    size_t GetAdditionalLocalSocketCount() {
#if ADB_HOST
        // dummy socket installed in PrepareThread()
        return 1;
#else
        // dummy socket and one more socket installed in fdevent_subproc_setup()
        return 2;
#endif
    }

    void TerminateThread(adb_thread_t thread) {
        fdevent_terminate_loop();
        ASSERT_TRUE(WriteFdExactly(dummy, "", 1));
        ASSERT_TRUE(adb_thread_join(thread));
        ASSERT_EQ(0, adb_close(dummy));
    }
};
