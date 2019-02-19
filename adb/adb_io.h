/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef ADB_IO_H
#define ADB_IO_H

#include <sys/types.h>

#include <string>

#include "adb_unique_fd.h"

// Sends the protocol "OKAY" message.
bool SendOkay(int fd);

// Sends the protocol "FAIL" message, with the given failure reason.
bool SendFail(int fd, const std::string& reason);

// Writes a protocol-format string; a four hex digit length followed by the string data.
bool SendProtocolString(int fd, const std::string& s);

// Reads a protocol-format string; a four hex digit length followed by the string data.
bool ReadProtocolString(int fd, std::string* s, std::string* error);

// Reads exactly len bytes from fd into buf.
//
// Returns false if there is an error or if EOF was reached before len bytes
// were read. If EOF was found, errno will be set to 0.
//
// If this function fails, the contents of buf are undefined.
bool ReadFdExactly(int fd, void* buf, size_t len);

// Given a client socket, wait for orderly/graceful shutdown. Call this:
//
// * Before closing a client socket.
// * Only when no more data is expected to come in.
// * Only when the server is not waiting for data from the client (because then
//   the client and server will deadlock waiting for each other).
// * Only when the server is expected to close its socket right now.
// * Don't call shutdown(SHUT_WR) before calling this because that will shutdown
//   the client socket early, defeating the purpose of calling this.
//
// Waiting for orderly/graceful shutdown of the server socket will cause the
// server socket to close before the client socket. That prevents the client
// socket from staying in TIME_WAIT which eventually causes subsequent
// connect()s from the client to fail with WSAEADDRINUSE on Windows.
// Returns true if it is sure that orderly/graceful shutdown has occurred with
// no additional data read from the server.
bool ReadOrderlyShutdown(int fd);

// Writes exactly len bytes from buf to fd.
//
// Returns false if there is an error or if the fd was closed before the write
// completed. If the other end of the fd (such as in a socket, pipe, or fifo),
// is closed, errno will be set to 0.
bool WriteFdExactly(int fd, const void* buf, size_t len);

// Same as above, but for strings.
bool WriteFdExactly(int fd, const char* s);
bool WriteFdExactly(int fd, const std::string& s);

// Same as above, but formats the string to send.
bool WriteFdFmt(int fd, const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3)));
#endif /* ADB_IO_H */
