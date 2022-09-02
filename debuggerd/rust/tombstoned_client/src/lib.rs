// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Rust wrapper for tombstoned client.

pub use ffi::DebuggerdDumpType;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use thiserror::Error;

/// Error communicating with tombstoned.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("Error communicating with tombstoned")]
pub struct Error;

/// File descriptors for communicating with tombstoned.
pub struct TombstonedConnection {
    /// The socket connection to tombstoned.
    ///
    /// This is actually a Unix SOCK_SEQPACKET socket not a file, but the Rust standard library
    /// doesn't have an appropriate type and it's not really worth bringing in a dependency on `uds`
    /// or something when all we do is pass it back to C++ or close it.
    tombstoned_socket: File,
    /// The file descriptor for text output.
    pub text_output: Option<File>,
    /// The file descriptor for proto output.
    pub proto_output: Option<File>,
}

impl TombstonedConnection {
    unsafe fn from_raw_fds(
        tombstoned_socket: RawFd,
        text_output_fd: RawFd,
        proto_output_fd: RawFd,
    ) -> Self {
        Self {
            tombstoned_socket: File::from_raw_fd(tombstoned_socket),
            text_output: if text_output_fd >= 0 {
                Some(File::from_raw_fd(text_output_fd))
            } else {
                None
            },
            proto_output: if proto_output_fd >= 0 {
                Some(File::from_raw_fd(proto_output_fd))
            } else {
                None
            },
        }
    }

    /// Connects to tombstoned.
    pub fn connect(pid: i32, dump_type: DebuggerdDumpType) -> Result<Self, Error> {
        let mut tombstoned_socket = -1;
        let mut text_output_fd = -1;
        let mut proto_output_fd = -1;
        if ffi::tombstoned_connect_files(
            pid,
            &mut tombstoned_socket,
            &mut text_output_fd,
            &mut proto_output_fd,
            dump_type,
        ) {
            Ok(unsafe { Self::from_raw_fds(tombstoned_socket, text_output_fd, proto_output_fd) })
        } else {
            Err(Error)
        }
    }

    /// Notifies tombstoned that the dump is complete.
    pub fn notify_completion(&self) -> Result<(), Error> {
        if ffi::tombstoned_notify_completion(self.tombstoned_socket.as_raw_fd()) {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

#[cxx::bridge]
mod ffi {
    /// The type of dump.
    enum DebuggerdDumpType {
        /// A native backtrace.
        #[cxx_name = "kDebuggerdNativeBacktrace"]
        NativeBacktrace,
        /// A tombstone.
        #[cxx_name = "kDebuggerdTombstone"]
        Tombstone,
        /// A Java backtrace.
        #[cxx_name = "kDebuggerdJavaBacktrace"]
        JavaBacktrace,
        /// Any intercept.
        #[cxx_name = "kDebuggerdAnyIntercept"]
        AnyIntercept,
        /// A tombstone proto.
        #[cxx_name = "kDebuggerdTombstoneProto"]
        TombstoneProto,
    }

    unsafe extern "C++" {
        include!("wrapper.hpp");

        type DebuggerdDumpType;

        fn tombstoned_connect_files(
            pid: i32,
            tombstoned_socket: &mut i32,
            text_output_fd: &mut i32,
            proto_output_fd: &mut i32,
            dump_type: DebuggerdDumpType,
        ) -> bool;

        fn tombstoned_notify_completion(tombstoned_socket: i32) -> bool;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, process};

    // Verify that we can connect to tombstoned, write something to the file descriptor it returns,
    // and notify completion, without any errors.
    #[test]
    fn test() {
        let connection =
            TombstonedConnection::connect(process::id() as i32, DebuggerdDumpType::Tombstone)
                .expect("Failed to connect to tombstoned.");

        assert!(connection.proto_output.is_none());
        connection
            .text_output
            .as_ref()
            .expect("No text output FD returned.")
            .write_all(b"test data")
            .expect("Failed to write to text output FD.");

        connection
            .notify_completion()
            .expect("Failed to notify completion.");
    }
}
