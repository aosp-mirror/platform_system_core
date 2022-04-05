// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Functionality for communicating with Trusty services.
//!
//! This crate provides the [`TipcChannel`] type, which allows you to establish a
//! connection to a Trusty service and then communicate with that service.
//!
//! # Usage
//!
//! To connect to a Trusty service you need two things:
//!
//! * The filesystem path to the Trusty IPC device. This is usually
//!   `/dev/trusty-ipc-dev0`, which is exposed in the constant [`DEFAULT_DEVICE`].
//! * The port name defined by the service, e.g. `com.android.ipc-unittest.srv.echo`.
//!
//! Pass these values to [`TipcChannel::connect`] to establish a connection to a
//! service.
//!
//! Once connected use the [`send`][TipcChannel::send] and [`recv`][TipcChannel::recv]
//! methods to communicate with the service. Messages are passed as byte buffers, and
//! each Trusty service has its own protocol for what data messages are expected to
//! contain. Consult the documentation for the service you are communicating with to
//! determine how to format outgoing messages and interpret incoming ones.
//!
//! The connection is closed automatically when [`TipcChannel`] is dropped.
//!
//! # Examples
//!
//! This example is a simplified version of the echo test from `tipc-test-rs`:
//!
//! ```no_run
//! use trusty::{DEFAULT_DEVICE, TipcChannel};
//! use std::io::{Read, Write};
//!
//! let mut chann = TipcChannel::connect(
//!     DEFAULT_DEVICE,
//!     "com.android.ipc-unittest.srv.echo",
//! ).unwrap();
//!
//! chann.send("Hello, world!".as_bytes()).unwrap();
//!
//! let mut read_buf = [0u8; 1024];
//! let read_len = stream.read(&mut read_buf[..]).unwrap();
//!
//! let response = std::str::from_utf8(&read_buf[..read_len]).unwrap();
//! assert_eq!("Hello, world!", response);
//!
//! // The connection is closed here.
//! ```

use crate::sys::tipc_connect;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::os::unix::prelude::AsRawFd;
use std::path::Path;

mod sys;

/// The default filesystem path for the Trusty IPC device.
pub const DEFAULT_DEVICE: &str = "/dev/trusty-ipc-dev0";

/// A channel for communicating with a Trusty service.
///
/// See the [crate-level documentation][crate] for usage details and examples.
#[derive(Debug)]
pub struct TipcChannel(File);

impl TipcChannel {
    /// Attempts to establish a connection to the specified Trusty service.
    ///
    /// The first argument is the path of the Trusty device in the local filesystem,
    /// e.g. `/dev/trusty-ipc-dev0`. The second argument is the name of the service
    /// to connect to, e.g. `com.android.ipc-unittest.srv.echo`.
    ///
    /// # Panics
    ///
    /// This function will panic if `service` contains any intermediate `NUL`
    /// bytes. This is handled with a panic because the service names are all
    /// hard-coded constants, and so such an error should always be indicative of a
    /// bug in the calling code.
    pub fn connect(device: impl AsRef<Path>, service: &str) -> io::Result<Self> {
        let file = File::options().read(true).write(true).open(device)?;

        let srv_name = CString::new(service).expect("Service name contained null bytes");
        unsafe {
            tipc_connect(file.as_raw_fd(), srv_name.as_ptr())?;
        }

        Ok(TipcChannel(file))
    }

    /// Sends a message to the connected service.
    ///
    /// The entire contents of `buf` will be sent as a single message to the
    /// connected service.
    pub fn send(&mut self, buf: &[u8]) -> io::Result<()> {
        let write_len = self.0.write(buf)?;

        // Verify that the expected number of bytes were written. The entire message
        // should always be written with a single `write` call, or an error should have
        // been returned if the message couldn't be written. An assertion failure here
        // potentially means a bug in the kernel driver.
        assert_eq!(
            buf.len(),
            write_len,
            "Failed to send full message ({} of {} bytes written)",
            write_len,
            buf.len(),
        );

        Ok(())
    }

    /// Receives a message from the connected service.
    ///
    /// Returns the number of bytes in the received message, or any error that
    /// occurred when reading the message. A return value of 0 indicates that
    /// there were no incoming messages to receive.
    ///
    /// # Errors
    ///
    /// Returns an error with native error code 90 (`EMSGSIZE`) if `buf` isn't
    /// large enough to contain the incoming message. Use
    /// [`raw_os_error`][std::io::Error::raw_os_error] to check the error code
    /// to determine if you need to increase the size of `buf`.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    // TODO: Add method that is equivalent to `tipc_send`, i.e. that supports
    // sending shared memory buffers.
}
