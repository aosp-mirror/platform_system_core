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
//! let mut read_buf = Vec::new();
//! let read_len = stream.recv(&mut read_buf).unwrap();
//!
//! let response = std::str::from_utf8(&read_buf[..read_len]).unwrap();
//! assert_eq!("Hello, world!", response);
//!
//! // The connection is closed here.
//! ```

use crate::sys::tipc_connect;
use std::ffi::CString;
use std::fs::File;
use std::io::prelude::*;
use std::io::{ErrorKind, Result};
use std::os::unix::prelude::AsRawFd;
use std::path::Path;

mod sys;

/// The default filesystem path for the Trusty IPC device.
pub const DEFAULT_DEVICE: &str = "/dev/trusty-ipc-dev0";

/// The maximum size an incoming TIPC message can be.
///
/// This can be used to pre-allocate buffer space in order to ensure that your
/// read buffer can always hold an incoming message.
pub const MAX_MESSAGE_SIZE: usize = 4096;

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
    pub fn connect(device: impl AsRef<Path>, service: &str) -> Result<Self> {
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
    pub fn send(&mut self, buf: &[u8]) -> Result<()> {
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

    /// Reads the next incoming message.
    ///
    /// Attempts to read the next incoming message from the connected service if any
    /// exist. If the initial capacity of `buf` is not enough to hold the incoming
    /// message the function repeatedly attempts to reserve additional space until
    /// it is able to fully read the message.
    ///
    /// Blocks until there is an incoming message if there is not already a message
    /// ready to be received.
    ///
    /// # Errors
    ///
    /// If this function encounters an error of the kind [`ErrorKind::Interrupted`]
    /// then the error is ignored and the operation will be tried again.
    ///
    /// If this function encounters an error with the error code `EMSGSIZE` then
    /// additional space will be reserved in `buf` and the operation will be tried
    /// again.
    ///
    /// If any other read error is encountered then this function immediately
    /// returns the error to the caller, and the length of `buf` is set to 0.
    pub fn recv(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        // If no space has been allocated in the buffer reserve enough space to hold any
        // incoming message.
        if buf.capacity() == 0 {
            buf.reserve(MAX_MESSAGE_SIZE);
        }

        loop {
            // Resize the vec to make its full capacity available to write into.
            buf.resize(buf.capacity(), 0);

            match self.0.read(buf.as_mut_slice()) {
                Ok(len) => {
                    buf.truncate(len);
                    return Ok(());
                }

                Err(err) => {
                    if let Some(libc::EMSGSIZE) = err.raw_os_error() {
                        // Ensure that we didn't get `EMSGSIZE` when we already had enough capacity
                        // to contain the maximum message size. This should never happen, but if it
                        // does we don't want to hang by looping infinitely.
                        assert!(
                            buf.capacity() < MAX_MESSAGE_SIZE,
                            "Received `EMSGSIZE` error when buffer capacity was already at maximum",
                        );

                        // If we didn't have enough space to hold the incoming message, reserve
                        // enough space to fit the maximum message size regardless of how much
                        // capacity the buffer already had.
                        buf.reserve(MAX_MESSAGE_SIZE - buf.capacity());
                    } else if err.kind() == ErrorKind::Interrupted {
                        // If we get an interrupted error the operation can be retried as-is, i.e.
                        // we don't need to allocate additional space.
                        continue;
                    } else {
                        buf.truncate(0);
                        return Err(err);
                    }
                }
            }
        }
    }

    /// Reads the next incoming message without allocating.
    ///
    /// Returns the number of bytes in the received message, or any error that
    /// occurred when reading the message.
    ///
    /// Blocks until there is an incoming message if there is not already a message
    /// ready to be received.
    ///
    /// # Errors
    ///
    /// Returns an error with native error code `EMSGSIZE` if `buf` isn't large
    /// enough to contain the incoming message. Use
    /// [`raw_os_error`][std::io::Error::raw_os_error] to check the error code to
    /// determine if you need to increase the size of `buf`. If error code
    /// `EMSGSIZE` is returned the incoming message will not be dropped, and a
    /// subsequent call to `recv_no_alloc` can still read it.
    ///
    /// An error of the [`ErrorKind::Interrupted`] kind is non-fatal and the read
    /// operation should be retried if there is nothing else to do.
    pub fn recv_no_alloc(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.read(buf)
    }

    // TODO: Add method that is equivalent to `tipc_send`, i.e. that supports
    // sending shared memory buffers.
}
