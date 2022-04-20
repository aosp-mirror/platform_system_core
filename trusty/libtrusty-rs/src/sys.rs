// NOTE: The ioctl definitions are sequestered into this module because the
// `ioctl_*!` macros provided by the nix crate generate public functions that we
// don't want to be part of this crate's public API.
//
// NOTE: We are manually re-declaring the types and constants here instead of using
// bindgen and a separate `-sys` crate because the defines used for the ioctl
// numbers (`TIPC_IOC_CONNECT` and `TIPC_IOC_SEND_MSG`) can't currently be
// translated by bindgen.

use std::os::raw::c_char;

const TIPC_IOC_MAGIC: u8 = b'r';

// NOTE: We use `ioctl_write_ptr_bad!` here due to an error in how the ioctl
// code is defined in `trusty/ipc.h`.
//
// If we were to do `ioctl_write_ptr!(TIPC_IOC_MAGIC, 0x80, c_char)` it would
// generate a function that takes a `*const c_char` data arg and would use
// `size_of::<c_char>()` when generating the ioctl number. However, in
// `trusty/ipc.h` the definition for `TIPC_IOC_CONNECT` declares the ioctl with
// `char*`, meaning we need to use `size_of::<*const c_char>()` to generate an
// ioctl number that matches what Trusty expects.
//
// To maintain compatibility with the `trusty/ipc.h` and the kernel driver we
// use `ioctl_write_ptr_bad!` and manually use `request_code_write!` to generate
// the ioctl number using the correct size.
nix::ioctl_write_ptr_bad!(
    tipc_connect,
    nix::request_code_write!(TIPC_IOC_MAGIC, 0x80, std::mem::size_of::<*const c_char>()),
    c_char
);
