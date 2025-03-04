// Copyright (C) 2024 The Android Open Source Project
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

//! A library to prefetch files on the file system to optimize startup times
//!

mod args;
mod error;
mod format;
mod replay;
mod tracer;
#[cfg(target_os = "android")]
mod arch {
    pub mod android;
}

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::string::ToString;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "android")]
use log::Level;
#[cfg(target_os = "linux")]
use log::LevelFilter;

pub use args::args_from_env;
use args::OutputFormat;
pub use args::ReplayArgs;
pub use args::{DumpArgs, MainArgs, RecordArgs, SubCommands};
pub use error::Error;
pub use format::FileId;
pub use format::InodeInfo;
pub use format::Record;
pub use format::RecordsFile;
use log::info;
pub use replay::Replay;
pub use tracer::nanoseconds_since_boot;

#[cfg(target_os = "android")]
pub use arch::android::*;

/// Records prefetch data for the given configuration
pub fn record(args: &RecordArgs) -> Result<(), Error> {
    #[cfg(target_os = "android")]
    if !ensure_record_is_ready(&args.ready_path, &args.path, &args.build_fingerprint_path)? {
        info!("Cannot perform record -- skipping");
        return Ok(());
    }

    info!("Starting record.");
    let (mut tracer, exit_tx) = tracer::Tracer::create(
        args.trace_buffer_size_kib,
        args.tracing_subsystem.clone(),
        args.tracing_instance.clone(),
        args.setup_tracing,
    )?;
    let duration = Duration::from_secs(args.duration as u64);

    let thd = thread::spawn(move || {
        if !duration.is_zero() {
            info!("Record start - waiting for duration: {:?}", duration);
            thread::sleep(duration);
        } else {
            #[cfg(target_os = "android")]
            wait_for_record_stop();
        }

        info!("Prefetch record exiting");
        // We want to unwrap here on failure to send this signal. Otherwise
        // tracer will continue generating huge records data.
        exit_tx.send(()).unwrap();
    });

    let mut rf = tracer.trace(args.int_path.as_ref())?;
    thd.join()
        .map_err(|_| Error::ThreadPool { error: "Failed to join timeout thread".to_string() })?;

    let mut out_file =
        OpenOptions::new().write(true).create(true).truncate(true).open(&args.path).map_err(
            |source| Error::Create { source, path: args.path.to_str().unwrap().to_owned() },
        )?;

    std::fs::set_permissions(&args.path, std::fs::Permissions::from_mode(0o644))
        .map_err(|source| Error::Create { source, path: args.path.to_str().unwrap().to_owned() })?;

    // Write the record file
    out_file
        .write_all(&rf.add_checksum_and_serialize()?)
        .map_err(|source| Error::Write { path: args.path.to_str().unwrap().to_owned(), source })?;
    out_file.sync_all()?;

    // Write build-finger-print file
    #[cfg(target_os = "android")]
    write_build_fingerprint(args)?;

    Ok(())
}

/// Replays prefetch data for the given configuration
pub fn replay(args: &ReplayArgs) -> Result<(), Error> {
    #[cfg(target_os = "android")]
    if !can_perform_replay(&args.path, &args.build_fingerprint_path)? {
        info!("Cannot perform replay -- exiting.");
        return Ok(());
    }

    info!("Starting replay.");
    let replay = Replay::new(args)?;
    replay.replay()
}

/// Dumps prefetch data in the human readable form
pub fn dump(args: &DumpArgs) -> Result<(), Error> {
    let reader = File::open(&args.path)
        .map_err(|source| Error::Open { source, path: args.path.to_str().unwrap().to_string() })?;
    let rf: RecordsFile =
        serde_cbor::from_reader(reader).map_err(|e| Error::Deserialize { error: e.to_string() })?;
    match args.format {
        OutputFormat::Json => println!(
            "{:#}",
            serde_json::to_string_pretty(&rf)
                .map_err(|e| Error::Serialize { error: e.to_string() })?
        ),
        OutputFormat::Csv => rf.serialize_records_to_csv(&mut io::stdout())?,
    }
    Ok(())
}

/// An alias of android_logger::Level to use log level across android and linux.
#[cfg(target_os = "android")]
pub type LogLevel = Level;

/// An alias of log::LevelFilter to use log level across android and linux.
#[cfg(not(target_os = "android"))]
pub type LogLevel = LevelFilter;

/// Convenience logging initializer that is shared between the prefetch tool and c wrapper library
#[cfg(target_os = "android")]
pub fn init_logging(_level: LogLevel) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info).format(
            |f, record| {
                write!(
                    f,
                    "{} prefetch_rs: {}:{} {}: {}",
                    nanoseconds_since_boot(),
                    record.file().unwrap_or("unknown_file"),
                    record.line().unwrap_or(0),
                    record.level(),
                    record.args()
                )
            },
        ),
    )
}

/// Convenience logging initializer that is shared between the prefetch tool and c wrapper library
#[cfg(target_os = "linux")]
pub fn init_logging(level: LogLevel) {
    let mut builder = env_logger::Builder::from_default_env();

    builder
        .filter(None, level)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} prefetch_rs: {}:{} {}: {}",
                nanoseconds_since_boot(),
                record.file().unwrap_or("unknown_file"),
                record.line().unwrap_or(0),
                record.level(),
                record.args()
            )
        })
        .init();
}
