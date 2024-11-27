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

use std::{option::Option, path::PathBuf, result::Result::Ok, str::FromStr};

use argh::FromArgs;
use serde::Deserialize;

use crate::args::DEFAULT_EXIT_ON_ERROR;
use crate::args::DEFAULT_IO_DEPTH;
use crate::args::DEFAULT_MAX_FDS;
use crate::Error;

/// prefetch-rs
#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
pub struct MainArgs {
    /// subcommands
    #[argh(subcommand)]
    pub nested: SubCommands,
}

/// Sub commands for prefetch functions
#[derive(Eq, PartialEq, Debug, FromArgs)]
#[argh(subcommand)]
pub enum SubCommands {
    /// Records prefetch data.
    Record(RecordArgs),
    /// Replays from prefetch data
    Replay(ReplayArgs),
    /// Dump prefetch data in human readable format
    Dump(DumpArgs),
    /// Start prefetch service if possible
    /// If the pack file is present, then prefetch replay is started
    /// If the pack file is absent or if the build fingerprint
    /// of the current pack file is different, then prefetch record is started.
    #[cfg(target_os = "android")]
    Start(StartArgs),
}

#[cfg(target_os = "android")]
fn default_ready_path() -> PathBuf {
    PathBuf::from("/metadata/prefetch/prefetch_ready")
}

#[cfg(target_os = "android")]
fn default_build_finger_print_path() -> PathBuf {
    PathBuf::from("/metadata/prefetch/build_finger_print")
}

#[cfg(target_os = "android")]
#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
/// Start prefetch service based on if pack file is present.
#[argh(subcommand, name = "start")]
pub struct StartArgs {
    /// file path to check if prefetch_ready is present.
    ///
    /// A new file is created at the given path if it's not present.
    #[argh(option, default = "default_ready_path()")]
    pub path: PathBuf,

    /// file path where build fingerprint is stored
    #[argh(option, default = "default_build_finger_print_path()")]
    pub build_fingerprint_path: PathBuf,
}

impl Default for SubCommands {
    fn default() -> Self {
        Self::Dump(DumpArgs::default())
    }
}

fn default_path() -> PathBuf {
    PathBuf::from("/metadata/prefetch/prefetch.pack")
}

fn parse_tracing_instance(value: &str) -> Result<Option<String>, String> {
    Ok(Some(value.to_string()))
}

#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
/// Records prefect data.
#[argh(subcommand, name = "record")]
pub struct RecordArgs {
    /// duration in seconds to record the data
    ///
    /// On Android, if duration count is set to zero, recording
    /// will continue until the property sys.boot_completed = 1.
    #[argh(option)]
    pub duration: u16,

    /// file path where the records will be written to
    ///
    /// A new file is created at the given path. If the path exists, it
    /// will be overwritten
    #[argh(option, default = "default_path()")]
    pub path: PathBuf,

    /// when set an intermediate file will be created that provides more information
    /// about collected data.
    #[argh(option, default = "false")]
    pub debug: bool,

    /// file path where the intermediate file will be written to
    ///
    /// A new file is created at the given path. Errors out if the file
    /// already exists.
    #[argh(option)]
    pub int_path: Option<PathBuf>,

    /// size of the trace buffer which holds trace events. We need larger
    /// buffer on a system that has faster disks or has large number of events
    /// enabled. Defaults to TRACE_BUFFER_SIZE_KIB KiB.
    #[argh(option, long = "trace-buffer-size")]
    pub trace_buffer_size_kib: Option<u64>,

    /// trace subsystem to use. "mem" subsystem is set by default.
    #[argh(option, default = "Default::default()")]
    pub tracing_subsystem: TracerType,

    /// if true enables all the needed trace events. And at the end it restores
    /// the values of those events.
    /// If false, assumes that user has setup the needed trace events.
    #[argh(option, default = "true")]
    pub setup_tracing: bool,

    /// if specified, works on a tracing instance (like /sys/kernel/tracing/instance/my_instance)
    /// rather than using on shared global instance (i.e. /sys/kernel/tracing)."
    #[argh(
        option,
        default = "Some(\"prefetch\".to_string())",
        from_str_fn(parse_tracing_instance)
    )]
    pub tracing_instance: Option<String>,

    #[cfg(target_os = "android")]
    /// store build_finger_print to tie the pack format
    #[argh(option, default = "default_build_finger_print_path()")]
    pub build_fingerprint_path: PathBuf,
}

/// Type of tracing subsystem to use.
#[derive(Deserialize, Clone, Eq, PartialEq, Debug)]
pub enum TracerType {
    /// mem tracing subsystem relies on when a file's in-memory page gets added to the fs cache.
    Mem,
}

impl FromStr for TracerType {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "mem" => Self::Mem,
            _ => {
                return Err(Error::InvalidArgs {
                    arg_name: "tracing_subsystem".to_owned(),
                    arg_value: s.to_owned(),
                    error: "unknown value".to_owned(),
                })
            }
        })
    }
}

impl Default for TracerType {
    fn default() -> Self {
        Self::Mem
    }
}

#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
/// Prefetch data from the recorded file.
#[argh(subcommand, name = "replay")]
pub struct ReplayArgs {
    /// file path from where the records will be read
    #[argh(option, default = "default_path()")]
    pub path: PathBuf,

    /// IO depth. Number of IO that can go in parallel.
    #[argh(option, long = "io-depth", default = "DEFAULT_IO_DEPTH")]
    pub io_depth: u16,

    /// max number of open fds to cache
    #[argh(option, arg_name = "max-fds", default = "DEFAULT_MAX_FDS")]
    pub max_fds: u16,

    /// if true, command exits on encountering any error.
    ///
    /// This defaults to false as there is not harm prefetching if we encounter
    /// non-fatal errors.
    #[argh(option, default = "DEFAULT_EXIT_ON_ERROR")]
    pub exit_on_error: bool,

    /// file path from where the prefetch config file will be read
    #[argh(option, default = "PathBuf::new()")]
    pub config_path: PathBuf,
}

/// dump records file in given format
#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
#[argh(subcommand, name = "dump")]
pub struct DumpArgs {
    /// file path from where the records will be read
    #[argh(option)]
    pub path: PathBuf,
    /// output format. One of json or csv.
    /// Note: In csv format, few fields are excluded from the output.
    #[argh(option)]
    pub format: OutputFormat,
}

#[derive(Deserialize, Eq, PartialEq, Debug)]
pub enum OutputFormat {
    Json,
    Csv,
}

impl FromStr for OutputFormat {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "csv" => Self::Csv,
            "json" => Self::Json,
            _ => {
                return Err(Error::InvalidArgs {
                    arg_name: "format".to_owned(),
                    arg_value: s.to_owned(),
                    error: "unknown value".to_owned(),
                })
            }
        })
    }
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Json
    }
}

/// Build args struct from command line arguments
pub fn args_from_env() -> MainArgs {
    argh::from_env()
}
