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

pub(crate) static DEFAULT_IO_DEPTH: u16 = 2;
pub(crate) static DEFAULT_MAX_FDS: u16 = 128;
pub(crate) static DEFAULT_EXIT_ON_ERROR: bool = false;

mod args_argh;
use args_argh as args_internal;

use std::path::Path;
use std::path::PathBuf;
use std::process::exit;

pub use args_internal::OutputFormat;
pub use args_internal::ReplayArgs;
pub use args_internal::TracerType;
pub use args_internal::{DumpArgs, MainArgs, RecordArgs, SubCommands};
use serde::Deserialize;
use serde::Serialize;

use crate::Error;
use log::error;

// Deserialized form of the config file
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct ConfigFile {
    // Files to be excluded in prefetch. These files might have been
    // added in the record file while recording,but we do not want to
    // replay these files. These can be two types of files:
    // 1) installation-specific files (e.g. files in /data) and
    // 2) large files which we do not want to load in replay (e.g. APK files).
    pub files_to_exclude_regex: Vec<String>,
    // Files that are not in the record file, but need to be loaded during replay
    pub additional_replay_files: Vec<String>,
}

fn verify_and_fix(args: &mut MainArgs) -> Result<(), Error> {
    match &mut args.nested {
        SubCommands::Record(arg) => {
            if arg.debug && arg.int_path.is_none() {
                arg.int_path = Some(PathBuf::from(format!("{}.int", arg.path.to_str().unwrap())));
            }

            if let Some(p) = &arg.int_path {
                ensure_path_doesnt_exist(p)?;
            }
        }
        SubCommands::Replay(arg) => {
            ensure_path_exists(&arg.path)?;
            if !arg.config_path.as_os_str().is_empty() {
                ensure_path_exists(&arg.config_path)?;
            }
        }
        SubCommands::Dump(arg) => {
            ensure_path_exists(&arg.path)?;
        }
    }
    Ok(())
}

/// Returns error if the given path at `p` exist.
pub(crate) fn ensure_path_doesnt_exist(p: &Path) -> Result<(), Error> {
    if p.exists() {
        Err(Error::InvalidArgs {
            arg_name: "path".to_string(),
            arg_value: p.display().to_string(),
            error: "Path already exists".to_string(),
        })
    } else {
        Ok(())
    }
}

/// Returns error if the given path at `p` doesn't exist.
pub(crate) fn ensure_path_exists(p: &Path) -> Result<(), Error> {
    if p.is_file() {
        Ok(())
    } else {
        Err(Error::InvalidArgs {
            arg_name: "path".to_string(),
            arg_value: p.display().to_string(),
            error: "Path does not exist".to_string(),
        })
    }
}

/// Builds `MainArgs` from command line arguments. On error prints error/help message
/// and exits.
pub fn args_from_env() -> MainArgs {
    let mut args = args_internal::args_from_env();
    if let Err(e) = verify_and_fix(&mut args) {
        error!("failed to verify args: {}", e);
        exit(1);
    }
    args
}
