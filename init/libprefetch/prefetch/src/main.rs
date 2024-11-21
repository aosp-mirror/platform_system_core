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

//! A utility wrapper around libprefetch that allows to record, replay and dump
//! prefetch data.

use log::error;

use prefetch_rs::args_from_env;
use prefetch_rs::dump;
use prefetch_rs::init_logging;
use prefetch_rs::record;
use prefetch_rs::replay;
use prefetch_rs::LogLevel;
use prefetch_rs::MainArgs;
use prefetch_rs::SubCommands;

fn main() {
    init_logging(LogLevel::Debug);
    let args: MainArgs = args_from_env();
    let ret = match &args.nested {
        SubCommands::Record(args) => record(args),
        SubCommands::Replay(args) => replay(args),
        SubCommands::Dump(args) => dump(args),
    };

    if let Err(err) = ret {
        error!("{:?} command failed: {:?}", args, err);
    }
}
