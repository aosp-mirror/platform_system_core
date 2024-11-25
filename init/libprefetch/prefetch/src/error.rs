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

use thiserror::Error;

use crate::{format::FileId, InodeInfo};

/// Enumerates all possible errors returned by this library.
#[derive(Debug, Error)]
pub enum Error {
    /// Represents a failure to open a file.
    #[error("Open error: {path}: {source}")]
    Open {
        /// The IO error
        source: std::io::Error,
        /// Path on which the operation failed.
        path: String,
    },

    /// Represents a failure to create a file.
    #[error("Create error. {path} {source}")]
    Create {
        /// The IO error
        source: std::io::Error,
        /// Path on which the operation failed.
        path: String,
    },

    /// Represents a failure to read trace file.
    #[error("Read error. {error}")]
    Read {
        /// Detailed error message.
        error: String,
    },

    /// Represents a failure to write to a file.
    #[error("Write error. {source}")]
    Write {
        /// The IO error
        source: std::io::Error,

        /// file path
        path: String,
    },

    /// Represents a failure to delete a file.
    #[error("Delete error. {path} {source}")]
    Delete {
        /// The IO error
        source: std::io::Error,
        /// Path on which the operation failed.
        path: String,
    },

    /// Represents a failure to stat a file.
    #[error("Stat error. {path} {source}")]
    Stat {
        /// The IO error
        source: std::io::Error,
        /// Path on which the operation failed.
        path: String,
    },

    /// Represents a failure to stat a file.
    #[error("clone failed. {id} {source}")]
    FileClone {
        /// The IO error
        source: std::io::Error,
        /// File id for which we could not clone the file.
        id: FileId,
    },

    /// Represents a failure to mmap a file.
    #[error("mmap failed. {path} {error}")]
    Mmap {
        /// Detailed error message.
        error: String,
        /// Path on which the operation failed.
        path: String,
    },

    /// Represents a failure to munmap a file.
    #[error("munmap failed. {length} {error}")]
    Munmap {
        /// Detailed error message.
        error: String,
        /// Size of file which this munmap failed
        length: usize,
    },

    /// Represents all other cases of `std::io::Error`.
    ///
    #[error(transparent)]
    IoError(
        /// The IO error
        #[from]
        std::io::Error,
    ),

    /// Represents a failure to map FileId to path
    ///
    #[error("Failed to map id to path: {id}")]
    IdNoFound {
        /// File id for which path lookup failed.
        id: FileId,
    },

    /// Indicates that the file is skipped for prefetching
    /// because it is in the exclude files list.
    ///
    #[error("Skipped prefetching file from path: {path}")]
    SkipPrefetch {
        /// Path to file for which prefetching is skipped.
        path: String,
    },

    /// Represents spurious InodeInfo or missing Record.
    ///
    #[error(
        "Stale inode(s) info found.\n\
            missing_file_ids: {missing_file_ids:#?}\n\
            stale_inodes: {stale_inodes:#?} \n\
            missing_paths:{missing_paths:#?}"
    )]
    StaleInode {
        /// FileIds for which InodeInfo is missing.
        missing_file_ids: Vec<FileId>,

        /// InodeInfos for which no records exist.
        stale_inodes: Vec<InodeInfo>,

        /// InodeInfos in which no paths were found.
        missing_paths: Vec<InodeInfo>,
    },

    /// Represents a failure to serialize records file.
    #[error("Serialize error: {error}")]
    Serialize {
        /// Detailed error message.
        error: String,
    },

    /// Represents a failure to deserialize records file.
    #[error("Deserialize error: {error}")]
    Deserialize {
        /// Detailed error message.
        error: String,
    },

    /// Represents a failure from thread pool.
    #[error("Thread pool error: {error}")]
    ThreadPool {
        /// Detailed error message.
        error: String,
    },

    /// Represents a failure to setup file.
    #[error("Failed to setup prefetch: {error}")]
    Custom {
        /// Detailed error message.
        error: String,
    },

    /// Represents a failure to parse args.
    #[error("Failed to parse arg:{arg_name} value:{arg_value} error:{error}")]
    InvalidArgs {
        /// Arg name.
        arg_name: String,

        /// Arg value.
        arg_value: String,

        /// Detailed error message.
        error: String,
    },
}
