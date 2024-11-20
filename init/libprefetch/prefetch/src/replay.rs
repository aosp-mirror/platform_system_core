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

use std::clone::Clone;
use std::convert::TryInto;
use std::fmt::Display;
use std::mem::replace;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread;

use log::debug;
use log::error;
use log::warn;
use lru_cache::LruCache;
use nix::errno::Errno;
use nix::fcntl::posix_fadvise;
use regex::Regex;

use crate::args::ConfigFile;
use crate::format::Record;
use crate::format::{FileId, RecordsFile};
use crate::Error;
use crate::ReplayArgs;
use libc::{c_void, off64_t, pread64};
use std::fs::File;

const READ_SZ: usize = 1024 * 1024;

struct ScopedLog<T: Display + Sized> {
    msg: T,
    thd_id: usize,
}

fn scoped_log<T: Display + Sized>(ctx: usize, msg: T) -> ScopedLog<T> {
    let thd_id = ctx;
    debug!("{} {} start", thd_id, msg);
    ScopedLog { msg, thd_id }
}

impl<T: Display> Drop for ScopedLog<T> {
    fn drop(&mut self) {
        debug!("{} {} end", self.thd_id, self.msg);
    }
}

fn readahead(
    id: usize,
    file: Arc<File>,
    record: &Record,
    buffer: &mut [u8; READ_SZ],
) -> Result<(), Error> {
    debug!("readahead {:?}", record);
    let _dbg = scoped_log(id, "readahead");

    let mut current_offset: off64_t = record
        .offset
        .try_into()
        .map_err(|_| Error::Read { error: "Failed to convert offset".to_string() })?;
    let mut remaining_data: usize = record
        .length
        .try_into()
        .map_err(|_| Error::Read { error: "Failed to convert length".to_string() })?;

    while remaining_data > 0 {
        let read_size = std::cmp::min(READ_SZ, remaining_data);

        // SAFETY: This is safe because
        // - the file is known to exist and opened
        // - buffer is allocated upfront and is guaranteed by the fact it comes from a mutable slice reference.
        // - read_size is guaranteed not to exceed length of the buffer.
        let bytes_read = unsafe {
            pread64(file.as_raw_fd(), buffer.as_mut_ptr() as *mut c_void, read_size, current_offset)
        };

        if bytes_read == -1 {
            return Err(Error::Read { error: format!("readahead failed: {}", Errno::last_raw()) });
        }

        if bytes_read == 0 {
            break; // End of file reached
        }

        current_offset += bytes_read as off64_t;
        remaining_data -= bytes_read as usize;
    }

    // TODO: Try readahead() syscall or async I/O
    Ok(())
}

fn worker_internal(
    id: usize,
    state: Arc<Mutex<SharedState>>,
    records_file: Arc<RwLock<RecordsFile>>,
    exit_on_error: bool,
    exclude_files_regex: Vec<Regex>,
    buffer: &mut [u8],
) -> Result<(), Error> {
    loop {
        let index = {
            let mut state = state.lock().unwrap();
            if state.result.is_err() {
                return Ok(());
            }
            state.next_record()
        };

        let record = {
            let rf = records_file.read().unwrap();
            if index >= rf.inner.records.len() {
                return Ok(());
            }
            rf.inner.records.get(index).unwrap().clone()
        };

        let _dbg = scoped_log(id, "record_replay");

        let file = state.lock().unwrap().fds.get_mut(&record.file_id).map(|f| f.clone());

        let file = match file {
            Some(file) => file,
            None => {
                let file = Arc::new({
                    let file = records_file
                        .read()
                        .unwrap()
                        .open_file(record.file_id.clone(), &exclude_files_regex);
                    if let Err(e) = file {
                        if exit_on_error {
                            return Err(e);
                        } else {
                            match e {
                                Error::SkipPrefetch { path } => {
                                    debug!("Skipping file during replay: {}", path);
                                }
                                _ => error!(
                                    "Failed to open file id: {} with {}",
                                    record.file_id.clone(),
                                    e.to_string()
                                ),
                            }
                            continue;
                        }
                    }

                    let file = file.unwrap();
                    // We do not want the filesystem be intelligent and prefetch more than what this
                    // code is reading. So turn off prefetch.

                    if let Err(e) = posix_fadvise(
                        file.as_raw_fd(),
                        0,
                        0,
                        nix::fcntl::PosixFadviseAdvice::POSIX_FADV_RANDOM,
                    ) {
                        warn!(
                            "Failed to turn off filesystem read ahead for file id: {} with {}",
                            record.file_id.clone(),
                            e.to_string()
                        );
                    }
                    file
                });
                let cache_file = file.clone();
                state.lock().unwrap().fds.insert(record.file_id.clone(), cache_file);
                file
            }
        };
        if let Err(e) = readahead(id, file, &record, buffer.try_into().unwrap()) {
            if exit_on_error {
                return Err(e);
            } else {
                error!(
                    "readahead failed on file id: {} with: {}",
                    record.file_id.clone(),
                    e.to_string()
                );
                continue;
            }
        }
    }
}

fn worker(
    id: usize,
    state: Arc<Mutex<SharedState>>,
    records_file: Arc<RwLock<RecordsFile>>,
    exit_on_error: bool,
    exclude_files_regex: Vec<Regex>,
    buffer: &mut [u8],
) {
    let _dbg = scoped_log(id, "read_loop");
    let result = worker_internal(
        id,
        state.clone(),
        records_file,
        exit_on_error,
        exclude_files_regex,
        buffer,
    );
    if result.is_err() {
        error!("worker failed with {:?}", result);
        let mut state = state.lock().unwrap();
        if state.result.is_ok() {
            state.result = result;
        }
    }
}

#[derive(Debug)]
pub struct SharedState {
    fds: LruCache<FileId, Arc<File>>,
    records_index: usize,
    result: Result<(), Error>,
}

impl SharedState {
    fn next_record(&mut self) -> usize {
        let ret = self.records_index;
        self.records_index += 1;
        ret
    }
}

/// Runtime, in-memory, representation of records file structure.
#[derive(Debug)]
pub struct Replay {
    records_file: Arc<RwLock<RecordsFile>>,
    io_depth: u16,
    exit_on_error: bool,
    state: Arc<Mutex<SharedState>>,
    exclude_files_regex: Vec<Regex>,
}

impl Replay {
    /// Creates Replay from input `args`.
    pub fn new(args: &ReplayArgs) -> Result<Self, Error> {
        let _dbg = scoped_log(1, "new");
        let reader: File = File::open(&args.path).map_err(|source| Error::Open {
            source,
            path: args.path.to_str().unwrap().to_owned(),
        })?;
        let rf: RecordsFile = serde_cbor::from_reader(reader)
            .map_err(|error| Error::Deserialize { error: error.to_string() })?;

        let mut exclude_files_regex: Vec<Regex> = Vec::new();
        // The path to the configuration file is optional in the command.
        // If the path is provided, the configuration file will be read.
        if !&args.config_path.as_os_str().is_empty() {
            let config_reader = File::open(&args.config_path).map_err(|source| Error::Open {
                source,
                path: args.path.to_str().unwrap().to_owned(),
            })?;
            let cf: ConfigFile = serde_json::from_reader(config_reader)
                .map_err(|error| Error::Deserialize { error: error.to_string() })?;

            for file_to_exclude in &cf.files_to_exclude_regex {
                exclude_files_regex.push(Regex::new(file_to_exclude).unwrap());
            }
        }

        Ok(Self {
            records_file: Arc::new(RwLock::new(rf)),
            io_depth: args.io_depth,
            exit_on_error: args.exit_on_error,
            state: Arc::new(Mutex::new(SharedState {
                fds: LruCache::new(args.max_fds.into()),
                records_index: 0,
                result: Ok(()),
            })),
            exclude_files_regex,
        })
    }

    /// Replay records.
    pub fn replay(self) -> Result<(), Error> {
        let _dbg = scoped_log(1, "replay");
        let mut threads = vec![];
        for i in 0..self.io_depth {
            let i_clone = i as usize;
            let state = self.state.clone();
            let records_file = self.records_file.clone();
            let exit_on_error = self.exit_on_error;
            let exclude_files_regex = self.exclude_files_regex.clone();

            let mut buffer = Box::new([0u8; READ_SZ]);

            threads.push(thread::Builder::new().spawn(move || {
                worker(
                    i_clone,
                    state,
                    records_file,
                    exit_on_error,
                    exclude_files_regex,
                    buffer.as_mut_slice(),
                )
            }));
        }
        for thread in threads {
            thread.unwrap().join().unwrap();
        }
        replace(&mut self.state.lock().unwrap().result, Ok(()))
    }
}

// WARNING: flaky tests.
// In these tests we create files, invalidate their caches and then replay.
// Verify that after reply the same portions of data is in memory.
//
// Since these tests to rely on presence or absence of data in cache, the
// files used by the tests should not be in tmp filesystem. So we use relative
// path as target directory. There is no guarantee that this target directory
// is not on temp filesystem but chances are better than using target directory
// in tempfs.
//
// Tests can be flaky if the system under tests is running low on memory. The
// tests create file using O_DIRECT so that no data is left in file cache.
// Though this is sufficient to avoid caching, but other processes reading these
// files(like anti-virus) or some other system processes might change the state
// of the cache. Or it may happen that the filesystem evicts the file before
// we verify that read ahead worked as intended.
#[cfg(test)]
pub mod tests {
    use std::{
        assert,
        io::Write,
        ops::Range,
        path::{Path, PathBuf},
        time::Duration,
    };

    use crate::format::DeviceNumber;
    use crate::format::FsInfo;
    use crate::format::InodeNumber;
    use crate::nanoseconds_since_boot;
    use nix::sys::mman::MapFlags;
    use nix::sys::mman::ProtFlags;
    use serde::Deserialize;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::fs::OpenOptions;
    use std::num::NonZeroUsize;
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::MetadataExt;
    use std::ptr::NonNull;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::tracer::{
        page_size,
        tests::{copy_uncached_files_and_record_from, setup_test_dir},
    };

    static MB: u64 = 1024 * 1024;
    static KB: u64 = 1024;

    fn random_write(file: &mut NamedTempFile, base: u64) -> Range<u64> {
        let start: u64 = base + (rand::random::<u64>() % (base / 2)) as u64;
        let len: u64 = rand::random::<u64>() % (32 * KB);
        let buf = vec![5; len as usize];
        nix::sys::uio::pwrite(file.as_fd(), &buf, start as i64).unwrap();
        start..(start + len)
    }

    pub(crate) fn create_file(
        path: Option<&Path>,
        align: Option<u64>,
    ) -> (NamedTempFile, Vec<Range<u64>>) {
        let mut file = if let Some(path) = path {
            NamedTempFile::new_in(path).unwrap()
        } else {
            NamedTempFile::new().unwrap()
        };
        let range1 = random_write(&mut file, 32 * KB);
        let range2 = random_write(&mut file, 128 * KB);
        let range3 = random_write(&mut file, 4 * MB);
        if let Some(align) = align {
            let orig_size = file.metadata().unwrap().len();
            let aligned_size = orig_size + (align - (orig_size % align));
            file.set_len(aligned_size).unwrap();
        }
        (file, vec![range1, range2, range3])
    }

    pub(crate) fn generate_cached_files_and_record(
        path: Option<&Path>,
        create_symlink: bool,
        align: Option<u64>,
    ) -> (RecordsFile, Vec<(NamedTempFile, Vec<Range<u64>>)>) {
        let file1 = create_file(path, align);
        let file2 = create_file(path, align);
        let file3 = create_file(path, align);

        let mut f: RecordsFileBuilder = Default::default();
        f.add_file(file1.0.path().to_str().unwrap());
        f.add_file(file2.0.path().to_str().unwrap());
        f.add_file(file3.0.path().to_str().unwrap());
        if create_symlink {
            let symlink_path = format!("{}-symlink", file1.0.path().to_str().unwrap());
            symlink(file1.0.path().file_name().unwrap(), &symlink_path).unwrap();

            f.add_file(&symlink_path);
        }
        let rf = f.build().unwrap();
        (rf, vec![file1, file2, file3])
    }

    /// RecordsFileBuilder is primarily used for testing purpose. This
    /// is a thin wrapper around "Record". This gives the ability
    /// to test Records functionality. The flow of this test is as follows:
    ///
    /// 1: generate_cached_files_and_record -> This will create temporary files of different length
    /// and builds the "RecordFile" format.
    /// 2: For each of the file path create, a "RecordsFile" is generated.
    ///    a: mmap the file based on the length.
    ///    b: call mincore() to get the residency of pages in memory for the given
    ///    length.
    ///    c: Iterate over the buffer of pages returned by mincore(). If a page
    ///    is not resident in RAM, construct the "Record" structure.
    /// 3: build() function will finally return a constructed Prefetch Record which
    /// contains all the "Record" structure required for "Replay".
    #[derive(Debug, Default, Deserialize, Serialize)]
    pub struct RecordsFileBuilder {
        // Temporarily holds paths of all files opened by other processes.
        pub(crate) paths: HashMap<String, FileId>,

        // Read inode numbers
        inode_numbers: HashMap<(DeviceNumber, InodeNumber), FileId>,
    }

    impl RecordsFileBuilder {
        pub fn add_file(&mut self, path: &str) {
            if self.paths.contains_key(path) {
                return;
            }

            self.paths.insert(path.to_owned(), FileId(self.paths.len() as u64));
        }

        pub fn build(&mut self) -> Result<RecordsFile, Error> {
            let mut rf = RecordsFile::default();
            for (path, mut id) in self.paths.drain() {
                let stat = Path::new(&path)
                    .metadata()
                    .map_err(|source| Error::Stat { source, path: path.clone() })?;

                rf.inner
                    .filesystems
                    .entry(stat.dev())
                    .or_insert(FsInfo { block_size: stat.blksize() });

                if let Some(orig_id) = self.inode_numbers.get(&(stat.dev(), stat.ino())) {
                    let inode = rf.inner.inode_map.get_mut(orig_id).unwrap();
                    inode.paths.push(path.clone());

                    // There may be multiple paths for the file so from those path we may have multiple
                    // ids. Override the id.
                    id = orig_id.clone();
                } else {
                    self.inode_numbers.insert((stat.dev(), stat.ino()), id.clone());
                    rf.insert_or_update_inode(id.clone(), &stat, path.clone());
                }
                if let Some(mmap) = Mmap::create(&path, id)? {
                    mmap.get_records(&mut rf.inner.records)?;
                }
            }
            Ok(rf)
        }
    }

    #[derive(Debug)]
    pub(crate) struct Mmap {
        map_addr: *mut c_void,
        length: usize,
        #[allow(dead_code)]
        file: File,
        file_id: FileId,
    }

    impl Mmap {
        pub fn create(path: &str, file_id: FileId) -> Result<Option<Self>, Error> {
            let file = OpenOptions::new()
                .read(true)
                .write(false)
                .open(path)
                .map_err(|source| Error::Open { source, path: path.to_owned() })?;

            let length = file
                .metadata()
                .map_err(|source| Error::Stat { source, path: path.to_owned() })?
                .len() as usize;

            if length == 0 {
                return Ok(None);
            }

            // SAFETY: This is safe because
            // - the length is checked for zero
            // - offset is set to 0
            let map_addr = unsafe {
                nix::sys::mman::mmap(
                    None,
                    NonZeroUsize::new(length).unwrap(),
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_SHARED,
                    file.as_fd(),
                    0,
                )
                .map_err(|source| Error::Mmap {
                    error: source.to_string(),
                    path: path.to_owned(),
                })?
            };

            Ok(Some(Self { map_addr: map_addr.as_ptr(), length, file, file_id }))
        }

        /// Construct the "Record" file based on pages resident in RAM.
        pub(crate) fn get_records(&self, records: &mut Vec<Record>) -> Result<(), Error> {
            let page_size = page_size()?;
            let page_count = (self.length + page_size - 1) / page_size;
            let mut buf: Vec<u8> = vec![0_u8; page_count];
            // SAFETY: This is safe because
            // - the file is mapped
            // - buf points to a valid and sufficiently large memory region with the
            //   requirement of (length+PAGE_SIZE-1) / PAGE_SIZE bytes
            let ret = unsafe { libc::mincore(self.map_addr, self.length, buf.as_mut_ptr()) };
            if ret < 0 {
                return Err(Error::Custom {
                    error: format!("failed to query resident pages: {}", Errno::last_raw()),
                });
            }
            let mut i = 0;

            let mut offset_length: Option<(u64, u64)> = None;
            for (index, resident) in buf.iter().enumerate() {
                if *resident != 0 {
                    if let Some((_, length)) = &mut offset_length {
                        *length += page_size as u64;
                    } else {
                        offset_length = Some((index as u64 * page_size as u64, page_size as u64));
                    }
                } else if let Some((offset, length)) = offset_length {
                    i += 1;
                    records.push(Record {
                        file_id: self.file_id.clone(),
                        offset,
                        length,
                        timestamp: nanoseconds_since_boot(),
                    });

                    offset_length = None;
                }
            }

            if let Some((offset, length)) = offset_length {
                i += 1;
                records.push(Record {
                    file_id: self.file_id.clone(),
                    offset,
                    length,
                    timestamp: nanoseconds_since_boot(),
                });
            }
            debug!("records found: {} for {:?}", i, self);

            Ok(())
        }
    }

    impl Drop for Mmap {
        fn drop(&mut self) {
            // SAFETY: This is safe because
            // - addr is mapped and is multiple of page_size
            let ret = unsafe {
                nix::sys::mman::munmap(NonNull::new(self.map_addr).unwrap(), self.length)
            };
            if let Err(e) = ret {
                error!(
                    "failed to munmap {:p} {} with {}",
                    self.map_addr,
                    self.length,
                    e.to_string()
                );
            }
        }
    }

    // Please see comment above RecordsFileBuilder.
    fn rebuild_records_file(files: &[(PathBuf, Vec<Range<u64>>)]) -> RecordsFile {
        // Validate that caches are dropped
        let mut f: RecordsFileBuilder = Default::default();
        for (path, _) in files {
            f.add_file(path.to_str().unwrap());
        }
        f.build().unwrap()
    }

    fn ensure_files_not_cached(files: &mut [(PathBuf, Vec<Range<u64>>)]) {
        assert!(rebuild_records_file(files).inner.records.is_empty());
    }

    fn has_record(records: &[Record], key: &Record) -> bool {
        for r in records {
            if r.offset == key.offset && r.length == key.length {
                return true;
            }
        }
        false
    }

    fn compare_records(old: &[Record], new: &[Record]) {
        for key in new {
            if !has_record(old, key) {
                panic!("Failed to file {:?} in {:?}", key, old);
            }
        }
    }

    fn create_test_config_file(files_to_exclude_regex: Vec<String>) -> String {
        let cfg = ConfigFile { files_to_exclude_regex, ..Default::default() };
        serde_json::to_string(&cfg).unwrap()
    }

    // TODO: Split this into individual tests for better readability.
    // b/378554334
    fn test_replay_internal(
        create_symlink: bool,
        exit_on_error: bool,
        inject_error: bool,
        exclude_all_files: bool,
        empty_exclude_file_list: bool,
    ) {
        let page_size = page_size().unwrap() as u64;
        let test_base_dir = setup_test_dir();
        let (rf, mut files) =
            generate_cached_files_and_record(None, create_symlink, Some(page_size));

        // Here "uncached_files" emulate the files after reboot when none of those files data is in cache.
        let (mut uncached_rf, mut uncached_files) =
            copy_uncached_files_and_record_from(Path::new(&test_base_dir), &mut files, &rf);

        // Injects error(s) in the form of invalid filename
        if inject_error {
            if let Some(v) = uncached_rf.inner.inode_map.values_mut().next() {
                for path in &mut v.paths {
                    path.push('-');
                }
            }
        }

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&uncached_rf.add_checksum_and_serialize().unwrap()).unwrap();
        let mut config_file = NamedTempFile::new().unwrap();

        let mut files_to_exclude: Vec<String> = Vec::new();
        if exclude_all_files {
            // Exclude files from replay by adding them in config
            for v in uncached_rf.inner.inode_map.values_mut() {
                for path in &mut v.paths {
                    files_to_exclude.push(path.to_string())
                }
            }
        } else if empty_exclude_file_list {
            files_to_exclude.extend(vec![]);
        } else {
            // Exclude file1 and file2 during replay
            files_to_exclude.extend(vec!["file1".to_owned(), "file2".to_owned()]);
        }

        // Create a config json to exclude files during replay
        let config_file_contents = create_test_config_file(files_to_exclude);
        config_file.write_all(config_file_contents.as_bytes()).unwrap();

        ensure_files_not_cached(&mut uncached_files);

        let replay = Replay::new(&ReplayArgs {
            path: file.path().to_owned(),
            io_depth: 32,
            max_fds: 128,
            exit_on_error,
            config_path: config_file.path().to_owned(),
        })
        .unwrap();

        let result = replay.replay();
        // Sleep a bit so that readaheads are complete.
        thread::sleep(Duration::from_secs(1));

        if exit_on_error && inject_error {
            result.expect_err("Failure was expected");
        } else if exclude_all_files {
            let new_rf = rebuild_records_file(&uncached_files);
            assert!(new_rf.inner.records.is_empty());
        } else {
            result.unwrap();

            // At this point, we have prefetched data for uncached file bringing same set of
            // data in memory as the original cached files.
            // If we record prefetch data for new files, we should get same records files
            // (offset and lengths) except that the file names should be different.
            // This block verifies it.
            // Note: `new_rf` is for uncached_files. But, [un]fortunately, those "uncached_files"
            // are now cached after we replayed the records.
            let new_rf = rebuild_records_file(&uncached_files);
            assert!(!new_rf.inner.records.is_empty());
            assert_eq!(rf.inner.inode_map.len(), new_rf.inner.inode_map.len());
            assert_eq!(rf.inner.records.len(), new_rf.inner.records.len());
            compare_records(&rf.inner.records, &new_rf.inner.records);
        }
    }

    #[test]
    fn test_replay() {
        test_replay_internal(true, false, false, false, false);
    }

    #[test]
    fn test_replay_strict() {
        test_replay_internal(true, true, false, false, false);
    }

    #[test]
    fn test_replay_no_symlink() {
        test_replay_internal(false, false, false, false, false);
    }

    #[test]
    fn test_replay_no_symlink_strict() {
        test_replay_internal(false, true, false, false, false);
    }

    #[test]
    fn test_replay_fails_on_error() {
        test_replay_internal(true, true, true, false, false);
    }

    #[test]
    fn test_replay_exclude_all_files() {
        test_replay_internal(true, false, false, true, false);
    }

    #[test]
    fn test_replay_empty_exclude_files_list() {
        test_replay_internal(true, false, false, false, true);
    }
}
