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

//! Tracer supports collecting information based off of two different tracing
//! subsystems within `/sys/kernel/tracing`.
//!
//! ## Mem
//! Mem is preferred tracer.
//! ### Phase 1:
//! This phase relies on a trace event at
//! "events/filemap/mm_filemap_add_to_page_cache". When enabled, the event logs
//! a message that contains device id, inode number, offset of the page that is
//! being read. The tracer makes a note of this.
//!
//! ### Phase 2:
//! When the recording of events is done, tracer all get mount points for which
//! device id is recorded. Once it knows the mount points, it looks up file
//! paths for the inode numbers that it records. The paths, offset and lengths
//! are then stored in records file.
//!
//! Phase 2 is very IO intensive as entire filesystem is walked to find paths
//! for different inodes.
//!
pub(crate) mod mem;

use std::{
    boxed::Box,
    collections::HashSet,
    fs::{create_dir, read_to_string, rename, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    string::ToString,
    sync::mpsc::{self, Receiver, Sender},
};

use log::{error, info};
use nix::time::ClockId;
use serde::Deserialize;
use serde::Serialize;

use crate::error::Error;
use crate::{args::TracerType, format::RecordsFile};
use mem::MemTraceSubsystem;

pub(crate) static EXCLUDE_PATHS: &[&str] =
    &["/dev/", "/proc/", "/sys/", "/tmp/", "/run/", "/config/", "/mnt/", "/storage/"];

/// During record phase, prefetch may modify files under `/sys/kernel/tracing/` to
/// - change trace buffer size so that we don't lose trace events
/// - enable a few trace events
/// - enable tracing
///
///  The old values are restored at the end of record.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TraceEventFile {
    path: PathBuf,
    restore_value: Option<String>,
}

impl TraceEventFile {
    fn open_and_write(path: &Path, value: &str) -> Result<(), Error> {
        let mut f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .map_err(|e| Error::Open { source: e, path: path.to_str().unwrap().to_string() })?;
        f.write_all(value.as_bytes())
            .map_err(|e| Error::Write { path: path.to_str().unwrap().to_owned(), source: e })
    }

    pub fn write(path: PathBuf, value: &str) -> Result<Self, Error> {
        let restore_value = read_to_string(&path).map_err(|s| Error::Read {
            error: format!("Reading {} failed:{}", path.to_str().unwrap(), s),
        })?;

        Self::open_and_write(&path, value)?;

        info!(
            "Changed contents of {} from {:?} to {}",
            path.to_str().unwrap(),
            restore_value,
            value
        );
        Ok(Self { path, restore_value: Some(restore_value) })
    }

    pub fn enable(path: PathBuf) -> Result<Self, Error> {
        Self::write(path, "1")
    }

    pub fn restore(&self) -> Result<(), Error> {
        if let Some(restore_value) = &self.restore_value {
            Self::open_and_write(&self.path, restore_value)
        } else {
            Ok(())
        }
    }
}

impl Drop for TraceEventFile {
    fn drop(&mut self) {
        if let Err(ret) = self.restore() {
            error!(
                "Failed to restore state of file {:?} with value: {:?}. Error: {}",
                self.path,
                self.restore_value,
                ret.to_string()
            );
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TracerConfigs {
    pub excluded_paths: Vec<String>,
    pub buffer_size_file_path: String,
    pub trace_base_path: PathBuf,
    pub trace_events: Vec<String>,
    pub mountinfo_path: Option<String>,
    pub trace_operations: HashSet<String>,
    // We never read back these fields. The only use for holding these around is to restore state at
    // the end of run.
    #[allow(dead_code)]
    trace_files: Vec<TraceEventFile>,
}

impl TracerConfigs {
    pub fn new(
        kb_buffer_size: Option<u64>,
        setup_tracing: bool,
        tracer_type: TracerType,
        trace_mount_point: Option<String>,
        tracing_instance: Option<String>,
    ) -> Result<Self, Error> {
        static TRACE_MOUNT_POINT: &str = "/sys/kernel/tracing";

        // Trace buffer size file relative to trace mount point
        static TRACE_BUFFER_SIZE_FILE: &str = "buffer_size_kb";

        let trace_mount_point = trace_mount_point.unwrap_or_else(|| TRACE_MOUNT_POINT.to_owned());
        let trace_base_path = if let Some(instance) = tracing_instance {
            Path::new(&trace_mount_point).join("instances").join(instance)
        } else {
            Path::new(&trace_mount_point).to_owned()
        };

        if setup_tracing && !trace_base_path.exists() {
            create_dir(&trace_base_path).map_err(|e| Error::Create {
                source: e,
                path: trace_base_path.to_str().unwrap().to_owned(),
            })?;
        }

        if !trace_base_path.exists() {
            return Err(Error::Custom {
                error: format!(
                    "trace mount point doesn't exist: {}",
                    trace_base_path.to_str().unwrap().to_owned()
                ),
            });
        }

        let mut configs = TracerConfigs {
            excluded_paths: vec![],
            buffer_size_file_path: TRACE_BUFFER_SIZE_FILE.to_owned(),
            trace_base_path,
            trace_events: vec![],
            mountinfo_path: None,
            trace_operations: HashSet::new(),
            trace_files: vec![],
        };

        match tracer_type {
            TracerType::Mem => MemTraceSubsystem::update_configs(&mut configs),
        }

        if setup_tracing {
            let trace_base_dir = Path::new(&configs.trace_base_path);
            if let Some(kb_buffer_size) = kb_buffer_size {
                configs.trace_files.push(TraceEventFile::write(
                    trace_base_dir.join(&configs.buffer_size_file_path),
                    &kb_buffer_size.to_string(),
                )?);
            }
            for path in &configs.trace_events {
                configs.trace_files.push(TraceEventFile::enable(trace_base_dir.join(path))?);
            }
        }

        Ok(configs)
    }
}

/// Returns time, in nanoseconds, since boot
pub fn nanoseconds_since_boot() -> u64 {
    if let Ok(t) = nix::time::clock_gettime(ClockId::CLOCK_MONOTONIC) {
        //((t.tv_sec() * 1_000_000_000) + t.tv_nsec()) as u64
        (1 + t.tv_nsec()) as u64
    } else {
        0
    }
}

pub(crate) trait TraceSubsystem {
    /// This routine is called whenever there is a new line available to be parsed.
    /// The impl potentially want to parse the line and retain the data in memory.
    /// Implementors are not expected to do heavy lifting tasks, like IO, in this context.
    fn add_line(&mut self, line: &str) -> Result<(), Error>;

    /// Generates a records file from all the collected data.
    /// From this context, the implementors might process data by issuing queries to filesystems.
    fn build_records_file(&mut self) -> Result<RecordsFile, Error>;

    /// This helps us serialize internat state of tracing subsystem during record phase.
    /// This allows us to get raw data for analysis of read pattern and debugging in situations
    /// when we might not have access to system yet(ex. early boot phase) .
    fn serialize(&self, writer: &mut dyn Write) -> Result<(), Error>;
}

/// Returns page size in bytes
pub(crate) fn page_size() -> Result<usize, Error> {
    Ok(nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .map_err(|e| Error::Custom { error: format!("failed to query page size: {}", e) })?
        .ok_or(Error::Custom { error: "failed to query page size: None returned".to_string() })?
        as usize)
}

pub struct Tracer {
    // Open handle to static trace buffer file which is usually located at
    // `/sys/kernel/tracing/trace`.
    // See comment on top of `trace` function.
    trace_file: BufReader<File>,

    // Open handle to trace pipe which is usually located at
    // `/sys/kernel/tracing/trace_pipe`.
    // See comment on top of `trace` function.
    trace_pipe: BufReader<File>,

    // Signal to exit the infinite loop in `trace()`
    exit_rx: Receiver<()>,

    // tracing subsystem that actually parses trace lines and builds records.
    tracing_subsystem: Box<dyn TraceSubsystem + Send>,
}

impl Tracer {
    pub fn create(
        kb_buffer_size: Option<u64>,
        tracer_type: TracerType,
        tracing_instance: Option<String>,
        setup_tracing: bool,
    ) -> Result<(Self, Sender<()>), Error> {
        /// Trace pipe path relative to trace mount point
        static TRACE_PIPE_PATH: &str = "trace_pipe";

        /// Trace file path relative to trace mount point
        static TRACE_FILE_PATH: &str = "trace";

        let configs = TracerConfigs::new(
            kb_buffer_size,
            setup_tracing,
            tracer_type.clone(),
            None,
            tracing_instance,
        )?;

        let pipe_path = Path::new(&configs.trace_base_path).join(TRACE_PIPE_PATH);
        let trace_pipe = File::open(&pipe_path)
            .map_err(|e| Error::Open { source: e, path: pipe_path.to_str().unwrap().to_owned() })?;

        let file_path = Path::new(&configs.trace_base_path).join(TRACE_FILE_PATH);
        let trace_file = File::open(&file_path)
            .map_err(|e| Error::Open { source: e, path: file_path.to_str().unwrap().to_owned() })?;
        let tracer: Box<dyn TraceSubsystem + Send> = match tracer_type {
            TracerType::Mem => Box::new(MemTraceSubsystem::create_with_configs(configs)?),
        };

        Self::create_with_config(trace_file, trace_pipe, tracer)
    }

    fn create_with_config(
        file: File,
        pipe: File,
        tracer: Box<dyn TraceSubsystem + Send>,
    ) -> Result<(Self, Sender<()>), Error> {
        let (exit_tx, exit_rx) = mpsc::channel();
        let trace_pipe = BufReader::new(pipe);
        let trace_file = BufReader::new(file);

        Ok((Self { trace_file, trace_pipe, exit_rx, tracing_subsystem: tracer }, exit_tx))
    }

    fn save_intermediate_state(&self, intermediate_file: Option<&PathBuf>) -> Result<(), Error> {
        if let Some(int_path) = intermediate_file {
            let mut tmp_file = int_path.clone();
            tmp_file.set_extension("int.tmp");
            let mut out_file = File::create(&tmp_file).map_err(|source| Error::Create {
                source,
                path: int_path.to_str().unwrap().to_owned(),
            })?;
            self.tracing_subsystem.serialize(&mut out_file)?;
            rename(&tmp_file, int_path).map_err(|e| Error::Custom {
                error: format!(
                    "rename file from{} to:{} failed with {}",
                    tmp_file.to_str().unwrap(),
                    int_path.to_str().unwrap(),
                    e
                ),
            })?;
        }
        Ok(())
    }

    /// This routine parses all the events since last reset of trace buffer.
    ///
    /// The linux tracing subsystem exposes two interfaces to get trace events from
    /// 1. a file - usually at `/sys/kernel/tracing/trace`
    /// 2. a pipe - usually at `/sys/kernel/tracing/trace_pipe`
    ///
    /// The file is *sort of* ring buffer which works off of `buffer_size_kb` sized buffer.
    /// Relying on it is not very efficient as we end up getting a lot of duplicates.
    ///
    /// The pipe only contains line traces. Any trace events that occurred before opening
    /// of this file are lost.
    ///
    /// IMPORTANT: The moment we start reading from the pipe, the events in the file
    /// disappear/reset. So we should read file entirely before we start reading the pipe.
    pub fn trace(&mut self, intermediate_file: Option<&PathBuf>) -> Result<RecordsFile, Error> {
        let mut buf = String::new();
        self.trace_file
            .read_to_string(&mut buf)
            .map_err(|e| Error::Read { error: format!("failed to read trace file: {}", e) })?;

        for line in buf.lines() {
            let trimmed = line.trim_end();
            self.tracing_subsystem.add_line(trimmed)?;
        }

        // The logic here is to block on trace_pipe forever. We break out of loop only when we read
        // a line from the pipe *and* we have received an event on exit_rx.
        // This logic works because the system will have one or more read syscalls and also we,
        // at the moment, use prefetch on build systems and not in production to generate records
        // file.
        //
        // TODO(b/302045304): async read trace_pipe.
        while self.exit_rx.try_recv().is_err() {
            let mut line = String::new();
            let len = self
                .trace_pipe
                .read_line(&mut line)
                .map_err(|e| Error::Read { error: e.to_string() })?;
            let trimmed = line.trim_end();
            if len == 0 {
                // We should never read zero length line or reach EOF of the pipe.
                return Err(Error::Read {
                    error: "read zero length line from trace_pipe".to_string(),
                });
            }
            self.tracing_subsystem.add_line(trimmed)?;
        }

        // We are here because the above loop exited normally. Traced lines are stored in `Self`.
        // Build `RecordsFile` from processing data from read lines above.
        self.save_intermediate_state(intermediate_file)?;
        let rf = self.tracing_subsystem.build_records_file()?;
        self.save_intermediate_state(intermediate_file)?;
        Ok(rf)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::RecordsFile;

    use std::alloc::Layout;
    use std::borrow::ToOwned;
    use std::convert::TryInto;
    use std::fs::{create_dir_all, OpenOptions};
    use std::io::Read;
    use std::io::Seek;
    use std::io::Write;
    use std::ops::Range;
    use std::os::linux::fs::MetadataExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::prelude::OpenOptionsExt;
    use std::path::Path;
    use std::thread;
    use std::time::Duration;
    use std::{assert_eq, env};

    use libc::O_DIRECT;
    use nix::sys::stat::{major, minor};
    use nix::unistd::pipe;
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::replay::tests::generate_cached_files_and_record;
    use std::ops::{Deref, DerefMut};

    #[test]
    fn trace_event_file_enable_and_restore() {
        let mut file = NamedTempFile::new().unwrap();
        let _ = file.write("0".as_bytes()).unwrap();
        {
            let _e = TraceEventFile::enable(file.path().to_owned()).unwrap();
            assert_eq!(read_to_string(file.path()).unwrap(), "1");
        }
        assert_eq!(read_to_string(file.path()).unwrap(), "0");
    }

    #[test]
    fn trace_event_file_write_and_restore() {
        let mut file = NamedTempFile::new().unwrap();
        let _ = file.write("hello".as_bytes()).unwrap();
        {
            let _e = TraceEventFile::write(file.path().to_owned(), "world").unwrap();
            assert_eq!(read_to_string(file.path()).unwrap(), "world");
        }
        assert_eq!(read_to_string(file.path()).unwrap(), "hello");
    }

    fn setup_trace_mount_point(
        create_mount_point: bool,
        create_instances: bool,
        instance_name: Option<String>,
    ) -> PathBuf {
        assert!(
            create_mount_point || !create_instances,
            "cannot create instances without creating mount point"
        );

        let mount_point = env::temp_dir().join(
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect::<String>(),
        );

        let mut base_path = Path::new(&mount_point).to_owned();
        if create_mount_point {
            create_dir(&mount_point).unwrap();
        }

        if create_instances {
            base_path = base_path.join("instances");
            if let Some(instance_name) = &instance_name {
                base_path = base_path.join(instance_name)
            }
            create_dir_all(&base_path).unwrap();
        }

        if create_mount_point || create_instances {
            std::fs::write(&base_path.join("buffer_size_kb"), "100").unwrap();
            std::fs::write(&base_path.join("tracing_on"), "0").unwrap();
            std::fs::write(&base_path.join("trace"), "0").unwrap();
            std::fs::write(&base_path.join("trace_pipe"), "0").unwrap();

            for event in [
                "events/fs/do_sys_open",
                "events/fs/open_exec",
                "events/fs/uselib",
                "events/filemap/mm_filemap_add_to_page_cache",
            ] {
                let event_path = base_path.join(event);
                std::fs::create_dir_all(&event_path).unwrap();
                std::fs::write(&event_path.join("enable"), "0").unwrap();
            }
        }
        mount_point
    }

    #[test]
    fn test_configs_no_setup() {
        let mount_point = setup_trace_mount_point(true, true, None);
        let _configs = TracerConfigs::new(
            Some(10),
            false,
            TracerType::Mem,
            Some(mount_point.to_str().unwrap().to_owned()),
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_configs_no_setup_no_mount_point() {
        let mount_point = setup_trace_mount_point(false, false, None);
        assert_eq!(
            TracerConfigs::new(
                Some(10),
                false,
                TracerType::Mem,
                Some(mount_point.to_str().unwrap().to_owned()),
                None,
            )
            .unwrap_err()
            .to_string(),
            format!(
                "Failed to setup prefetch: trace mount point doesn't exist: {}",
                mount_point.to_str().unwrap()
            )
        );
    }

    #[test]
    fn test_configs_no_setup_no_instances() {
        let mount_point = setup_trace_mount_point(true, false, None);
        assert_eq!(
            TracerConfigs::new(
                Some(10),
                false,
                TracerType::Mem,
                Some(mount_point.to_str().unwrap().to_owned()),
                Some("my_instance".to_owned()),
            )
            .unwrap_err()
            .to_string(),
            format!(
                "Failed to setup prefetch: trace mount point doesn't exist: {}/instances/my_instance",
                mount_point.to_str().unwrap()
            )
        );
    }

    #[test]
    fn test_configs_setup_without_instances() {
        let mount_point = setup_trace_mount_point(true, false, None);
        assert!(TracerConfigs::new(
            Some(10),
            true,
            TracerType::Mem,
            Some(mount_point.to_str().unwrap().to_owned()),
            None
        )
        .is_ok());
    }

    #[test]
    fn test_configs_setup_with_instances() {
        let mount_point = setup_trace_mount_point(true, true, Some("my_instance".to_owned()));
        assert!(TracerConfigs::new(
            Some(10),
            true,
            TracerType::Mem,
            Some(mount_point.to_str().unwrap().to_owned()),
            Some("my_instance".to_owned())
        )
        .is_ok())
    }

    pub(crate) fn setup_test_dir() -> PathBuf {
        let test_base_dir: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        let test_base_dir = format!(
            "{}/test/{}",
            std::fs::read_link("/proc/self/exe").unwrap().parent().unwrap().to_str().unwrap(),
            test_base_dir
        );
        std::fs::create_dir_all(&test_base_dir).unwrap();
        PathBuf::from(test_base_dir)
    }

    fn modify_records_file(rf: &RecordsFile, target: &str) -> RecordsFile {
        let mut modified_rf = rf.clone();

        for inode in modified_rf.inner.inode_map.values_mut() {
            let new_paths: Vec<String> = inode
                .paths
                .iter()
                .map(|s| {
                    let parent = Path::new(s).parent().unwrap().to_str().unwrap();
                    s.replace(parent, target)
                })
                .collect();

            inode.paths = new_paths;
        }

        modified_rf
    }

    struct AlignedBuffer {
        ptr: *mut u8,
        len: usize,
        layout: Layout,
    }

    impl AlignedBuffer {
        fn new(size: usize, alignment: usize) -> Result<Self, Error> {
            if size == 0 {
                return Err(Error::Custom { error: "cannot allocate zero bytes".to_string() });
            }

            let layout = Layout::from_size_align(size, alignment).unwrap();
            // SAFETY:
            // - `size` is a valid non-zero positive integer representing the desired buffer size.
            // - The layout is checked for validity using `.unwrap()`.
            let ptr = unsafe { std::alloc::alloc(layout) };
            if ptr.is_null() {
                return Err(Error::Custom { error: format!("alloc failed: size: {}", size) });
            }
            Ok(AlignedBuffer { ptr, len: size, layout })
        }
    }

    impl Deref for AlignedBuffer {
        type Target = [u8];
        // SAFETY:
        // - self.ptr is a valid pointer obtained from a successful allocation in the new() method.
        // - self.len is a valid length used for allocation in the new() method.
        fn deref(&self) -> &Self::Target {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    impl DerefMut for AlignedBuffer {
        // SAFETY:
        // - self.ptr is a valid pointer obtained from a successful allocation in the new() method.
        // - self.len is a valid length used for allocation in the new() method.
        fn deref_mut(&mut self) -> &mut Self::Target {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }
    }

    impl Drop for AlignedBuffer {
        fn drop(&mut self) {
            // SAFETY:
            //  - self.ptr is a valid pointer obtained from a successful allocation in the new() method.
            //  - self.layout is the Layout used to allocate the memory.
            unsafe {
                std::alloc::dealloc(self.ptr, self.layout);
            }
        }
    }

    // Copies `files` into directory pointed by `base`.
    //
    // The newly created file's data is potentially uncached - i.e. the new
    // files are opened in O_DIRECT.
    //
    // WARNING: Though this function makes an attempt to copy into uncached files
    // but it cannot guarantee as other processes in the system may access the
    // files. This may lead to flaky tests or unexpected results.
    pub(crate) fn copy_uncached_files_and_record_from(
        base: &Path,
        files: &mut [(NamedTempFile, Vec<Range<u64>>)],
        rf: &RecordsFile,
    ) -> (RecordsFile, Vec<(PathBuf, Vec<Range<u64>>)>) {
        let mut new_files = vec![];
        for (in_file, ranges) in files {
            let out_path = base.join(in_file.path().file_name().unwrap());
            let mut out_file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(O_DIRECT)
                .create_new(true)
                .open(&out_path)
                .expect("Can't open");
            let page_size = page_size().unwrap() as u64;
            let in_file_size = in_file.metadata().unwrap().len();
            assert_eq!(
                in_file_size % page_size,
                0,
                "we create files that are aligned to page size"
            );
            let out_file_size = in_file_size;
            let mut buf =
                AlignedBuffer::new(out_file_size.try_into().unwrap(), page_size as usize).unwrap();
            let _ = in_file.read(&mut *buf).unwrap();
            out_file.write_all(&*buf).unwrap();

            new_files.push((out_path, ranges.clone()));
        }

        for inode in rf.inner.inode_map.values() {
            for path in &inode.paths {
                let in_path = Path::new(&path);
                let out_path = base.join(in_path.file_name().unwrap());
                if !out_path.exists() {
                    let orig_file =
                        out_path.file_name().unwrap().to_str().unwrap().replace("-symlink", "");
                    symlink(orig_file, out_path.to_str().unwrap()).unwrap();
                    new_files.push((out_path.to_owned(), vec![]));
                }
            }
        }
        let modified_rf = modify_records_file(rf, base.to_str().unwrap());
        (modified_rf, new_files)
    }

    // Generates mem trace string from given args. Sometimes injects lines that are of no importance
    fn mem_generate_trace_line_for_open(path: &Path, time: u16, _op: Option<&str>) -> Vec<String> {
        let op = "mm_filemap_add_to_page_cache";
        let stat = path.metadata().unwrap();
        let major_no = major(stat.st_dev());
        let minor_no = minor(stat.st_dev());
        let inode_number = stat.st_ino();

        vec![
            // unknown operation
            format!(
                " SettingsProvide-502     [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
                    page=000000008b759458 pfn=59827 ofs=0",
                time,
                (time * 100) + time,
                "unknown_operation",
                major_no,
                minor_no,
                inode_number,
            ),
            // invalid/relative inode
            format!(
                " SettingsProvide-502     [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
                    page=000000008b759458 pfn=59827 ofs=0",
                time,
                (time * 100) + time,
                "unknown_operation",
                major_no,
                minor_no,
                inode_number + 100,
            ),
            // good one
            format!(
                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
                    page=00000000f936540b pfn=60952 ofs={}",
                time,
                (time * 100) + time,
                op,
                major_no,
                minor_no,
                inode_number,
                0
            ),
            // good one
            format!(
                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
                    page=00000000f936540b pfn=60952 ofs={}",
                time,
                (time * 100) + time,
                op,
                major_no,
                minor_no,
                inode_number,
                10_000,
            ),
            // good one
            format!(
                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
                    page=00000000f936540b pfn=60952 ofs={}",
                time,
                (time * 100) + time,
                op,
                major_no,
                minor_no,
                inode_number,
                100_000,
            ),
            // good one
            format!(
                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
                    page=00000000f936540b pfn=60952 ofs={}",
                time,
                (time * 100) + time,
                op,
                major_no,
                minor_no,
                inode_number,
                1_000_000,
            ),
            // invalid operation case
            format!(
                " SettingsProvide-502     [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
                    page=000000008b759458 pfn=59827 ofs=0",
                time,
                (time * 100) + time,
                op.to_uppercase(),
                major_no,
                minor_no,
                inode_number,
            ),
        ]
    }

    fn generate_trace_line_for_open(
        tracing_type: TracerType,
        path: &Path,
        time: u16,
        op: Option<&str>,
    ) -> Vec<String> {
        match tracing_type {
            TracerType::Mem => mem_generate_trace_line_for_open(path, time, op),
        }
    }

    // Generates a fake mountinfo file with bunch of fake mount point and
    // fakes given path as a mount point.
    fn create_fake_mountinfo_for(path: &Path) -> NamedTempFile {
        let stat = path.metadata().unwrap();
        let major_no = major(stat.st_dev());
        let minor_no = minor(stat.st_dev());
        let mut mountinfo_path = NamedTempFile::new().unwrap();
        mountinfo_path
            .write_all(
                "16 15 0:17 / /dev/pts rw,relatime shared:3 - devpts devpts \
                     rw,seclabel,mode=600,ptmxmode=000\n"
                    .as_bytes(),
            )
            .unwrap();
        mountinfo_path
            .write_all(
                "17 26 0:18 / /proc rw,relatime shared:4 - proc proc rw,gid=3009,hidepid=\
                    invisible\n"
                    .as_bytes(),
            )
            .unwrap();
        mountinfo_path
            .write_all(
                format!(
                    "26 24 {}:{} / {} ro,nodev,noatime shared:1 - ext4 /dev/block/dm-3 ro,\
                    seclabel,errors=panic\n",
                    major_no,
                    minor_no,
                    path.to_str().unwrap(),
                )
                .as_bytes(),
            )
            .unwrap();

        mountinfo_path
    }

    static RECORD_PER_FILE: usize = 4;

    fn create_tracer(
        base_dir: &Path,
        t: TracerType,
    ) -> (Box<dyn TraceSubsystem + Send>, Vec<NamedTempFile>) {
        let kb_buffer_size = Some(8388608);
        let trace_mount_point = setup_test_dir();
        let mut buffer_size_file = NamedTempFile::new_in(&trace_mount_point).unwrap();
        buffer_size_file
            .write_all(format!("{}", kb_buffer_size.as_ref().unwrap()).as_bytes())
            .unwrap();

        let buffer_size_file_path = buffer_size_file.path().to_str().unwrap().to_string();
        let mut config = TracerConfigs::new(
            kb_buffer_size,
            false,
            t.clone(),
            Some(trace_mount_point.to_str().unwrap().to_string()),
            None,
        )
        .unwrap();
        let mut tempfiles = vec![buffer_size_file];
        (
            match t {
                TracerType::Mem => {
                    let mountinfo_path =
                        create_fake_mountinfo_for(&base_dir.canonicalize().unwrap());
                    config.trace_events = vec![];
                    config.buffer_size_file_path = buffer_size_file_path;
                    config.mountinfo_path =
                        Some(mountinfo_path.path().to_str().unwrap().to_string());
                    tempfiles.push(mountinfo_path);
                    Box::new(MemTraceSubsystem::create_with_configs(config).unwrap())
                }
            },
            tempfiles,
        )
    }

    fn test_trace_of_type(tracing_type: TracerType) {
        let test_base_dir = setup_test_dir();
        let (_rf, files) = generate_cached_files_and_record(
            Some(&test_base_dir),
            true,
            Some(page_size().unwrap() as u64),
        );

        let mut file = NamedTempFile::new().unwrap();
        let (reader_fd, writer_fd) = pipe().unwrap();
        let reader = File::from(reader_fd);
        let mut writer = File::from(writer_fd);

        let (tracer, _temp_files) = create_tracer(&test_base_dir, tracing_type.clone());

        let mut files_iter = files.iter();

        for line in generate_trace_line_for_open(
            tracing_type.clone(),
            files_iter.next().unwrap().0.path(),
            5,
            None,
        ) {
            writeln!(file, "{}", line).unwrap();
        }
        file.sync_all().unwrap();
        file.seek(std::io::SeekFrom::Start(0)).unwrap();

        let (mut tracer, exit_evt) =
            Tracer::create_with_config(file.reopen().unwrap(), reader, tracer).unwrap();

        let thd = thread::spawn(move || tracer.trace(None));

        for (index, file) in files_iter.enumerate() {
            for line in generate_trace_line_for_open(tracing_type.clone(), file.0.path(), 10, None)
            {
                writeln!(&mut writer, "{}", line).unwrap();
            }
            if index == 0 {
                // This sleep emulates delay in data arriving over a pipe. This shouldn't cause
                // flakes in virtualized environment.
                thread::sleep(Duration::from_secs(1));
            }
        }

        thread::sleep(Duration::from_millis(100));
        exit_evt.send(()).unwrap();
        writeln!(&mut writer, "line").unwrap();

        let tracer_rf = thd.join().unwrap().unwrap();

        let mut found_count = 0;
        for file in &files {
            let mut found = false;
            'inner: for inode in tracer_rf.inner.inode_map.values() {
                for found_path in &inode.paths {
                    if found_path == file.0.path().canonicalize().unwrap().to_str().unwrap() {
                        found = true;
                        break 'inner;
                    }
                }
            }
            if found {
                found_count += 1;
            } else {
                println!("missing {:?}", file.0.path());
            }
        }
        assert_eq!(found_count, files.len());
        assert_eq!(tracer_rf.inner.records.len(), files.len() * RECORD_PER_FILE);
    }

    #[test]
    fn test_trace_mem() {
        test_trace_of_type(TracerType::Mem)
    }
}
