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

//! See top level documentation for `crate::tracer`.

use std::collections::hash_map::Iter;
use std::fs::symlink_metadata;
use std::io::{ErrorKind, Write};
use std::iter::Iterator;
use std::mem::take;
use std::os::unix::fs::MetadataExt;
use std::{
    collections::{HashMap, HashSet},
    fs::read_to_string,
    option::Option,
    path::{Path, PathBuf},
};

use log::{debug, error, info, warn};
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use walkdir::{DirEntry, WalkDir};

use crate::format::{coalesce_records, FsInfo};
use crate::tracer::{page_size, TracerConfigs};
use crate::{
    format::{DeviceNumber, InodeNumber},
    tracer::{TraceSubsystem, EXCLUDE_PATHS},
    Error, FileId, Record, RecordsFile,
};

static MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

// Trace events to enable
// Paths are relative to trace mount point
static TRACE_EVENTS: &[&str] =
    &["events/filemap/mm_filemap_add_to_page_cache/enable", "tracing_on"];

// Filesystem types to ignore
static EXCLUDED_FILESYSTEM_TYPES: &[&str] = &[
    "binder",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "devpts",
    "fuse", // No emulated storage
    "fusectl",
    "proc",
    "pstore",
    "selinuxfs",
    "sysfs",
    "tmpfs", // Check for apex mount points
    "tracefs",
    "functionfs", // adb, fastboot
    "f2fs",       // Skip /data mounts
];

#[cfg(target_os = "linux")]
type MajorMinorType = u32;
#[cfg(target_os = "android")]
type MajorMinorType = i32;

// TODO(b/302056482): Once we uprev nix crate, we can use the function exported by the crate.
fn major(dev: DeviceNumber) -> MajorMinorType {
    (((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff)) as MajorMinorType
}

// TODO(b/302056482): Once we uprev nix crate, we can use the function exported by the crate.
fn minor(dev: DeviceNumber) -> MajorMinorType {
    (((dev >> 12) & 0xffff_ff00) | ((dev) & 0x0000_00ff)) as MajorMinorType
}

// TODO(b/302056482): Once we uprev nix crate, we can use the function exported by the crate.
fn makedev(major: MajorMinorType, minor: MajorMinorType) -> DeviceNumber {
    let major = major as DeviceNumber;
    let minor = minor as DeviceNumber;
    ((major & 0xffff_f000) << 32)
        | ((major & 0x0000_0fff) << 8)
        | ((minor & 0xffff_ff00) << 12)
        | (minor & 0x0000_00ff)
}

fn build_device_number(major: &str, minor: &str) -> Result<DeviceNumber, Error> {
    Ok(makedev(
        major.parse::<MajorMinorType>().map_err(|e| Error::Custom {
            error: format!("Failed to parse major number from {} with {}", major, e),
        })?,
        minor.parse::<MajorMinorType>().map_err(|e| Error::Custom {
            error: format!("Failed to parse major number from {} with {}", major, e),
        })?,
    ))
}

// Returns timestamp in nanoseconds
fn build_timestamp(seconds: &str, microseconds: &str) -> Result<u64, Error> {
    let seconds = seconds.parse::<u64>().map_err(|e| Error::Custom {
        error: format!("Failed to parse seconds from {} with {}", seconds, e),
    })?;
    let microseconds = microseconds.parse::<u64>().map_err(|e| Error::Custom {
        error: format!("Failed to parse microseconds from {} with {}", seconds, e),
    })?;
    Ok((seconds * 1_000_000_000) + (microseconds * 1_000))
}

#[cfg(not(target_os = "android"))]
fn is_highly_privileged_path(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "android")]
fn is_highly_privileged_path(path: &Path) -> bool {
    // Following directories contain a mix of files with and without access to stat/read.
    // We do not completely exclude these directories as there is still a lot of
    // file we can issue readahead on. Some of the files on which readahead fails include
    // - /system/bin/run-as
    // - /data/data/com.android.storagemanager
    // - /system/apex/com.android.art/bin/dex2oat32
    // - /data/user/0/com.android.systemui
    //
    // - TODO: /system/apex: Apex files in read-only partition may be read during boot.
    // However, some files may not have access. Double check the record files
    // to filter out the exact path.
    let privileged_paths = [
        "/data/data",
        "/data/user/0",
        "/data/user_de/0",
        "/system/bin/",
        "/system/etc/selinux/",
        "/system/system_ext/etc/selinux/",
        "/system/product/etc/selinux/",
        "/system/vendor/etc/selinux/",
        "/system_ext/etc/selinux/",
        "/product/etc/selinux/",
        "/vendor/etc/selinux/",
        "/system/xbin",
        "/system/etc/",
        "/data/",
        "/postinstall/",
        "/mnt/",
        "/metadata/",
    ];
    for privileged in privileged_paths {
        if path.to_str().unwrap().starts_with(privileged) {
            return true;
        }
    }
    false
}

enum DeviceState {
    Include((DeviceNumber, PathBuf)),
    Exclude(DeviceNumber),
}

/// Utility struct that helps to include and exclude devices and mount points that need and don't
/// need prefetching.
#[derive(Debug, Deserialize, Serialize)]
struct MountInfo {
    // Map of device number to mount points
    included_devices: HashMap<DeviceNumber, PathBuf>,

    // Devices that we don't want to prefetch - like devices backing tempfs and sysfs
    excluded_devices: HashSet<DeviceNumber>,
}

impl MountInfo {
    // Parses file at `path` to build `Self`.`
    fn create(path: &str) -> Result<Self, Error> {
        let buf = read_to_string(path)
            .map_err(|e| Error::Read { error: format!("Reading {} failed with: {}", path, e) })?;
        Self::with_buf(&buf)
    }

    // Parses string in `buf` to build `Self`.
    fn with_buf(buf: &str) -> Result<Self, Error> {
        let regex = Self::get_regex()?;
        let mut included_devices: HashMap<DeviceNumber, PathBuf> = HashMap::new();
        let mut excluded_devices = HashSet::new();
        let excluded_filesystem_types: HashSet<String> =
            EXCLUDED_FILESYSTEM_TYPES.iter().map(|s| String::from(*s)).collect();
        for line in buf.lines() {
            if let Some(state) = Self::parse_line(&regex, &excluded_filesystem_types, line)? {
                match state {
                    DeviceState::Include((device, path)) => {
                        included_devices.insert(device, path);
                    }
                    DeviceState::Exclude(device) => {
                        excluded_devices.insert(device);
                    }
                }
            }
        }

        Ok(Self { included_devices, excluded_devices })
    }

    fn parse_line(
        re: &Regex,
        excluded_filesystem_types: &HashSet<String>,
        line: &str,
    ) -> Result<Option<DeviceState>, Error> {
        let caps = match re.captures(line) {
            Some(caps) => caps,
            None => {
                return Ok(None);
            }
        };
        if &caps["relative_path"] != "/" {
            return Ok(None);
        }

        let mount_point = &caps["mount_point"];
        let mnt_pnt_with_slash = format!("{}/", mount_point);
        let device_number = build_device_number(&caps["major"], &caps["minor"])?;
        let fs_type = &caps["fs_type"];

        if excluded_filesystem_types.contains(fs_type) {
            info!(
                "excluding fs type: {} for {} mount-point {} slash {}",
                fs_type, line, mount_point, mnt_pnt_with_slash
            );
            return Ok(Some(DeviceState::Exclude(device_number)));
        }

        for excluded in EXCLUDE_PATHS {
            if mnt_pnt_with_slash.starts_with(excluded) {
                info!(
                    "exclude-paths fs type: {} for {} mount-point {} slash {}",
                    fs_type, line, mount_point, mnt_pnt_with_slash
                );
                return Ok(Some(DeviceState::Exclude(device_number)));
            }
        }

        Ok(Some(DeviceState::Include((device_number, PathBuf::from(mount_point)))))
    }

    fn get_regex() -> Result<Regex, Error> {
        Regex::new(concat!(
            r"^\s*(?P<id_unknown1>\S+)",
            r"\s+(?P<id_unknown2>\S+)",
            r"\s+(?P<major>[0-9]+):(?P<minor>[0-9]+)",
            r"\s+(?P<relative_path>\S+)",
            r"\s+(?P<mount_point>\S+)",
            r"\s+(?P<mount_opt>\S+)",
            r"\s+(?P<shared>\S+)",
            r"\s+\S+",
            r"\s+(?P<fs_type>\S+)",
            r"\s+(?P<device_path>\S+)"
        ))
        .map_err(|e| Error::Custom {
            error: format!("create regex for parsing mountinfo failed with: {}", e),
        })
    }

    fn is_excluded(&self, device: &DeviceNumber) -> bool {
        self.excluded_devices.contains(device)
    }

    fn get_included(&self) -> Iter<DeviceNumber, PathBuf> {
        self.included_devices.iter()
    }
}

#[derive(Default, PartialEq, Debug, Eq, Hash)]
struct TraceLineInfo {
    device: DeviceNumber,
    inode: InodeNumber,
    offset: u64,
    timestamp: u64,
}

impl TraceLineInfo {
    pub fn from_trace_line(re: &Regex, line: &str) -> Result<Option<Self>, Error> {
        let caps = match re.captures(line) {
            Some(caps) => caps,
            None => return Ok(None),
        };
        let major = &caps["major"];
        let minor = &caps["minor"];
        let ino = &caps["ino"];
        let offset = &caps["offset"];
        let timestamp = build_timestamp(&caps["seconds"], &caps["microseconds"])?;
        Ok(Some(TraceLineInfo {
            device: build_device_number(major, minor)?,
            inode: u64::from_str_radix(ino, 16).map_err(|e| Error::Custom {
                error: format!("failed parsing inode: {} : {}", ino, e),
            })?,
            offset: offset.parse::<u64>().map_err(|e| Error::Custom {
                error: format!("failed parsing offset: {} : {}", offset, e),
            })?,
            timestamp,
        }))
    }

    #[cfg(test)]
    pub fn from_fields(
        major: MajorMinorType,
        minor: MajorMinorType,
        inode: u64,
        offset: u64,
        timestamp: u64,
    ) -> Self {
        Self { device: makedev(major, minor), inode, offset, timestamp }
    }

    // Convenience function to create regex. Used once per life of `record` but multiple times in
    // case of tests.
    pub fn get_trace_line_regex() -> Result<Regex, Error> {
        // TODO: Fix this Regex expression for 5.15 kernels. This expression
        // works only on 6.1+. Prior to 6.1, "<page>" was present in the output.
        Regex::new(concat!(
            r"^\s+(?P<cmd_pid>\S+)",
            r"\s+(?P<cpu>\S+)",
            r"\s+(?P<irq_stuff>\S+)",
            r"\s+(?P<seconds>[0-9]+)\.(?P<microseconds>[0-9]+):",
            r"\s+mm_filemap_add_to_page_cache:",
            r"\s+dev\s+(?P<major>[0-9]+):(?P<minor>[0-9]+)",
            r"\s+ino\s+(?P<ino>\S+)",
            //r"\s+(?P<page>\S+)",
            r"\s+(?P<pfn>\S+)",
            r"\s+ofs=(?P<offset>[0-9]+)"
        ))
        .map_err(|e| Error::Custom {
            error: format!("create regex for tracing failed with: {}", e),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MissingFile {
    major_no: MajorMinorType,
    minor_no: MajorMinorType,
    inode: InodeNumber,
    records: Vec<Record>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct DebugInfo {
    // Check all inodes for which paths don't exists. These are the files which
    // * got deleted before we got to them
    // * are filesystem internal files that fs access only via inode numbers.
    missing_files: HashMap<FileId, MissingFile>,

    // Number of bytes read that belongs to directory type inodes.
    directory_read_bytes: u64,

    // Number of bytes read from files for which we could not find a path in
    // the filesystems.
    missing_path_bytes: u64,

    // Paths for which the current process doesn't have read permission.
    privileged_paths: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
pub(crate) struct MemTraceSubsystem {
    device_inode_map: HashMap<DeviceNumber, HashMap<InodeNumber, FileId>>,
    // Count of all InodeNumber held by `device_inode_map`. This is handy to assign unique
    // FileId.
    inode_count: u64,

    // `Record`s built from parsing read trace lines.
    records: Vec<Record>,

    // Regex to parse lines from trace_pipe.
    #[serde(skip_serializing)]
    regex: Regex,

    // Mounted devices/filesystems either at the time of parsing trace file or at the time
    // of building RecordsFile from parsed lines.
    mount_info: MountInfo,

    // A copy of TracerConfigs
    tracer_configs: Option<TracerConfigs>,

    // system page size stored to avoid frequent syscall to get the page size.
    page_size: u64,

    // The fields of the debug_info are populated when build_records_file is called (after lines
    // are parsed from the trace file/pipe).
    debug_info: DebugInfo,
}

impl MemTraceSubsystem {
    pub fn update_configs(configs: &mut TracerConfigs) {
        for path in EXCLUDE_PATHS {
            configs.excluded_paths.push(path.to_owned().to_string());
        }

        for event in TRACE_EVENTS {
            configs.trace_events.push(event.to_owned().to_string());
        }
        configs.mountinfo_path = Some(MOUNTINFO_PATH.to_string());
    }

    pub fn create_with_configs(tracer_configs: TracerConfigs) -> Result<Self, Error> {
        static INITIAL_RECORDS_CAPACITY: usize = 100_000;
        debug!("TracerConfig: {:#?}", tracer_configs);

        let regex = TraceLineInfo::get_trace_line_regex()?;
        let mount_info = MountInfo::create(tracer_configs.mountinfo_path.as_ref().unwrap())?;
        debug!("mountinfo: {:#?}", mount_info);

        Ok(Self {
            device_inode_map: HashMap::new(),
            inode_count: 0,
            // For one product of android, we see around 50k records. To avoid a lot allocations
            // and copying of records, we create a vec of this size.
            //
            // We do this to reduces chances of losing data, however unlikely, coming over
            // `trace_pipe`.
            //
            // Note: Once we are done reading trace lines, we are less pedantic about allocations
            // and mem copies.
            records: Vec::with_capacity(INITIAL_RECORDS_CAPACITY),
            regex,
            mount_info,
            tracer_configs: Some(tracer_configs),
            page_size: page_size()? as u64,
            debug_info: DebugInfo {
                missing_files: HashMap::new(),
                directory_read_bytes: 0,
                missing_path_bytes: 0,
                privileged_paths: vec![],
            },
        })
    }

    fn new_file_id(&mut self) -> FileId {
        let id = self.inode_count;
        self.inode_count += 1;
        FileId(id)
    }

    fn get_trace_info(&self, line: &str) -> Result<Option<TraceLineInfo>, Error> {
        TraceLineInfo::from_trace_line(&self.regex, line)
    }

    // Returns true if the file or directory is on a device which is excluded from walking.
    // If the path was excluded because the current process doesn't have privileged to read it,
    // the path gets added to `privileged` list.
    fn is_excluded(&self, entry: &DirEntry, device: u64, privileged: &mut Vec<PathBuf>) -> bool {
        // We skip paths that are reside on excluded devices here. This is ok because a
        // non-excluded mount point will have a separate entry in MountInfo. For example
        // - `/` has ext4
        // - `/tmp` has tempfs
        // - `/tmp/mnt` has ext4 that we are interested in.
        // MountInfo will have three entries - `/`, `/tmp/` and `/tmp/mnt`. Skipping walking
        // `/tmp` while walking `/` is ok as next `mount_info.get_included()` will return
        // `/tmp/mnt` path.
        //
        //
        // We skip links here as they can refer to mount points across
        // filesystems. If that path is valid and access are valid, then
        // we should have entry by the file's <device, inode> pair.
        //
        //
        // We skip devices that don't match current walking device because we eventually
        // walk other devices.
        match symlink_metadata(entry.path()) {
            Ok(lstat) => {
                if self.mount_info.is_excluded(&lstat.dev())
                    || lstat.dev() != device
                    || lstat.file_type().is_symlink()
                {
                    return true;
                }
            }
            Err(e) => {
                error!("stat on {} failed with {}", entry.path().to_str().unwrap(), e);

                // We treat EACCES special because on some platforms, like android, process needs to
                // have very special set of permissions to access some inodes.
                // We ignore errors in such cases *after* making an effort to get to them.
                if e.kind() == ErrorKind::PermissionDenied
                    && is_highly_privileged_path(entry.path())
                {
                    privileged.push(entry.path().to_owned());
                    return true;
                }
            }
        }

        // On error, we return false because if lstat has failed, it will fail following operations
        // including stat.
        false
    }
}

impl TraceSubsystem for MemTraceSubsystem {
    fn add_line(&mut self, line: &str) -> Result<(), Error> {
        if let Some(info) = self.get_trace_info(line)? {
            if self.mount_info.is_excluded(&info.device) {
                return Ok(());
            }

            self.device_inode_map.entry(info.device).or_default();

            let file_id = if let Some(id) =
                self.device_inode_map.get_mut(&info.device).unwrap().get(&info.inode)
            {
                id.clone()
            } else {
                self.new_file_id()
            };
            self.device_inode_map
                .get_mut(&info.device)
                .unwrap()
                .insert(info.inode, file_id.clone());

            self.records.push(Record {
                file_id,
                offset: info.offset,
                length: self.page_size,
                timestamp: info.timestamp,
            });
        }

        Ok(())
    }

    fn build_records_file(&mut self) -> Result<RecordsFile, Error> {
        // reset debug_info in case build_records_file was called twice.
        self.debug_info = DebugInfo::default();
        let mut rf = RecordsFile::default();
        let mut directories = HashSet::new();

        // TODO(b/302194377): We are holding all privileged_paths in this variable and then
        // transferring it to `self.debug_info.privileged_paths` later. We can avoid this step
        // if we directly update `self.debug_info.privileged_paths`. To do so, we need to refactor
        // code to make borrow not complain at several places - ex. immutably borrowing
        // `self.mount_info` in outer loop and then mutably borrowing
        // `self.debug_info.privileged_paths`.
        let mut privileged_paths = vec![];

        // Reload mount_info. When we created mount_info for the first time, maybe
        // the system was in early boot phase. Reload the mount_info so as to get
        // current/new mount points.
        if let Some(tracer_config) = &self.tracer_configs {
            self.mount_info = MountInfo::create(tracer_config.mountinfo_path.as_ref().unwrap())?;
            debug!("reloaded mountinfo: {:#?}", self.mount_info);
        }

        for (device, root_path) in self.mount_info.get_included() {
            let inode_map = if let Some(map) = self.device_inode_map.get(device) {
                map
            } else {
                continue;
            };

            if inode_map.is_empty() {
                return Err(Error::Custom {
                    error: format!("Unexpected empty records for {:?}", root_path),
                });
            }

            let mut block_size = 0;
            let walker = WalkDir::new(root_path).into_iter();

            for entry in
                walker.filter_entry(|e| !self.is_excluded(e, *device, &mut privileged_paths))
            {
                let path = match entry {
                    Ok(entry) => entry.path().to_owned(),
                    Err(e) => {
                        error!("walking directory failed: {} {}", root_path.to_str().unwrap(), e);
                        continue;
                    }
                };

                let stat = match path.metadata() {
                    Ok(stat) => stat,
                    Err(e) => {
                        error!("stat on {} failed with {}", path.to_str().unwrap(), e);
                        continue;
                    }
                };

                block_size = stat.blksize();

                let file_id = if let Some(id) = inode_map.get(&stat.ino()) {
                    id.clone()
                } else {
                    continue;
                };

                // We cannot issue a normal readahead on directories. So we skip those records that
                // belong to directories.
                if stat.file_type().is_dir() {
                    info!(
                        "skipping directory readahead record for file_id:{file_id} ino:{} path:{} ",
                        stat.ino(),
                        path.to_str().unwrap()
                    );
                    directories.insert(file_id.clone());
                    continue;
                }

                rf.insert_or_update_inode(file_id, &stat, path.to_str().unwrap().to_owned());
            }

            rf.inner.filesystems.insert(*device, FsInfo { block_size });
        }

        self.debug_info.privileged_paths.append(&mut privileged_paths);

        for (device, inode_map) in &self.device_inode_map {
            for (inode, file_id) in inode_map {
                if !rf.inner.inode_map.contains_key(file_id) {
                    let major_no: MajorMinorType = major(*device);
                    let minor_no: MajorMinorType = minor(*device);
                    self.debug_info.missing_files.insert(
                        file_id.clone(),
                        MissingFile { major_no, minor_no, inode: *inode, records: vec![] },
                    );
                }
            }
        }

        // Remove all records that belong to directories or for which we did not find paths.
        let mut records = vec![];
        for record in take(&mut self.records) {
            if directories.contains(&record.file_id) {
                self.debug_info.directory_read_bytes += record.length;
            } else if let Some(missing_file) =
                self.debug_info.missing_files.get_mut(&record.file_id)
            {
                self.debug_info.missing_path_bytes += record.length;
                missing_file.records.push(record);
            } else {
                records.push(record);
            }
        }

        warn!(
            "Recorded {} bytes worth of data read from directories",
            self.debug_info.directory_read_bytes
        );
        warn!(
            "Recorded {} bytes worth of data read from files that don't have paths",
            self.debug_info.missing_path_bytes
        );

        rf.inner.records = coalesce_records(records, true);

        Ok(rf)
    }

    fn serialize(&self, write: &mut dyn Write) -> Result<(), Error> {
        write
            .write_all(
                &serde_json::to_vec(&self)
                    .map_err(|e| Error::Serialize { error: e.to_string() })?,
            )
            .map_err(|source| Error::Write { path: "intermediate file".to_owned(), source })
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::stat::{major, minor};
    use std::assert_eq;
    use std::path::Path;

    use crate::tracer::tests::{copy_uncached_files_and_record_from, setup_test_dir};

    use crate::replay::tests::generate_cached_files_and_record;

    use super::*;

    static TRACE_BUFFER: &str = r#"
 Settingide-502  [001] ....   484.360292: mm_filemap_add_to_page_CACHE: dev 254:6 ino cf1 page=68d477 pfn=59833 ofs=32768
 Settingide-502  [001] ....   484.360311: mm_filemap_add_to_page_cache: dev 254:6 ino cf1 page=759458 pfn=59827 ofs=57344
 BOX_ENTDED-3071 [001] ....   485.276715: mm_filemap_add_to_pag_ecache: dev 254:6 ino 1 page=00cc1c pfn=81748 ofs=13574144
 BOX_ENTDED-3071 [001] ....   485.276990: mm_filemap_add_to_page_cache: dev 254:6 ino cf2 page=36540b pfn=60952 ofs=0
 .gms.peent-843  [001] ....   485.545516: mm_filemap_add_to_page_cache: dev 254:6 ino 1 page=002e8b pfn=58928 ofs=13578240
 .gms.peent-843  [001] ....   485.545820: mm_filemap_add_to_page_cache: dev 254:6 ino cf3 page=6233ce pfn=58108 ofs=0
      an.bg-459  [001] ....   494.029396: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=c5b5c7 pfn=373933 ofs=1310720
      an.bg-459  [001] ....   494.029398: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=b8b9ec pfn=410074 ofs=1314816
       "#;

    fn sample_mem_traces() -> (String, Vec<Option<TraceLineInfo>>) {
        (
            TRACE_BUFFER.to_owned(),
            vec![
                None,
                None,
                Some(TraceLineInfo::from_fields(254, 6, 0xcf1, 57344, 484360311000)),
                None,
                Some(TraceLineInfo::from_fields(254, 6, 0xcf2, 0, 485276990000)),
                Some(TraceLineInfo::from_fields(254, 6, 0x1, 13578240, 485545516000)),
                Some(TraceLineInfo::from_fields(254, 6, 0xcf3, 0, 485545820000)),
                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1310720, 494029396000)),
                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1314816, 494029398000)),
                None,
            ],
        )
    }

    #[test]
    fn test_parse_trace_line() {
        let (buf, res) = sample_mem_traces();
        let re = TraceLineInfo::get_trace_line_regex().unwrap();
        for (index, line) in buf.lines().enumerate() {
            let found = TraceLineInfo::from_trace_line(&re, line).unwrap();
            let expected = res.get(index).unwrap();
            assert_eq!(found.is_some(), expected.is_some());
            if found.is_some() {
                assert_eq!(found.unwrap(), *expected.as_ref().unwrap());
            }
        }
    }

    #[test]
    fn test_add_line() {
        let test_base_dir = setup_test_dir();
        let (rf, mut files) =
            generate_cached_files_and_record(None, true, Some(page_size().unwrap() as u64));
        let (_uncached_rf, uncached_files) =
            copy_uncached_files_and_record_from(Path::new(&test_base_dir), &mut files, &rf);
        let mut mount_include = HashMap::new();

        let included_dev = uncached_files.get(0).unwrap().0.metadata().unwrap().dev();
        let included_inode1 = uncached_files.get(0).unwrap().0.metadata().unwrap().ino();
        let included_inode2 = uncached_files.get(1).unwrap().0.metadata().unwrap().ino();
        let included_major = major(included_dev);
        let included_minor = minor(included_dev);
        mount_include.insert(included_dev, std::fs::canonicalize(test_base_dir).unwrap());
        let mut mount_exclude = HashSet::new();
        mount_exclude.insert(0);

        let mut mem_tracer = MemTraceSubsystem {
            device_inode_map: HashMap::new(),
            inode_count: 0,
            records: vec![],
            regex: TraceLineInfo::get_trace_line_regex().unwrap(),
            mount_info: MountInfo {
                included_devices: mount_include,
                excluded_devices: mount_exclude,
            },
            tracer_configs: None,
            page_size: page_size().unwrap() as u64,
            debug_info: DebugInfo {
                missing_files: HashMap::new(),
                directory_read_bytes: 0,
                missing_path_bytes: 0,
                privileged_paths: vec![],
            },
        };

        let pg_size = page_size().unwrap();
        // Format is major, minor, inode, offset
        let inputs = vec![
            (0, 0, 2, 10), // to be excluded. bad device.
            (included_major, included_minor, included_inode1, 0),
            (included_major, included_minor, included_inode1, 3 * pg_size),
            // duplicate read
            (included_major, included_minor, included_inode1, 3 * pg_size),
            (0, 0, included_inode1, 10), // to be excluded. bad device.
            (included_major, included_minor, included_inode1, 2 * pg_size), // contiguous
            // non-contiguous
            (included_major, included_minor, included_inode1, 12 * pg_size),
            // same offset different inode
            (included_major, included_minor, included_inode2, 3 * pg_size),
            // Contiguous offset different inode
            (included_major, included_minor, included_inode2, pg_size),
        ];

        for (i, (major, minor, inode, offset)) in inputs.iter().enumerate() {
            // used to timestamp the log line.
            let seconds = i;
            // used to timestamp the log line.
            let microseconds = i;
            for operation in &["mm_filemap_add_to_page_cache", "some_other_operation"] {
                let line = format!(
                    " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: \
                    dev {}:{} ino {:x} page=00000000f936540b pfn=60952 ofs={}",
                    seconds, microseconds, operation, major, minor, inode, offset
                );
                mem_tracer.add_line(&line).unwrap();
            }
        }
        assert_eq!(mem_tracer.records.len(), 7);
        assert_eq!(mem_tracer.device_inode_map.len(), 1);
        assert_eq!(mem_tracer.device_inode_map.get(&included_dev).unwrap().len(), 2);
        assert!(mem_tracer
            .device_inode_map
            .get(&included_dev)
            .unwrap()
            .contains_key(&included_inode1));
        assert!(mem_tracer
            .device_inode_map
            .get(&included_dev)
            .unwrap()
            .contains_key(&included_inode2));
    }

    fn new_record(file: u64, offset: u64, length: u64, timestamp: u64) -> Record {
        Record { file_id: FileId(file), offset, length, timestamp }
    }

    #[test]
    fn test_get_records_file() {
        let test_base_dir = setup_test_dir();
        let (rf, mut files) =
            generate_cached_files_and_record(None, true, Some(page_size().unwrap() as u64));
        let (_uncached_rf, uncached_files) =
            copy_uncached_files_and_record_from(Path::new(&test_base_dir), &mut files, &rf);
        let mut mount_include = HashMap::new();

        let included_dev = uncached_files.get(0).unwrap().0.metadata().unwrap().dev();
        let included_inode1 = uncached_files.get(0).unwrap().0.metadata().unwrap().ino();
        let included_inode2 = uncached_files.get(1).unwrap().0.metadata().unwrap().ino();
        let included_major = major(included_dev);
        let included_minor = minor(included_dev);
        mount_include.insert(included_dev, std::fs::canonicalize(test_base_dir).unwrap());
        let mut mount_exclude = HashSet::new();
        mount_exclude.insert(0);

        let mut mem_tracer = MemTraceSubsystem {
            device_inode_map: HashMap::new(),
            inode_count: 0,
            records: vec![],
            regex: TraceLineInfo::get_trace_line_regex().unwrap(),
            mount_info: MountInfo {
                included_devices: mount_include,
                excluded_devices: mount_exclude,
            },
            tracer_configs: None,
            page_size: page_size().unwrap() as u64,
            debug_info: DebugInfo {
                missing_files: HashMap::new(),
                directory_read_bytes: 0,
                missing_path_bytes: 0,
                privileged_paths: vec![],
            },
        };

        let pg_size = page_size().unwrap() as u64;
        // Format is major, minor, inode, offset
        let inputs = vec![
            (0, 0, 2, 10), // to be excluded. bad device.
            (included_major, included_minor, included_inode1, 0),
            (included_major, included_minor, included_inode1, 3 * pg_size),
            // duplicate read
            (included_major, included_minor, included_inode1, 3 * pg_size),
            (0, 0, included_inode1, 10), // to be excluded. bad device.
            (included_major, included_minor, included_inode1, 2 * pg_size), // contiguous
            // non-contiguous
            (included_major, included_minor, included_inode1, 12 * pg_size),
            // same offset different inode
            (included_major, included_minor, included_inode2, 3 * pg_size),
            // Contiguous offset different inode
            (included_major, included_minor, included_inode2, pg_size),
        ];

        for (i, (major, minor, inode, offset)) in inputs.iter().enumerate() {
            // used to timestamp the log line.
            let seconds = i;
            // used to timestamp the log line.
            let microseconds = i;
            for operation in &["mm_filemap_add_to_page_cache", "some_other_operation"] {
                let line = format!(
                    " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: \
                    dev {}:{} ino {:x} page=00000000f936540b pfn=60952 ofs={}",
                    seconds, microseconds, operation, major, minor, inode, offset
                );
                mem_tracer.add_line(&line).unwrap();
            }
        }
        let rf = mem_tracer.build_records_file().unwrap();
        assert_eq!(
            rf.inner.records,
            vec![
                new_record(0, 0, pg_size, 1000001000),
                new_record(0, 2 * pg_size, 2 * pg_size, 2000002000),
                new_record(0, 12 * pg_size, pg_size, 6000006000),
                new_record(1, pg_size, pg_size, 8000008000),
                new_record(1, 3 * pg_size, pg_size, 7000007000),
            ]
        );
    }
}
