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

use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fmt::Display;
use std::fs::{File, Metadata, OpenOptions};
use std::hash::Hash;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::MetadataExt;
use std::time::SystemTime;

use crc32fast::Hasher;
use log::debug;
use regex::Regex;
use serde::Deserializer;
use serde::Serialize;
use serde::{Deserialize, Serializer};

use crate::error::Error;

static MAGIC_UUID: [u8; 16] = [
    0x10, 0x54, 0x3c, 0xb8, 0x60, 0xdb, 0x49, 0x45, 0xa1, 0xd5, 0xde, 0xa7, 0xd2, 0x3b, 0x05, 0x49,
];
static MAJOR_VERSION: u16 = 0;
static MINOR_VERSION: u16 = 1;

/// Represents inode number which is unique within a filesystem.
pub(crate) type InodeNumber = u64;

/// Represents device number which is unique for given block device.
pub(crate) type DeviceNumber = u64;

/// Convenience name for string that represents a path.
pub(crate) type PathString = String;

/// Represents unique file id across filesystems.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Default, PartialEq, PartialOrd, Ord, Serialize)]
pub struct FileId(pub u64);

impl Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn serialize_hashmap<S, K: Ord + Serialize + Clone, V: Serialize + Clone>(
    value: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut btree = BTreeMap::new();
    for (k, v) in value {
        btree.insert(k.clone(), v.clone());
    }
    btree.serialize(serializer)
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SerializableHashMap<
    K: Ord + Serialize + Clone + Hash + PartialEq,
    V: Serialize + Clone,
> {
    #[serde(serialize_with = "serialize_hashmap")]
    pub map: HashMap<K, V>,
}

impl<K, V> Deref for SerializableHashMap<K, V>
where
    K: Ord + Serialize + Clone + Hash + PartialEq,
    V: Serialize + Clone,
{
    type Target = HashMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<K, V> DerefMut for SerializableHashMap<K, V>
where
    K: Ord + Serialize + Clone + Hash + PartialEq,
    V: Serialize + Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

/// The InodeInfo is unique per (device, inode) combination. It is
/// used to verify that we are prefetching a file for which we generated
/// the records for.
/// `Record` refers to this information with a unique `FileId`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InodeInfo {
    // Inode number of the file.
    pub(crate) inode_number: InodeNumber,

    // File size in bytes.
    pub(crate) file_size: u64,

    // Helps to get to a file from a Record. The field is used to get to the file
    // that needs to be prefetched.
    //
    // This struct is built by getting data from trace lines and querying filesystem
    // for other fields about the file/inode.
    //
    // One instance per file to be prefetched. A file/inode can have multiple paths.
    // We store multiple paths so that we can still get to it if some of the
    // paths get deleted.
    //
    // See comments for `Record`.
    #[serde(deserialize_with = "check_inode_info_paths")]
    pub(crate) paths: Vec<PathString>,

    // Block device number on which the file is located.
    pub(crate) device_number: DeviceNumber,
}

impl InodeInfo {
    /// Returns InodeInfo.
    pub fn new(
        inode_number: InodeNumber,
        file_size: u64,
        paths: Vec<String>,
        device_number: DeviceNumber,
    ) -> Self {
        Self { inode_number, file_size, paths, device_number }
    }
}

// Helps us check block alignment.
//
// A records file can have multiple FsInfos.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FsInfo {
    // This is filesystem block size and is not underlying device's block size
    pub(crate) block_size: u64,
}

/// Prefetch record.
/// Each record translates to one filesystem `read()` request.
///
/// Tracer builds `Record` by parsing trace lines or by querying filesystem.
///
/// Multiple `Record`s can belong to a single InodeInfo. For example if there were two
/// reads for file `/data/my.apk` which is assigned FileId 10 at offsets 0 and 8k of length
/// 1 byte each then we will have two `Records` in `RecordsFile` that look like
/// `Record {file_id: 10, offset: 0, length: 1, timestamp: t1}`
/// `Record {file_id: 10, offset: 8192, length: 1, timestamp: t2}`
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Record {
    /// Points to the file that should be fetched./ file_id is unique per `InodeInfo`
    /// in a `RecordsFile`
    pub file_id: FileId,

    /// start offset to fetch data from. This is FsInfo.block_size aligned.
    pub offset: u64,

    /// length of the read. This is generally rounded up to Fs.Info.block_size
    /// except when the rounding up crosses `InodeInfo.file_size`
    pub length: u64,

    /// Timestamp in nanoseconds since the start when the data was loaded.
    pub timestamp: u64,
}

impl Record {
    /// Returns a new record if two records belong to same file and overlap.
    fn overlaps(&self, other: &Self) -> Option<Self> {
        if self.file_id == other.file_id {
            let self_start = self.offset;
            let self_end = self.offset + self.length;
            let other_start = other.offset;
            let other_end = other.offset + other.length;

            if (self_start <= other_end) && (self_end >= other_start) {
                let offset = min(self_start, other_start);
                let length = max(self_end, other_end) - offset;
                return Some(Self {
                    file_id: self.file_id.clone(),
                    offset,
                    length,
                    timestamp: min(self.timestamp, other.timestamp),
                });
            }
        }
        None
    }
}

fn group_record_by_file_id(records: Vec<Record>) -> Vec<Record> {
    let mut map: HashMap<FileId, BTreeMap<u64, Record>> = HashMap::new();

    for record in &records {
        let recs = map.entry(record.file_id.clone()).or_default();
        recs.entry(record.offset).or_insert_with(|| record.clone());
    }

    let mut grouped = vec![];
    for record in &records {
        if let Some(inode) = map.get(&record.file_id) {
            for rec in inode.values() {
                grouped.push(rec.clone());
            }
        }
        let _ = map.remove(&record.file_id);
    }

    grouped
}

/// When records are coalesced, because their file ids match and IO offsets overlap, the least
/// timestamp of the coalesced records is retained.
pub(crate) fn coalesce_records(records: Vec<Record>, group_by_file_id: bool) -> Vec<Record> {
    let records = if group_by_file_id { group_record_by_file_id(records) } else { records };

    let mut coalesced = vec![];
    let mut current: Option<Record> = None;
    for r in records {
        current = match current {
            None => Some(r),
            Some(c) => {
                let merged = c.overlaps(&r);
                match merged {
                    None => {
                        coalesced.push(c);
                        Some(r)
                    }
                    Some(m) => Some(m),
                }
            }
        }
    }
    if let Some(r) = current {
        coalesced.push(r);
    }
    coalesced
}

// Records file header.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Header {
    /// magic number as uuid to identify the header/format.
    #[serde(deserialize_with = "check_magic")]
    magic: [u8; 16],

    // major version number.
    #[serde(deserialize_with = "check_major_number")]
    major_number: u16,

    // minor version number.
    #[serde(deserialize_with = "check_minor_number")]
    minor_number: u16,

    /// timestamp when the records file was generated.
    date: SystemTime,

    /// Checksum of the `RecordsFile` with `digest` being empty vector.
    digest: u32,
}

fn check_version_number<'de, D>(
    deserializer: D,
    expected: u16,
    version_type: &str,
) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let found = u16::deserialize(deserializer)?;
    if expected != found {
        return Err(serde::de::Error::custom(format!(
            "Failed to parse {} version. Expected: {} Found: {}",
            version_type, expected, found
        )));
    }
    Ok(found)
}

fn check_major_number<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    check_version_number(deserializer, MAJOR_VERSION, "major")
}

fn check_minor_number<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    check_version_number(deserializer, MINOR_VERSION, "minor")
}

fn check_magic<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let found: [u8; 16] = <[u8; 16]>::deserialize(deserializer)?;
    if found != MAGIC_UUID {
        return Err(serde::de::Error::custom(format!(
            "Failed to parse magic number. Expected: {:?} Found: {:?}",
            MAGIC_UUID, found
        )));
    }
    Ok(found)
}

fn check_inode_info_paths<'de, D>(deserializer: D) -> Result<Vec<PathString>, D::Error>
where
    D: Deserializer<'de>,
{
    let parsed: Vec<PathString> = Vec::deserialize(deserializer)?;
    if parsed.is_empty() {
        return Err(serde::de::Error::custom("No paths found for in InodeInfo"));
    }
    Ok(parsed)
}

// Helper inner struct of RecordsFile meant to verify checksum.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub(crate) struct RecordsFileInner {
    // One instance per mounted block device.
    pub(crate) filesystems: SerializableHashMap<DeviceNumber, FsInfo>,

    /// Helps to get to a file path from a given `FileId`.
    /// One instance per file to be prefetched.
    pub(crate) inode_map: SerializableHashMap<FileId, InodeInfo>,

    /// Helps to get to a file and offset to be replayed..
    ///
    // The records are chronologically arranged meaning the data that
    // needs first is at the beginning of the vector and the data that
    // needs last is at the end.
    //
    // One instance per part of the file that needs to be prefetched.
    pub records: Vec<Record>,
}

/// Deserialized form of records file.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(remote = "Self")]
pub struct RecordsFile {
    /// Helps the prefetch tool to parse rest of the file
    pub header: Header,

    /// Helps the prefetch tool to verify checksum.
    pub(crate) inner: RecordsFileInner,
}

impl RecordsFile {
    /// Given file id, looks up path of the file and returns open File handle.
    pub fn open_file(&self, id: FileId, exclude_files_regex: &[Regex]) -> Result<File, Error> {
        if let Some(inode) = self.inner.inode_map.get(&id) {
            let path = inode.paths.first().unwrap();

            for regex in exclude_files_regex {
                if regex.is_match(path) {
                    return Err(Error::SkipPrefetch { path: path.to_owned() });
                }
            }
            debug!("Opening {} file {}", id.0, path);
            OpenOptions::new()
                .read(true)
                .write(false)
                .open(path)
                .map_err(|source| Error::Open { source, path: path.to_owned() })
        } else {
            Err(Error::IdNoFound { id })
        }
    }

    /// Inserts given record in RecordsFile
    pub fn insert_record(&mut self, records: Record) {
        self.inner.records.push(records);
    }

    /// Inserts given InodeInfo into in RecordsFile.
    pub fn insert_or_update_inode_info(&mut self, id: FileId, info: InodeInfo) {
        if let Some(inode) = self.inner.inode_map.get_mut(&id) {
            if let Some(first_path) = info.paths.first() {
                inode.paths.push(first_path.clone());
            }
        } else {
            self.inner.inode_map.insert(id, info);
        }
    }

    /// Verifies the integrity of records file.
    ///
    /// check saves us from serializing a improperly built record file or replaying an inconsistent
    /// `RecordFile`.
    ///
    /// Note: check only works on the `RecordsFile` and doesn't access filesystem. We limit the
    /// scope so that we avoid issuing filesystem operations(directory lookup, stats) twice - once
    /// during check and once during replaying.
    pub fn check(&self) -> Result<(), Error> {
        let mut unique_files = HashSet::new();
        let mut missing_file_ids = vec![];

        for record in &self.inner.records {
            if !self.inner.inode_map.contains_key(&record.file_id) {
                missing_file_ids.push(record.file_id.clone());
            }
            unique_files.insert(record.file_id.clone());
        }

        let mut stale_inodes = vec![];
        let mut missing_paths = vec![];
        for (file_id, inode_info) in &self.inner.inode_map.map {
            if inode_info.paths.is_empty() {
                missing_paths.push(inode_info.clone());
            }
            if !unique_files.contains(file_id) {
                stale_inodes.push(inode_info.clone());
            }
        }

        if !stale_inodes.is_empty() || !missing_paths.is_empty() || !missing_file_ids.is_empty() {
            return Err(Error::StaleInode { stale_inodes, missing_paths, missing_file_ids });
        }

        Ok(())
    }

    /// Builds InodeInfo from args and inserts inode info in RecordsFile.
    pub fn insert_or_update_inode(&mut self, id: FileId, stat: &Metadata, path: PathString) {
        self.insert_or_update_inode_info(
            id,
            InodeInfo {
                inode_number: stat.ino(),
                file_size: stat.len(),
                paths: vec![path],
                device_number: stat.dev(),
            },
        )
    }

    /// Serialize records in the form of csv.
    pub fn serialize_records_to_csv(&self, writer: &mut dyn Write) -> Result<(), Error> {
        let mut wtr = csv::Writer::from_writer(writer);

        #[derive(Serialize)]
        struct TempRecord<'a> {
            timestamp: u64,
            file: &'a PathString,
            offset: u64,
            length: u64,
            file_size: u64,
        }

        for record in &self.inner.records {
            if let Some(inode_info) = self.inner.inode_map.get(&record.file_id) {
                let mut inode_info = inode_info.clone();
                inode_info.paths.sort();

                if let Some(first_path) = inode_info.paths.first().cloned() {
                    // Clone the &String inside Option
                    let record = TempRecord {
                        timestamp: record.timestamp,
                        file: &first_path, // Now you have &String
                        offset: record.offset,
                        length: record.length,
                        file_size: inode_info.file_size,
                    };
                    wtr.serialize(&record)
                        .map_err(|e| Error::Serialize { error: e.to_string() })?;
                }
            }
        }
        wtr.flush()?;
        Ok(())
    }

    fn compute_digest(&mut self) -> Result<u32, Error> {
        self.header.digest = Default::default();
        let serialized = serde_cbor::to_vec(self)
            .map_err(|source| Error::Serialize { error: source.to_string() })?;

        let mut hasher = Hasher::new();
        hasher.update(&serialized);

        Ok(hasher.finalize())
    }

    /// Convenience wrapper around serialize that adds checksum/digest to the file
    /// to verify file consistency during replay/deserialize.
    pub fn add_checksum_and_serialize(&mut self) -> Result<Vec<u8>, Error> {
        self.header.digest = self.compute_digest()?;

        serde_cbor::to_vec(self).map_err(|source| Error::Serialize { error: source.to_string() })
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            major_number: MAJOR_VERSION,
            minor_number: MINOR_VERSION,
            date: SystemTime::now(),
            digest: 0,
            magic: MAGIC_UUID,
        }
    }
}

// Wrapper around deserialize to check any inconsistencies in the file format.
impl<'de> Deserialize<'de> for RecordsFile {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rf = Self::deserialize(deserializer)?;

        rf.check().map_err(|e| {
            serde::de::Error::custom(format!("failed to validate records file: {}", e))
        })?;

        let mut zero_digest = rf.clone();
        zero_digest.header.digest = 0;
        let digest =
            zero_digest.compute_digest().map_err(|e| serde::de::Error::custom(format!("{}", e)))?;

        if digest != rf.header.digest {
            return Err(serde::de::Error::custom(format!(
                "file consistency check failed. Expected: {}. Found: {}",
                digest, rf.header.digest
            )));
        }

        Ok(rf)
    }
}

// Wrapper around serialize to check any inconsistencies in the file format before serializing
impl Serialize for RecordsFile {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.check().map(|_| self).map_err(|e| {
            serde::ser::Error::custom(format!("failed to validate records file: {}", e))
        })?;
        Self::serialize(self, serializer)
    }
}

#[cfg(test)]
pub mod tests {

    use std::assert_eq;

    use super::*;

    #[test]
    fn test_major_version_mismatch() {
        let mut rf = RecordsFile::default();

        rf.header.major_number += 1;

        let serialized: Result<RecordsFile, serde_cbor::Error> =
            serde_cbor::from_slice(&serde_cbor::to_vec(&rf).unwrap());

        assert_eq!(
            serialized.unwrap_err().to_string(),
            format!(
                "Failed to parse major version. Expected: {} Found: {}",
                MAJOR_VERSION,
                MAJOR_VERSION + 1
            )
        );
    }

    #[test]
    fn test_minor_version_mismatch() {
        let mut rf = RecordsFile::default();

        rf.header.minor_number += 1;

        let serialized: Result<RecordsFile, serde_cbor::Error> =
            serde_cbor::from_slice(&serde_cbor::to_vec(&rf).unwrap());

        assert_eq!(
            serialized.unwrap_err().to_string(),
            format!(
                "Failed to parse minor version. Expected: {} Found: {}",
                MINOR_VERSION,
                MINOR_VERSION + 1
            )
        );
    }

    #[test]
    fn deserialize_inode_info_without_path() {
        let inode = InodeInfo { inode_number: 1, file_size: 10, paths: vec![], device_number: 1 };
        let serialized = serde_cbor::to_vec(&inode).unwrap();
        let deserialized: Result<InodeInfo, serde_cbor::Error> =
            serde_cbor::from_slice(&serialized);
        assert_eq!(
            deserialized.unwrap_err().to_string(),
            "No paths found for in InodeInfo".to_owned()
        );
    }
    #[test]
    fn test_serialize_records_to_csv() {
        let mut rf = RecordsFile::default();
        let file_count = 4;
        for i in 0..file_count {
            rf.insert_or_update_inode_info(
                FileId(i),
                InodeInfo {
                    inode_number: i,
                    file_size: i * 10,
                    paths: vec![format!("/hello/{}", i)],
                    device_number: i + 10,
                },
            )
        }
        for i in 0..10 {
            rf.insert_record(Record {
                file_id: FileId(i % file_count),
                offset: i * 3,
                length: i + 4,
                timestamp: i * file_count,
            });
        }

        let mut buf = vec![];
        rf.serialize_records_to_csv(&mut buf).unwrap();

        let data = String::from_utf8(buf).unwrap();
        assert_eq!(
            data,
            "timestamp,file,offset,length,file_size\n\
            0,/hello/0,0,4,0\n\
            4,/hello/1,3,5,10\n\
            8,/hello/2,6,6,20\n\
            12,/hello/3,9,7,30\n\
            16,/hello/0,12,8,0\n\
            20,/hello/1,15,9,10\n\
            24,/hello/2,18,10,20\n\
            28,/hello/3,21,11,30\n\
            32,/hello/0,24,12,0\n\
            36,/hello/1,27,13,10\n"
        );
    }

    fn new_record(file: u64, offset: u64, length: u64, timestamp: u64) -> Record {
        Record { file_id: FileId(file), offset, length, timestamp }
    }

    #[test]
    fn test_coalesced_without_group() {
        let non_coalescable_same_inode =
            vec![new_record(1, 2, 3, 4), new_record(1, 6, 3, 5), new_record(1, 10, 3, 6)];
        assert_eq!(
            coalesce_records(non_coalescable_same_inode.clone(), false),
            non_coalescable_same_inode
        );

        let non_coalescable_different_inode =
            vec![new_record(1, 2, 3, 4), new_record(2, 5, 3, 5), new_record(3, 8, 3, 6)];
        assert_eq!(
            coalesce_records(non_coalescable_different_inode.clone(), false),
            non_coalescable_different_inode
        );

        let some_coalesced =
            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(3, 8, 3, 6)];
        assert_eq!(
            coalesce_records(some_coalesced, false),
            vec![new_record(1, 2, 6, 4), new_record(3, 8, 3, 6),]
        );

        let coalesced_into_one =
            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(1, 8, 3, 6)];
        assert_eq!(coalesce_records(coalesced_into_one, false), vec![new_record(1, 2, 9, 4)]);

        let no_grouping_or_coalescing =
            vec![new_record(1, 2, 3, 4), new_record(3, 8, 3, 5), new_record(1, 5, 3, 6)];
        assert_eq!(
            coalesce_records(no_grouping_or_coalescing, false),
            vec![new_record(1, 2, 3, 4), new_record(3, 8, 3, 5), new_record(1, 5, 3, 6),]
        );
    }

    #[test]
    fn test_coalesced_with_grouping() {
        let non_coalescable_same_inode =
            vec![new_record(1, 2, 3, 4), new_record(1, 6, 3, 5), new_record(1, 10, 3, 6)];
        assert_eq!(
            coalesce_records(non_coalescable_same_inode.clone(), true),
            non_coalescable_same_inode
        );

        let non_coalescable_different_inode =
            vec![new_record(1, 2, 3, 4), new_record(2, 5, 3, 5), new_record(3, 8, 3, 6)];
        assert_eq!(
            coalesce_records(non_coalescable_different_inode.clone(), true),
            non_coalescable_different_inode
        );

        let some_coalesced =
            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(3, 8, 3, 6)];
        assert_eq!(
            coalesce_records(some_coalesced, true),
            vec![new_record(1, 2, 6, 4), new_record(3, 8, 3, 6),]
        );

        let coalesced_into_one =
            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(1, 8, 3, 6)];
        assert_eq!(coalesce_records(coalesced_into_one, true), vec![new_record(1, 2, 9, 4)]);

        let some_grouped_coalesced =
            vec![new_record(1, 2, 3, 4), new_record(3, 8, 3, 5), new_record(1, 5, 3, 6)];
        assert_eq!(
            coalesce_records(some_grouped_coalesced, true),
            vec![new_record(1, 2, 6, 4), new_record(3, 8, 3, 5),]
        );
    }

    #[test]
    fn check_missing_records() {
        let mut rf = RecordsFile::default();
        rf.inner.inode_map.insert(
            FileId(0),
            InodeInfo {
                inode_number: 0,
                file_size: 1,
                paths: vec!["hello".to_owned()],
                device_number: 2,
            },
        );
        rf.insert_record(Record { file_id: FileId(0), offset: 10, length: 20, timestamp: 30 });

        rf.inner.inode_map.insert(
            FileId(1),
            InodeInfo {
                inode_number: 1,
                file_size: 2,
                paths: vec!["world".to_owned()],
                device_number: 3,
            },
        );
        let e = rf.check().unwrap_err();
        assert_eq!(
            e.to_string(),
            "Stale inode(s) info found.\n\
                missing_file_ids: []\n\
                stale_inodes: [\n    \
                    InodeInfo {\n        \
                        inode_number: 1,\n        \
                        file_size: 2,\n        \
                        paths: [\n            \"world\",\n        ],\n        \
                        device_number: 3,\n    },\n] \n\
                missing_paths:[]"
        );
    }

    #[test]
    fn check_missing_file() {
        let mut rf = RecordsFile::default();
        rf.inner.inode_map.insert(
            FileId(0),
            InodeInfo {
                inode_number: 0,
                file_size: 1,
                paths: vec!["hello".to_owned()],
                device_number: 2,
            },
        );
        rf.insert_record(Record { file_id: FileId(0), offset: 10, length: 20, timestamp: 30 });
        rf.insert_record(Record { file_id: FileId(1), offset: 10, length: 20, timestamp: 30 });

        let e = rf.check().unwrap_err();
        assert_eq!(
            e.to_string(),
            "Stale inode(s) info found.\n\
                missing_file_ids: [\n    \
                    FileId(\n        1,\n    ),\n]\n\
                stale_inodes: [] \n\
                missing_paths:[]"
        );
    }

    #[test]
    fn check_missing_paths() {
        let mut rf = RecordsFile::default();
        rf.inner.inode_map.insert(
            FileId(0),
            InodeInfo { inode_number: 0, file_size: 1, paths: vec![], device_number: 2 },
        );
        rf.insert_record(Record { file_id: FileId(0), offset: 10, length: 20, timestamp: 30 });

        let e = rf.check().unwrap_err();
        assert_eq!(
            e.to_string(),
            "Stale inode(s) info found.\n\
                missing_file_ids: []\n\
                stale_inodes: [] \n\
                missing_paths:[\n    \
                    InodeInfo {\n        \
                        inode_number: 0,\n        \
                        file_size: 1,\n        \
                        paths: [],\n        \
                        device_number: 2,\n    },\n]"
        );
    }
}
