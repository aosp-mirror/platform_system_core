// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A Rust interface for the StatsD pull API.

use once_cell::sync::Lazy;
use statslog_rust_header::{Atoms, Stat, StatsError};
use statspull_bindgen::*;
use std::collections::HashMap;
use std::convert::TryInto;
use std::os::raw::c_void;
use std::sync::Mutex;

/// The return value of callbacks.
pub type StatsPullResult = Vec<Box<dyn Stat>>;

/// A wrapper for AStatsManager_PullAtomMetadata.
/// It calls AStatsManager_PullAtomMetadata_release on drop.
pub struct Metadata {
    metadata: *mut AStatsManager_PullAtomMetadata,
}

impl Metadata {
    /// Calls AStatsManager_PullAtomMetadata_obtain.
    pub fn new() -> Self {
        // Safety: We panic if the memory allocation fails.
        let metadata = unsafe { AStatsManager_PullAtomMetadata_obtain() };
        if metadata.is_null() {
            panic!("Cannot obtain pull atom metadata.");
        } else {
            Metadata { metadata }
        }
    }

    /// Calls AStatsManager_PullAtomMetadata_setCoolDownMillis.
    pub fn set_cooldown_millis(&mut self, cooldown_millis: i64) {
        // Safety: Metadata::new ensures that self.metadata is a valid object.
        unsafe { AStatsManager_PullAtomMetadata_setCoolDownMillis(self.metadata, cooldown_millis) }
    }

    /// Calls AStatsManager_PullAtomMetadata_getCoolDownMillis.
    pub fn get_cooldown_millis(&self) -> i64 {
        // Safety: Metadata::new ensures that self.metadata is a valid object.
        unsafe { AStatsManager_PullAtomMetadata_getCoolDownMillis(self.metadata) }
    }

    /// Calls AStatsManager_PullAtomMetadata_setTimeoutMillis.
    pub fn set_timeout_millis(&mut self, timeout_millis: i64) {
        // Safety: Metadata::new ensures that self.metadata is a valid object.
        unsafe { AStatsManager_PullAtomMetadata_setTimeoutMillis(self.metadata, timeout_millis) }
    }

    /// Calls AStatsManager_PullAtomMetadata_getTimeoutMillis.
    pub fn get_timeout_millis(&self) -> i64 {
        // Safety: Metadata::new ensures that self.metadata is a valid object.
        unsafe { AStatsManager_PullAtomMetadata_getTimeoutMillis(self.metadata) }
    }

    /// Calls AStatsManager_PullAtomMetadata_setAdditiveFields.
    pub fn set_additive_fields(&mut self, additive_fields: &mut [i32]) {
        // Safety: Metadata::new ensures that self.metadata is a valid object.
        unsafe {
            AStatsManager_PullAtomMetadata_setAdditiveFields(
                self.metadata,
                additive_fields.as_mut_ptr(),
                additive_fields.len().try_into().expect("Cannot convert length to i32"),
            )
        }
    }

    /// Calls AStatsManager_PullAtomMetadata_getAdditiveFields.
    pub fn get_additive_fields(&self) -> Vec<i32> {
        // Safety: Metadata::new ensures that self.metadata is a valid object.
        // We call getNumAdditiveFields to ensure we pass getAdditiveFields a large enough array.
        unsafe {
            let num_fields = AStatsManager_PullAtomMetadata_getNumAdditiveFields(self.metadata)
                .try_into()
                .expect("Cannot convert num additive fields to usize");
            let mut fields = vec![0; num_fields];
            AStatsManager_PullAtomMetadata_getAdditiveFields(self.metadata, fields.as_mut_ptr());
            fields
        }
    }
}

impl Drop for Metadata {
    fn drop(&mut self) {
        // Safety: Metadata::new ensures that self.metadata is a valid object.
        unsafe { AStatsManager_PullAtomMetadata_release(self.metadata) }
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

static COOKIES: Lazy<Mutex<HashMap<i32, fn() -> StatsPullResult>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// # Safety
///
/// `data` must be a valid pointer with no aliases.
unsafe extern "C" fn callback_wrapper(
    atom_tag: i32,
    data: *mut AStatsEventList,
    _cookie: *mut c_void,
) -> AStatsManager_PullAtomCallbackReturn {
    if !data.is_null() {
        let map = COOKIES.lock().unwrap();
        let cb = map.get(&atom_tag);
        match cb {
            None => log::error!("No callback found for {}", atom_tag),
            Some(cb) => {
                let stats = cb();
                let result = stats
                    .iter()
                    // Safety: The caller promises that `data` is valid and unaliased.
                    .map(|stat| stat.add_astats_event(unsafe { &mut *data }))
                    .collect::<Result<Vec<()>, StatsError>>();
                match result {
                    Ok(_) => {
                        return AStatsManager_PULL_SUCCESS as AStatsManager_PullAtomCallbackReturn
                    }
                    _ => log::error!("Error adding astats events: {:?}", result),
                }
            }
        }
    }
    AStatsManager_PULL_SKIP as AStatsManager_PullAtomCallbackReturn
}

/// Rust wrapper for AStatsManager_setPullAtomCallback.
pub fn set_pull_atom_callback(
    atom: Atoms,
    metadata: Option<&Metadata>,
    callback: fn() -> StatsPullResult,
) {
    COOKIES.lock().unwrap().insert(atom as i32, callback);
    let metadata_raw = match metadata {
        Some(m) => m.metadata,
        None => std::ptr::null_mut(),
    };
    // Safety: We pass a valid function as the callback.
    unsafe {
        AStatsManager_setPullAtomCallback(
            atom as i32,
            metadata_raw,
            Some(callback_wrapper),
            std::ptr::null_mut(),
        );
    }
}

/// Rust wrapper for AStatsManager_clearPullAtomCallback.
pub fn clear_pull_atom_callback(atom: Atoms) {
    COOKIES.lock().unwrap().remove(&(atom as i32));
    // Safety: No memory allocations.
    unsafe { AStatsManager_clearPullAtomCallback(atom as i32) }
}
