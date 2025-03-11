use crate::Error;
use crate::RecordArgs;
use log::warn;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use rustutils::system_properties::error::PropertyWatcherError;
use rustutils::system_properties::PropertyWatcher;

const PREFETCH_RECORD_PROPERTY_STOP: &str = "prefetch_boot.record_stop";

fn is_prefetch_enabled() -> Result<bool, Error> {
    rustutils::system_properties::read_bool("ro.prefetch_boot.enabled", false).map_err(|e| {
        Error::Custom { error: format!("Failed to read ro.prefetch_boot.enabled: {}", e) }
    })
}

fn wait_for_property_true(
    property_name: &str,
    timeout: Option<Duration>,
) -> Result<(), PropertyWatcherError> {
    let mut prop = PropertyWatcher::new(property_name)?;
    prop.wait_for_value("1", timeout)?;
    Ok(())
}

/// Wait for record to stop
pub fn wait_for_record_stop() {
    wait_for_property_true(PREFETCH_RECORD_PROPERTY_STOP, None).unwrap_or_else(|e| {
        warn!("failed to wait for {} with error: {}", PREFETCH_RECORD_PROPERTY_STOP, e)
    });
}

/// Checks if we can perform replay phase.
/// Ensure that the pack file exists and is up-to-date, returns false otherwise.
pub fn can_perform_replay(pack_path: &Path, fingerprint_path: &Path) -> Result<bool, Error> {
    if !is_prefetch_enabled()? {
        return Ok(false);
    }

    if !pack_path.exists() || !fingerprint_path.exists() {
        return Ok(false);
    }

    let saved_fingerprint = std::fs::read_to_string(fingerprint_path)?;

    let current_device_fingerprint = rustutils::system_properties::read("ro.build.fingerprint")
        .map_err(|e| Error::Custom {
            error: format!("Failed to read ro.build.fingerprint: {}", e),
        })?;

    Ok(current_device_fingerprint.is_some_and(|fp| fp == saved_fingerprint.trim()))
}

/// Checks if we can perform record phase.
/// Ensure that following conditions hold:
///   - File specified in ready_path exists. otherwise, create a new file and return false.
///   - can_perform_replay is false.
pub fn ensure_record_is_ready(
    ready_path: &Path,
    pack_path: &Path,
    fingerprint_path: &Path,
) -> Result<bool, Error> {
    if !is_prefetch_enabled()? {
        return Ok(false);
    }

    if !ready_path.exists() {
        File::create(ready_path)
            .map_err(|_| Error::Custom { error: "File Creation failed".to_string() })?;

        return Ok(false);
    }

    let can_replay = can_perform_replay(pack_path, fingerprint_path)?;
    Ok(!can_replay)
}

/// Write build finger print to associate prefetch pack file
pub fn write_build_fingerprint(args: &RecordArgs) -> Result<(), Error> {
    let mut build_fingerprint_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.build_fingerprint_path)
        .map_err(|source| Error::Create {
            source,
            path: args.build_fingerprint_path.to_str().unwrap().to_owned(),
        })?;

    let device_build_fingerprint =
        rustutils::system_properties::read("ro.build.fingerprint").unwrap_or_default();
    let device_build_fingerprint = device_build_fingerprint.unwrap_or_default();

    build_fingerprint_file.write_all(device_build_fingerprint.as_bytes())?;
    build_fingerprint_file.sync_all()?;

    Ok(())
}
