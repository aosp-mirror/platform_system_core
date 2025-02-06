use crate::Error;
use crate::RecordArgs;
use crate::StartArgs;
use log::info;
use log::warn;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;

use rustutils::system_properties::error::PropertyWatcherError;
use rustutils::system_properties::PropertyWatcher;

const PREFETCH_RECORD_PROPERTY: &str = "prefetch_boot.record";
const PREFETCH_REPLAY_PROPERTY: &str = "prefetch_boot.replay";
const PREFETCH_RECORD_PROPERTY_STOP: &str = "prefetch_boot.record_stop";

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

fn start_prefetch_service(property_name: &str) -> Result<(), Error> {
    match rustutils::system_properties::write(property_name, "true") {
        Ok(_) => {}
        Err(_) => {
            return Err(Error::Custom { error: "Failed to start prefetch service".to_string() });
        }
    }
    Ok(())
}

/// Start prefetch service
///
/// 1: Check the presence of the file 'prefetch_ready'. If it doesn't
/// exist then the device is booting for the first time after wipe.
/// Thus, we would just create the file and exit as we do not want
/// to initiate the record after data wipe primiarly because boot
/// after data wipe is long and the I/O pattern during first boot may not actually match
/// with subsequent boot.
///
/// 2: If the file 'prefetch_ready' is present:
///
///   a: Compare the build-finger-print of the device with the one record format
///   is associated with by reading the file 'build_finger_print'. If they match,
///   start the prefetch_replay.
///
///   b: If they don't match, then the device was updated through OTA. Hence, start
///   a fresh record and delete the build-finger-print file. This should also cover
///   the case of device rollback.
///
///   c: If the build-finger-print file doesn't exist, then just restart the record
///   from scratch.
pub fn start_prefetch(args: &StartArgs) -> Result<(), Error> {
    if !args.path.exists() {
        match File::create(args.path.clone()) {
            Ok(_) => {}
            Err(_) => {
                return Err(Error::Custom { error: "File Creation failed".to_string() });
            }
        }
        return Ok(());
    }

    if args.build_fingerprint_path.exists() {
        let device_build_fingerprint = rustutils::system_properties::read("ro.build.fingerprint")
            .map_err(|e| Error::Custom {
            error: format!("Failed to read ro.build.fingerprint: {}", e),
        })?;
        let pack_build_fingerprint = std::fs::read_to_string(&args.build_fingerprint_path)?;
        if pack_build_fingerprint.trim() == device_build_fingerprint.as_deref().unwrap_or_default()
        {
            info!("Start replay");
            start_prefetch_service(PREFETCH_REPLAY_PROPERTY)?;
        } else {
            info!("Start record");
            std::fs::remove_file(&args.build_fingerprint_path)?;
            start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
        }
    } else {
        info!("Start record");
        start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
    }
    Ok(())
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
