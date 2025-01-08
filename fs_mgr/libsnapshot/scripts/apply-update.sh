#!/bin/bash

# Copyright 2024 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# apply_update.sh: Script to update the device in incremental way

# Ensure OUT directory exists
if [ -z "$OUT" ]; then
  echo "Error: OUT environment variable not set." >&2
  exit 1
fi

DEVICE_PATH="/data/verity-hash"
HOST_PATH="$OUT/verity-hash"

# Create the log file path
log_file="$HOST_PATH/snapshot.log"

# Function to log messages to both console and log file
log_message() {
    message="$1"
    echo "$message"  # Print to stdout
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$log_file"  # Append to log file with timestamp
}

# Function to check for create_snapshot and build if needed
ensure_create_snapshot() {
  if ! command -v create_snapshot &> /dev/null; then
    log_message "create_snapshot not found. Building..."
    m create_snapshot
    if [[ $? -ne 0 ]]; then
      log_message "Error: Failed to build create_snapshot."
      exit 1
    fi
  fi
}

ensure_create_snapshot

# Function to flash static partitions
flash_static_partitions() {
  local wipe_flag="$1"

  fastboot flash bootloader "$OUT"/bootloader.img
  fastboot reboot bootloader
  sleep 1
  fastboot flash radio "$OUT"/radio.img
  fastboot reboot bootloader
  sleep 1
  fastboot flashall --exclude-dynamic-partitions --disable-super-optimization --skip-reboot

  if (( wipe_flag )); then
      log_message "Wiping device..."
      fastboot -w
  fi
  fastboot reboot
}

# Function to display the help message
show_help() {
  cat << EOF
Usage: $0 [OPTIONS]

This script updates an Android device with incremental flashing, optionally wiping data and flashing static partitions.

Options:
  --skip-static-partitions  Skip flashing static partitions (bootloader, radio, boot, vbmeta, dtbo and other static A/B partitions).
                           * Requires manual update of static partitions on both A/B slots
                             *before* using this flag.
                           * Speeds up the update process and development iteration.
                           * Ideal for development focused on the Android platform (AOSP,
                             git_main).
                           * Safe usage: First update static partitions on both slots, then
                             use this flag for faster development iterations.
                             Ex:
                                1: Run this on both the slots - This will update the kernel and other static partitions:
                                   $fastboot flashall --exclude-dynamic-partitions --disable-super-optimization --skip-reboot

                                2: Update bootloader on both the slots:
                                    $fastboot flash bootloader $OUT/bootloader.img --slot=all

                                3: Update radio on both the slots:
                                    $fastboot flash radio $OUT/radio.img --slot=all
                            Now, the script can safely use this flag for update purpose.

  --wipe                   Wipe user data during the update.
  --help                   Display this help message.

Environment Variables:
  OUT                      Path to the directory containing build output.
                           This is required for the script to function correctly.

Examples:
  <Development workflow for any project in the platform and build with 'm' to create the images>

  Update the device:
  $0

  Update the device, but skip flashing static partitions (see above for the usage):
  $0 --skip-static-partitions

  Update the device and wipe user data:
  $0 --wipe

  Display this help message:
  $0 --help
EOF
}

skip_static_partitions=0
wipe_flag=0
help_flag=0

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --skip-static-partitions)
      skip_static_partitions=1
      ;;
    --wipe)
      wipe_flag=1
      ;;
    --help)
      help_flag=1
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      help_flag=1
      ;;
  esac
done

# Check if help flag is set
if (( help_flag )); then
  show_help
  exit 0
fi

rm -rf $HOST_PATH

adb root
adb wait-for-device

adb shell rm -rf $DEVICE_PATH
adb shell mkdir -p $DEVICE_PATH

echo "Extracting device source hash from dynamic partitions"
adb shell snapshotctl dump-verity-hash $DEVICE_PATH
adb pull -q $DEVICE_PATH $OUT/

log_message "Entering directory:"

# Navigate to the verity-hash directory
cd "$HOST_PATH" || { log_message "Error: Could not navigate to $HOST_PATH"; exit 1; }

pwd

# Iterate over all .pb files using a for loop
for pb_file in *.pb; do
  # Extract the base filename without the .pb extension
  base_filename="${pb_file%.*}"

  # Construct the source and target file names
  source_file="$pb_file"
  target_file="$OUT/$base_filename.img"

  # Construct the create_snapshot command using an array
  snapshot_args=(
    "create_snapshot"
    "--source" "$source_file"
    "--target" "$target_file"
    "--merkel_tree"
  )

  # Log the command about to be executed
  log_message "Running: ${snapshot_args[*]}"

  "${snapshot_args[@]}" >> "$log_file" 2>&1 &
done

log_message "Waiting for snapshot patch creation"

# Wait for all background processes to complete
wait $(jobs -p)

log_message "Snapshot patches created successfully"

adb push -q $HOST_PATH/*.patch $DEVICE_PATH

log_message "Applying update"

if (( wipe_flag )); then
  adb shell snapshotctl apply-update $DEVICE_PATH -w
else
  adb shell snapshotctl apply-update $DEVICE_PATH
fi

if (( skip_static_partitions )); then
    log_message "Rebooting device - Skipping flashing static partitions"
    adb reboot
else
    log_message "Rebooting device to bootloader"
    adb reboot bootloader
    log_message "Waiting to enter fastboot bootloader"
    flash_static_partitions "$wipe_flag"
fi

log_message "Update completed"
