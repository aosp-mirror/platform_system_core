/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOUNTD_H__
#define MOUNTD_H__

#define LOG_TAG "mountd"
#include "cutils/log.h"

#include "ASEC.h"

typedef int boolean;
enum {
    false = 0,
    true = 1
};

#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)

// Set this for logging error messages
#define ENABLE_LOG_ERROR

// set this to log automounter events
#define ENABLE_LOG_MOUNT

// set this to log server events
//#define ENABLE_LOG_SERVER

// set this to log ASEC events
#define ENABLE_LOG_ASEC

#ifdef ENABLE_LOG_ERROR
#define LOG_ERROR(fmt, args...) \
    { LOGE(fmt , ## args); }
#else
#define LOG_ERROR(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_ERROR */

#ifdef ENABLE_LOG_MOUNT
#define LOG_MOUNT(fmt, args...) \
    { LOGD(fmt , ## args); }
#else
#define LOG_MOUNT(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_MOUNT */

#ifdef ENABLE_LOG_SERVER
#define LOG_SERVER(fmt, args...) \
    { LOGD(fmt , ## args); }
#else
#define LOG_SERVER(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_SERVER */

#ifdef ENABLE_LOG_ASEC
#define LOG_ASEC(fmt, args...) \
    { LOGD(fmt , ## args); }
#else
#define LOG_ASEC(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_ASEC */


typedef enum MediaState {
    // no media in SD card slot
    MEDIA_REMOVED,
    
    // media in SD card slot, but not mounted
    MEDIA_UNMOUNTED,
    
    // media in SD card slot and mounted at its mount point
    MEDIA_MOUNTED,
    
    // media in SD card slot, unmounted, and shared as a mass storage device
    MEDIA_SHARED,
    
    // media was removed from SD card slot, but mount point was not unmounted
    // this state is cleared after the mount point is unmounted
    MEDIA_BAD_REMOVAL,

    // media in SD card slot could not be mounted (corrupt file system?)
    MEDIA_UNMOUNTABLE,
} MediaState;

// socket name for connecting to mountd
#define MOUNTD_SOCKET         "mountd"

// mountd commands
// these must match the corresponding strings in //device/java/android/android/os/UsbListener.java
#define MOUNTD_ENABLE_UMS     "enable_ums"
#define MOUNTD_DISABLE_UMS    "disable_ums"
#define MOUNTD_SEND_STATUS    "send_status"

// these commands should contain a mount point following the colon
#define MOUNTD_MOUNT_MEDIA  "mount_media:"
#define MOUNTD_EJECT_MEDIA  "eject_media:"

// mountd events
// these must match the corresponding strings in //device/java/android/android/os/UsbListener.java
#define MOUNTD_UMS_ENABLED              "ums_enabled"
#define MOUNTD_UMS_DISABLED             "ums_disabled"
#define MOUNTD_UMS_CONNECTED            "ums_connected"
#define MOUNTD_UMS_DISCONNECTED         "ums_disconnected"

// these events correspond to the states in the MediaState enum.
// a path to the mount point follows the colon.
#define MOUNTD_MEDIA_REMOVED            "media_removed:"
#define MOUNTD_MEDIA_UNMOUNTED        	"media_unmounted:"
#define MOUNTD_MEDIA_MOUNTED          	"media_mounted:"
#define MOUNTD_MEDIA_MOUNTED_READ_ONLY  "media_mounted_ro:"
#define MOUNTD_MEDIA_SHARED             "media_shared:"
#define MOUNTD_MEDIA_BAD_REMOVAL        "media_bad_removal:"
#define MOUNTD_MEDIA_UNMOUNTABLE        "media_unmountable:"

// this event sent to request unmount for media mount point
#define MOUNTD_REQUEST_EJECT            "request_eject:"

// system properties
// these must match the corresponding strings in //device/java/android/android/os/Environment.java
#define EXTERNAL_STORAGE_STATE          "EXTERNAL_STORAGE_STATE"
#define EXTERNAL_STORAGE_REMOVED        "removed"
#define EXTERNAL_STORAGE_UNMOUNTED      "unmounted"
#define EXTERNAL_STORAGE_MOUNTED        "mounted"
#define EXTERNAL_STORAGE_MOUNTED_READ_ONLY        "mounted_ro"
#define EXTERNAL_STORAGE_SHARED         "shared"
#define EXTERNAL_STORAGE_BAD_REMOVAL    "bad_removal"
#define EXTERNAL_STORAGE_UNMOUNTABLE    "unmountable"

// AutoMount.c

boolean IsMassStorageEnabled();
boolean IsMassStorageConnected();

void MountMedia(const char* mountPoint);
void UnmountMedia(const char* mountPoint);
void EnableMassStorage(boolean enable);

// call this before StartAutoMounter() to add a mount point to monitor
void *AddMountPoint(const char* device, const char* mountPoint, const char* driverStorePath,
                    boolean enableUms);

int AddAsecToMountPoint(void *Mp, const char *name, const char *backing_file,
                        const char *size, const char *mount_point, const char *crypt);

// start automounter thread
void StartAutoMounter();

// check /proc/mounts for mounted file systems, and notify mount or unmount for any that are in our automount list
void NotifyExistingMounts();


// ASEC.c

void *AsecInit(const char *Name, const char *SrcPath, const char *BackingFile,
               const char *Size, const char *DstPath, const char *Crypt);
int AsecStart(void *Handle);
int AsecStop(void *Handle);
void AsecDeinit(void *Handle);
boolean AsecIsStarted(void *Handle);
const char *AsecMountPoint(void *Handle);

// ProcessKiller.c

void KillProcessesWithOpenFiles(const char* mountPoint, boolean sigkill, pid_t *excluded, int num_excluded);


// Server.c

int RunServer();
void SendMassStorageConnected(boolean connected); 
void SendUnmountRequest(const char* path);
void NotifyMediaState(const char* path, MediaState state, boolean readOnly);
void NotifyAsecState(AsecState state, const char *argument);
#endif // MOUNTD_H__
