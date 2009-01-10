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

/*
** mountd automount support
*/

#include "mountd.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <stdlib.h>
#include <poll.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/loop.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>

#define DEVPATH    "/dev/block/"
#define DEVPATHLENGTH 11    // strlen(DEVPATH)

// FIXME - only one loop mount is supported at a time
#define LOOP_DEVICE "/dev/block/loop0"

// timeout value for poll() when retries are pending
#define POLL_TIMEOUT    1000

#define MAX_MOUNT_RETRIES   3
#define MAX_UNMOUNT_RETRIES   5

typedef enum {
    // device is unmounted
    kUnmounted,
    
    // attempting to mount device
    kMounting,
    
    // device is unmounted
    kMounted,
    
    // attempting to unmount device
    // so the media can be removed
    kUnmountingForEject,
    
    // attempting to mount device
    // so it can be shared via USB mass storage
    kUnmountingForUms,
} MountState;

typedef struct MountPoint {
    // block device to mount
    const char* device;
    
    // mount point for device
    const char* mountPoint;

    // path to the UMS driver file for specifying the block device path
    const char* driverStorePath;
    
    // true if device can be shared via
    // USB mass storage
    boolean enableUms;
 
    // Array of ASEC handles
    void *asecHandles[ASEC_STORES_MAX];

    // true if the device is being shared via USB mass storage
    boolean umsActive;
    
    // current state of the mount point
    MountState state;
    
    // number of mount or unmount retries so far, 
    // when attempting to mount or unmount the device
    int retryCount; 
 
    // next in sMountPointList linked list
    struct MountPoint* next;   
} MountPoint;

// list of our mount points (does not change after initialization)
static MountPoint* sMountPointList = NULL;
boolean gMassStorageEnabled = false;
boolean gMassStorageConnected = false;

static pthread_t sAutoMountThread = 0;
static pid_t gExcludedPids[2] = {-1, -1};

static const char FSCK_MSDOS_PATH[] = "/system/bin/dosfsck";

// number of mount points that have timeouts pending
static int sRetriesPending = 0;

// for synchronization between sAutoMountThread and the server thread
static pthread_mutex_t sMutex = PTHREAD_MUTEX_INITIALIZER;

// requests the USB mass_storage driver to begin or end sharing a block device
// via USB mass storage.
static void SetBackingStore(MountPoint* mp, boolean enable) 
{
    int fd;

    if (!mp->driverStorePath) {
        LOG_ERROR("no driver_store_path specified in config file for %s", mp->device);
        return;
    }

    LOG_MOUNT("SetBackingStore enable: %s\n", (enable ? "true" : "false"));
    fd = open(mp->driverStorePath, O_WRONLY);
    if (fd < 0)
    {
        LOG_ERROR("could not open driver_store_path %s\n", mp->driverStorePath);
    }
    else
    {
        if (enable)
        {
            write(fd, mp->device, strlen(mp->device));
            mp->umsActive = true;
        }
        else
        {
            char ch = 0;
            write(fd, &ch, 1);
            mp->umsActive = false;
        }
        close(fd);
    }
}

static boolean ReadMassStorageState()
{
    FILE* file = fopen("/sys/class/switch/usb_mass_storage/state", "r");
    if (file)
    {
        char    buffer[20];
        fgets(buffer, sizeof(buffer), file);
        fclose(file);
        return (strncmp(buffer, "online", strlen("online")) == 0);
    }
    else
    {
        LOG_ERROR("could not read initial mass storage state\n");
        return false;
    }
}

static boolean IsLoopMounted(const char* path)
{
    FILE* f;
    int count;
    char device[256];
    char mount_path[256];
    char rest[256];
    int result = 0;
    int path_length = strlen(path);
       
    f = fopen("/proc/mounts", "r");
    if (!f) {
        LOG_ERROR("could not open /proc/mounts\n");
        return -1;
    }

    do {
        count = fscanf(f, "%255s %255s %255s\n", device, mount_path, rest);
        if (count == 3) {
            if (strcmp(LOOP_DEVICE, device) == 0 && strcmp(path, mount_path) == 0)
            {
                result = 1;
                break;
            }
        }
    } while (count == 3);

    fclose(f);
    LOG_MOUNT("IsLoopMounted: %s returning %d\n", path, result);
    return result;
}

static int CheckFilesystem(const char *device)
{
    char cmdline[255];
    int rc;

    // XXX: SAN: Check for FAT signature
    
    int result = access(FSCK_MSDOS_PATH, X_OK);
    if (result != 0) {
        LOG_MOUNT("CheckFilesystem(%s): %s not found (skipping checks)\n", FSCK_MSDOS_PATH, device);
        return 0;
    }
 
    char *args[7];
    args[0] = FSCK_MSDOS_PATH;
    args[1] = "-v";
    args[2] = "-V";
    args[3] = "-w";
    args[4] = "-p";
    args[5] = device;
    args[6] = NULL;

    LOG_MOUNT("Checking filesystem on %s\n", device);
    rc = logwrap(6, args);
  
    // XXX: We need to be able to distinguish between a FS with an error
    // and a block device which does not have a FAT fs at all on it
    if (rc == 0) {
        LOG_MOUNT("Filesystem check completed OK\n");
        return 0;
    } else if (rc == 1) {
        LOG_MOUNT("Filesystem check failed (general failure)\n");
        return -EINVAL;
    } else if (rc == 2) {
        LOG_MOUNT("Filesystem check failed (invalid usage)\n");
        return -EIO;
    } else {
        LOG_MOUNT("Filesystem check failed (unknown exit code %d)\n", rc);
        return -EIO;
    }
}

static int DoMountDevice(const char* device, const char* mountPoint)
{
    LOG_MOUNT("Attempting mount of %s on %s\n", device, mountPoint);

#if CREATE_MOUNT_POINTS
    // make sure mount point exists
    mkdir(mountPoint, 0000);
#endif

    int flags = 0;
    
    if (device && strncmp(device, "/dev/", 5))
    {
        // mount with the loop driver if device does not start with "/dev/"
        int file_fd, device_fd;
        
        // FIXME - only one loop mount supported at a time
        file_fd = open(device, O_RDWR);
        if (file_fd < -1) {
            LOG_ERROR("open backing file %s failed\n", device);
            return 1;
        }
        device_fd = open(LOOP_DEVICE, O_RDWR);
        if (device_fd < -1) {
            LOG_ERROR("open %s failed", LOOP_DEVICE);
            close(file_fd);
            return 1;
        }
        if (ioctl(device_fd, LOOP_SET_FD, file_fd) < 0)
        {
            LOG_ERROR("ioctl LOOP_SET_FD failed\n");
            close(file_fd);
            close(device_fd);
            return 1;
        }

        close(file_fd);
        close(device_fd);
        device = "/dev/block/loop0";
    }

    int result = access(device, R_OK);
    if (result) {
	LOG_ERROR("Unable to access '%s' (%d)\n", device, errno);
   	return -errno;
    }

    if ((result = CheckFilesystem(device))) {
        LOG_ERROR("Not mounting filesystem due to check failure (%d)\n", result);
        // XXX:  Notify framework - need a new SDCARD state for the following:
        //       - SD cards which are not present
        //       - SD cards with no partition table
        //       - SD cards with no filesystem
        //       - SD cards with bad filesystem
        return result;
    }

    // Extra safety measures:
    flags |= MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;
    // Also, set fmask = 711 so that files cannot be marked executable,
    // and cannot by opened by uid 1000 (system). Similar, dmask = 700
    // so that directories cannot be accessed by uid 1000.
    result = mount(device, mountPoint, "vfat", flags, 
                       "utf8,uid=1000,gid=1000,fmask=711,dmask=700");
    if (result && errno == EROFS) {
        LOG_ERROR("mount failed EROFS, try again read-only\n");
        flags |= MS_RDONLY;
        result = mount(device, mountPoint, "vfat", flags,
                       "utf8,uid=1000,gid=1000,fmask=711,dmask=700");
    }

    if (result == 0) {
        LOG_MOUNT("Partition %s mounted on %s\n", device, mountPoint);
        NotifyMediaState(mountPoint, MEDIA_MOUNTED, (flags & MS_RDONLY) != 0);

        MountPoint* mp = sMountPointList;
        while (mp) {
            if (!strcmp(mountPoint, mp->mountPoint)) {
                int i;
             
                for (i = 0; i < ASEC_STORES_MAX; i++) {
                    if (mp->asecHandles[i] != NULL) {
                        int a_result;
                        if ((a_result = AsecStart(mp->asecHandles[i])) < 0) {
                            LOG_ERROR("ASEC start failure (%d)\n", a_result);
                        }
                    }
                }
                break;
            }
            mp = mp -> next;
        }
    } else if (errno == EBUSY) {
        LOG_MOUNT("Mount failed (already mounted)\n");
        result = 0;
    } else {
#if CREATE_MOUNT_POINTS
        rmdir(mountPoint);
#endif
        LOG_MOUNT("Unable to mount %s on %s\n", device, mountPoint);
    }

    return result;
}

static int DoUnmountDevice(MountPoint *mp)
{
    boolean loop = IsLoopMounted(mp->mountPoint);
    int i;

    for (i = 0; i < ASEC_STORES_MAX; i++) {
        if (mp->asecHandles[i] && AsecIsStarted(mp->asecHandles[i]))
            AsecStop(mp->asecHandles[i]);
    }

    int result = umount(mp->mountPoint);
    LOG_MOUNT("umount returned %d errno: %d\n", result, errno);

    if (result == 0)
    {
#if CREATE_MOUNT_POINTS
        rmdir(mountPoint);
#endif
        NotifyMediaState(mp->mountPoint, MEDIA_UNMOUNTED, false);
    }

    if (loop)
    {
        // free the loop device
        int loop_fd = open(LOOP_DEVICE, O_RDONLY);
        if (loop_fd < -1) {
            LOG_ERROR("open loop device failed\n");
        }
        if (ioctl(loop_fd, LOOP_CLR_FD, 0) < 0) {
            LOG_ERROR("ioctl LOOP_CLR_FD failed\n");
        }

        close(loop_fd);
    }

    // ignore EINVAL and ENOENT, since it usually means the device is already unmounted
    if (result && (errno == EINVAL || errno == ENOENT))
        result = 0;

    return result;
}

static int MountPartition(const char* device, const char* mountPoint)
{
    char    buf[100];
    int i;
    
    // attempt to mount subpartitions of the device
    for (i = 1; i < 10; i++)
    {
        int rc;
        snprintf(buf, sizeof(buf), "%sp%d", device, i);
        rc = DoMountDevice(buf, mountPoint);
        LOG_MOUNT("DoMountDevice(%s, %s) = %d\n", buf, mountPoint, rc);
        if (rc == 0)
            return 0;
    }

    return -1;
}

/*****************************************************
 * 
 * AUTO-MOUNTER STATE ENGINE IMPLEMENTATION
 * 
 *****************************************************/

static void SetState(MountPoint* mp, MountState state)
{
    mp->state = state;
}

// Enter a state that requires retries and timeouts.
static void SetRetries(MountPoint* mp, MountState state)
{
    SetState(mp, state);
    mp->retryCount = 0;

    sRetriesPending++;
    // wake up the automounter thread if we are being called 
    // from somewhere else with no retries pending
    if (sRetriesPending == 1 && sAutoMountThread != 0 && 
            pthread_self() != sAutoMountThread)
        pthread_kill(sAutoMountThread, SIGUSR1);
}

// Exit a state that requires retries and timeouts.
static void ClearRetries(MountPoint* mp, MountState state)
{
    SetState(mp, state);
    sRetriesPending--;
}

// attempt to mount the specified mount point.
// set up retry/timeout if it does not succeed at first.
static void RequestMount(MountPoint* mp)
{
    LOG_MOUNT("RequestMount %s\n", mp->mountPoint);

    if (mp->state != kMounted && mp->state != kMounting &&
            access(mp->device, R_OK) == 0) {
        // try raw device first
        if (DoMountDevice(mp->device, mp->mountPoint) == 0 ||
            MountPartition(mp->device, mp->mountPoint) == 0)
        {
            SetState(mp, kMounted);
        }
        else 
        {
            SetState(mp, kMounting);
            mp->retryCount = 0;
            SetRetries(mp, kMounting);
        }
    }
}

// Force the kernel to drop all caches.
static void DropSystemCaches(void)
{
    int fd;

    LOG_MOUNT("Dropping system caches\n");
    fd = open("/proc/sys/vm/drop_caches", O_WRONLY);

    if (fd > 0) {
        char ch = 3;
        int rc;

        rc = write(fd, &ch, 1);
        if (rc <= 0)
            LOG_MOUNT("Error dropping caches (%d)\n", rc);
        close(fd);
    }
}

// attempt to unmount the specified mount point.
// set up retry/timeout if it does not succeed at first.
static void RequestUnmount(MountPoint* mp, MountState retryState)
{
    int result;

    LOG_MOUNT("RequestUnmount %s retryState: %d\n", mp->mountPoint, retryState);
    
    if (mp->state == kMounted)
    {
        SendUnmountRequest(mp->mountPoint);

        // do this in case the user pulls the SD card before we can successfully unmount
        sync();
        DropSystemCaches();

        if (DoUnmountDevice(mp) == 0) 
        {
            SetState(mp, kUnmounted);
            if (retryState == kUnmountingForUms) 
            {
                SetBackingStore(mp, true);
                NotifyMediaState(mp->mountPoint, MEDIA_SHARED, false);
            }
        }
        else 
        {
            LOG_MOUNT("unmount failed, set retry\n");
            SetRetries(mp, retryState);
        }
    } 
    else if (mp->state == kMounting)
    {
        SetState(mp, kUnmounted);
    }
}

// returns true if the mount point should be shared via USB mass storage
static boolean MassStorageEnabledForMountPoint(const MountPoint* mp)
{
    return (gMassStorageEnabled && gMassStorageConnected && mp->enableUms);
}

// handles changes in gMassStorageEnabled and gMassStorageConnected
static void MassStorageStateChanged()
{
    MountPoint* mp = sMountPointList;

    boolean enable = (gMassStorageEnabled && gMassStorageConnected);
    LOG_MOUNT("MassStorageStateChanged enable: %s\n", (enable ? "true" : "false"));
    
    while (mp)
    {
        if (mp->enableUms)
        {
            if (enable)
            {
                if (mp->state == kMounting)
                    SetState(mp, kUnmounted);
                if (mp->state == kUnmounted) 
                {
                    SetBackingStore(mp, true);
                    NotifyMediaState(mp->mountPoint, MEDIA_SHARED, false);
                }
                else
                {
                    LOG_MOUNT("MassStorageStateChanged requesting unmount\n");
                    // need to successfully unmount first
                    RequestUnmount(mp, kUnmountingForUms);
                }
            } else if (mp->umsActive) {
                SetBackingStore(mp, false);
                if (mp->state == kUnmountingForUms)
                {
                    ClearRetries(mp, kMounted);
                    NotifyMediaState(mp->mountPoint, MEDIA_MOUNTED, false);
                }
                else if (mp->state == kUnmounted)
                {
                    NotifyMediaState(mp->mountPoint, MEDIA_UNMOUNTED, false);
                    RequestMount(mp);
                }
            }
        }

        mp = mp->next;
    }
}

// called when USB mass storage connected state changes
static void HandleMassStorageOnline(boolean connected)
{
    if (connected != gMassStorageConnected)
    {
        gMassStorageConnected = connected;
        SendMassStorageConnected(connected);
        
        // we automatically reset to mass storage off after USB is connected
        if (!connected)
            gMassStorageEnabled = false;
    
        MassStorageStateChanged();
    }
}

// called when a new block device has been created
static void HandleMediaInserted(const char* device)
{
    MountPoint* mp = sMountPointList;
    
    LOG_MOUNT("HandleMediaInserted(%s):\n", device);

    while (mp)
    {
        // see if the device matches mount point's block device
        if (mp->state == kUnmounted &&
                strncmp(device, mp->device + DEVPATHLENGTH, strlen(mp->device) - DEVPATHLENGTH) == 0) 
        {
            if (MassStorageEnabledForMountPoint(mp))
            {
                SetBackingStore(mp, true);
                NotifyMediaState(mp->mountPoint, MEDIA_SHARED, false);
            }
            else
                RequestMount(mp);
        }  
        mp = mp->next;
    }
}

// called when a new block device has been deleted
static void HandleMediaRemoved(const char* device)
{    
    MountPoint* mp = sMountPointList;
    while (mp)
    {
        if (strncmp(device, mp->device + DEVPATHLENGTH, strlen(mp->device) - DEVPATHLENGTH) == 0)
        {
            if (mp->enableUms)
                SetBackingStore(mp, false);

             if (mp->state == kMounted) 
            {
                RequestUnmount(mp, kUnmountingForEject);
                NotifyMediaState(mp->mountPoint, MEDIA_BAD_REMOVAL, false);
            }
            
            NotifyMediaState(mp->mountPoint, MEDIA_REMOVED, false);
            break;
        }  
        mp = mp->next;
    }
}

// Handle retrying to mount or unmount devices, 
// and handle timeout condition if we have tried too many times
static void HandleRetries()
{
    MountPoint* mp = sMountPointList;
    
    while (mp)
    {
       if (mp->state == kMounting) 
       {
            if (MountPartition(mp->device, mp->mountPoint) == 0)
            {
                // mount succeeded - clear the retry for this mount point
                ClearRetries(mp, kMounted);
            } 
            else 
            {
                mp->retryCount++;
                if (mp->retryCount == MAX_MOUNT_RETRIES)
                {
                    // we failed to mount the device too many times
                    ClearRetries(mp, kUnmounted);
                    // notify that we failed to mount
                    NotifyMediaState(mp->mountPoint, MEDIA_UNMOUNTABLE, false);
                }
            }
       } 
       else if (mp->state == kUnmountingForEject || mp->state == kUnmountingForUms)
       {
            if (DoUnmountDevice(mp) == 0)
            {
                // unmounting succeeded
                // start mass storage, if state is kUnmountingForUms
                if (mp->state == kUnmountingForUms)
                {
                    SetBackingStore(mp, true);
                     NotifyMediaState(mp->mountPoint, MEDIA_SHARED, false);
                }
                // clear the retry for this mount point
                ClearRetries(mp, kUnmounted);
            } 
            else 
            {
                mp->retryCount++;
                if (mp->retryCount >= MAX_UNMOUNT_RETRIES)
                {
                    // kill any processes that are preventing the device from unmounting
                    // send SIGKILL instead of SIGTERM if the first attempt did not succeed
                    boolean sigkill = (mp->retryCount > MAX_UNMOUNT_RETRIES);
                    
                    int i;

                    for (i = 0; i < ASEC_STORES_MAX; i++) {
                        if (mp->asecHandles[i] && AsecIsStarted(mp->asecHandles[i])) {
                            LOG_MOUNT("Killing processes for ASEC path '%s'\n",
                                      AsecMountPoint(mp->asecHandles[i]));
                            KillProcessesWithOpenFiles(AsecMountPoint(mp->asecHandles[i]),
                                                       sigkill,
                                                       gExcludedPids, sizeof(gExcludedPids) / sizeof(pid_t));

                            // Now that we've killed the processes, try to stop the volume again
                            AsecStop(mp->asecHandles[i]);
                        }
                    }

                    // unmounting the device is failing, so start killing processes
                    KillProcessesWithOpenFiles(mp->mountPoint, sigkill, gExcludedPids, 
                                               sizeof(gExcludedPids) / sizeof(pid_t));

                }
            }
       } 
        
        mp = mp->next;
    }
}

/*****************************************************
 * 
 * AUTO-MOUNTER THREAD
 * 
 *****************************************************/

static void sigusr1_handler(int signo)
{
    // don't need to do anything here
}

// create a socket for listening to inotify events
int CreateINotifySocket()
{
    // initialize inotify
    int fd = inotify_init();

    if (fd < 0) {
        LOG_ERROR("inotify_init failed, %s\n", strerror(errno));
        return -1;
    }

    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL));

    return fd;
}


// create a socket for listening to uevents
int CreateUEventSocket()
{
    struct sockaddr_nl addr;
    int sz = 64*1024;
    int fd;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0xffffffff;

   fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if(fd < 0)
    {
        LOG_ERROR("could not create NETLINK_KOBJECT_UEVENT socket\n");
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));

    if(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        LOG_ERROR("could not bind NETLINK_KOBJECT_UEVENT socket\n");
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * Automounter main event thread.
 * This thread listens for block devices being created and deleted via inotify,
 * and listens for changes in the USB mass storage connected/disconnected via uevents from the 
 * power supply driver.
 * This thread also handles retries and timeouts for requests to mount or unmount a device.
 */
static void* AutoMountThread(void* arg)
{
    int inotify_fd;
    int uevent_fd;
    int id;
    struct sigaction    actions;

    gExcludedPids[1] = getpid();

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &actions, NULL);
    
    // initialize inotify
    inotify_fd = CreateINotifySocket();
    // watch for files created and deleted in "/dev"
    inotify_add_watch(inotify_fd, DEVPATH, IN_CREATE|IN_DELETE);

    // initialize uevent watcher
    uevent_fd = CreateUEventSocket();
    if (uevent_fd < 0) 
    {
        LOG_ERROR("CreateUEventSocket failed, %s\n", strerror(errno));
        return NULL;
    }
    
    while (1)
    {
        struct pollfd fds[2];
        int timeout, result;

#define INOTIFY_IDX 0
#define UEVENT_IDX  1
    
        fds[INOTIFY_IDX].fd = inotify_fd;
        fds[INOTIFY_IDX].events = POLLIN;
        fds[INOTIFY_IDX].revents = 0;
        fds[UEVENT_IDX].fd = uevent_fd;
        fds[UEVENT_IDX].events = POLLIN;
        fds[UEVENT_IDX].revents = 0;
        
        // wait for an event or a timeout to occur.
        // poll() can also return in response to a SIGUSR1 signal
        timeout = (sRetriesPending ? POLL_TIMEOUT : -1);
        result = poll(fds, 2, timeout);

        // lock the mutex while we are handling events
        pthread_mutex_lock(&sMutex);

        // handle inotify notifications for block device creation and deletion
        if (fds[INOTIFY_IDX].revents == POLLIN)
        {
            struct inotify_event    event;
            char    buffer[512];
            int length = read(inotify_fd, buffer, sizeof(buffer));
            int offset = 0;
 
            while (length >= (int)sizeof(struct inotify_event))
            {
               struct inotify_event* event = (struct inotify_event *)&buffer[offset];
               
               if (event->mask == IN_CREATE)
               {
                   LOG_MOUNT("/dev/block/%s created\n", event->name);
                   HandleMediaInserted(event->name);
               }
               else if (event->mask == IN_DELETE)
               {
                   LOG_MOUNT("/dev/block/%s deleted\n", event->name);
                   HandleMediaRemoved(event->name);
               }
               
               int size = sizeof(struct inotify_event) + event->len;
               length -= size;
               offset += size;
            }
        }

        // handle uevent notifications for USB state changes
        if (fds[UEVENT_IDX].revents == POLLIN)
        {
            char buffer[64*1024];
            int count;
            
            count = recv(uevent_fd, buffer, sizeof(buffer), 0);
            if (count > 0) {
                char* s = buffer;
                char* end = s + count;
                char* type = NULL;
                char* online = NULL;
                char* switchName = NULL;
                char* switchState = NULL;
                                
                while (s < end) {
                    if (!strncmp("POWER_SUPPLY_TYPE=", s, strlen("POWER_SUPPLY_TYPE=")))
                        type = s + strlen("POWER_SUPPLY_TYPE=");
                    else if (!strncmp("POWER_SUPPLY_ONLINE=", s, strlen("POWER_SUPPLY_ONLINE=")))
                        online = s + strlen("POWER_SUPPLY_ONLINE=");                    
                    else if (!strncmp("SWITCH_NAME=", s, strlen("SWITCH_NAME=")))
                        switchName = s + strlen("SWITCH_NAME=");                    
                    else if (!strncmp("SWITCH_STATE=", s, strlen("SWITCH_STATE=")))
                        switchState = s + strlen("SWITCH_STATE=");                    
                    s += (strlen(s) + 1);
                }

                // we use the usb_mass_storage switch state to tell us when USB is online
                if (switchName && switchState && 
                        !strcmp(switchName, "usb_mass_storage") && !strcmp(switchState, "online"))
                {
                    LOG_MOUNT("USB online\n");
                    HandleMassStorageOnline(true);
                }
                
                // and we use the power supply state to tell us when USB is offline
                // we can't rely on the switch for offline detection because we get false positives
                // when USB is reenumerated by the host.
                if (type && online && !strcmp(type, "USB") && !strcmp(online, "0"))
                {
                    LOG_MOUNT("USB offline\n");
                    HandleMassStorageOnline(false);
                }
            }
        }

       // handle retries
       if (sRetriesPending)
            HandleRetries();

        // done handling events, so unlock the mutex
        pthread_mutex_unlock(&sMutex);
    }

    inotify_rm_watch(inotify_fd, id);
    close(inotify_fd);
    close(uevent_fd);

    return NULL;
}

/*****************************************************
 * 
 * THESE FUNCTIONS ARE CALLED FROM THE SERVER THREAD
 * 
 *****************************************************/

// Called to enable or disable USB mass storage support
void EnableMassStorage(boolean enable)
{
    pthread_mutex_lock(&sMutex);

    LOG_MOUNT("EnableMassStorage %s\n", (enable ? "true" : "false"));
    gMassStorageEnabled = enable;
    MassStorageStateChanged();
    pthread_mutex_unlock(&sMutex);
 }

// Called to request that the specified mount point be mounted
void MountMedia(const char* mountPoint)
{
    MountPoint* mp = sMountPointList;
 
    LOG_MOUNT("MountMedia(%s)\n", mountPoint);
   
    pthread_mutex_lock(&sMutex);
    while (mp)
    {
        if (strcmp(mp->mountPoint, mountPoint) == 0)
        {
            if (mp->state == kUnmountingForEject)
            {
                // handle the case where we try to remount before we actually unmounted
                ClearRetries(mp, kMounted);
            }
            
            // don't attempt to mount if mass storage is active
            if (!MassStorageEnabledForMountPoint(mp))
                RequestMount(mp);
        }
        
        mp = mp->next;
    }
    pthread_mutex_unlock(&sMutex);
 }

// Called to request that the specified mount point be unmounted
void UnmountMedia(const char* mountPoint)
{
    MountPoint* mp = sMountPointList;
    
    pthread_mutex_lock(&sMutex);
    while (mp)
    {
        if (strcmp(mp->mountPoint, mountPoint) == 0)
            RequestUnmount(mp, kUnmountingForEject);
        
        mp = mp->next;
    }
    pthread_mutex_unlock(&sMutex);
}

boolean IsMassStorageEnabled()
{
    return gMassStorageEnabled;
}

boolean IsMassStorageConnected()
{
    return gMassStorageConnected;
}

/***********************************************
 * 
 * THESE FUNCTIONS ARE CALLED ONLY AT STARTUP
 * 
 ***********************************************/
 
void *AddMountPoint(const char* device, const char* mountPoint, const char * driverStorePath, boolean enableUms)
{
    MountPoint* newMountPoint;
    
    LOG_MOUNT("AddMountPoint device: %s, mountPoint: %s driverStorePath: %s\n", device, mountPoint, driverStorePath);
    // add a new MountPoint to the head of our linked list
    newMountPoint = (MountPoint *)malloc(sizeof(MountPoint));
    newMountPoint->device = device;
    newMountPoint->mountPoint = mountPoint;
    newMountPoint->driverStorePath = driverStorePath;
    newMountPoint->enableUms = enableUms;
    newMountPoint->umsActive = false;
    newMountPoint->state = kUnmounted;
    newMountPoint->retryCount = 0;

    // add to linked list
    newMountPoint->next = sMountPointList;
    sMountPointList = newMountPoint;
    return newMountPoint;
}

int AddAsecToMountPoint(void *Mp, const char *name, const char *backing_file, const char *size,
                        const char *mount_point, const char *crypt)
{
    MountPoint *mp = (MountPoint *) Mp;
    int i;

    for (i = 0; i < ASEC_STORES_MAX; i++) {
        if (!mp->asecHandles[i])
            break;   
    }

    if (i == ASEC_STORES_MAX) {
        LOG_ERROR("Maximum # of ASEC stores exceeded\n");
        return -EINVAL;
    }

    if (!(mp->asecHandles[i] = AsecInit(name, mp->mountPoint, backing_file, size, mount_point, crypt)))
        return -1;

    return 0;
}
static void MountDevices()
{
    MountPoint* mp = sMountPointList;
    while (mp)
    {
        RequestMount(mp);
        mp = mp->next;
    }
}

void StartAutoMounter()
{
    gExcludedPids[0] = getpid();

    gMassStorageConnected = ReadMassStorageState();
    LOG_MOUNT(gMassStorageConnected ? "USB online\n" : "USB offline\n");

    MountDevices();
    pthread_create(&sAutoMountThread, NULL, AutoMountThread, NULL);
}
