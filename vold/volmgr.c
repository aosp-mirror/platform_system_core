
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sched.h>

#include <sys/mount.h>

#include <cutils/config_utils.h>
#include <cutils/properties.h>

#include "vold.h"
#include "volmgr.h"
#include "blkdev.h"
#include "ums.h"

#include "volmgr_ext3.h"
#include "volmgr_vfat.h"

#define DEBUG_VOLMGR 0

static volume_t        *vol_root = NULL;

static struct volmgr_fstable_entry fs_table[] = {
    { "ext3", ext3_identify, ext3_check, ext3_mount },
    { "vfat", vfat_identify, vfat_check, vfat_mount },
    { NULL, NULL, NULL, NULL }
};

struct _volume_state_event_map {
    volume_state_t state;
    char           *event;
    char           *property_val;
};

static struct _volume_state_event_map volume_state_strings[] = {
    { volstate_unknown,     "volstate_unknown:",  "unknown" },
    { volstate_nomedia,     VOLD_EVT_NOMEDIA,     VOLD_ES_PVAL_NOMEDIA },
    { volstate_unmounted,   VOLD_EVT_UNMOUNTED,   VOLD_ES_PVAL_UNMOUNTED },
    { volstate_checking,    VOLD_EVT_CHECKING,    VOLD_ES_PVAL_CHECKING },
    { volstate_mounted,     VOLD_EVT_MOUNTED,     VOLD_ES_PVAL_MOUNTED },
    { volstate_mounted_ro,  VOLD_EVT_MOUNTED_RO,  VOLD_ES_PVAL_MOUNTED_RO },
    { volstate_badremoval,  VOLD_EVT_BADREMOVAL,  VOLD_ES_PVAL_BADREMOVAL },
    { volstate_damaged,     VOLD_EVT_DAMAGED,     VOLD_ES_PVAL_DAMAGED },
    { volstate_nofs,        VOLD_EVT_NOFS,        VOLD_ES_PVAL_NOFS },
    { volstate_ums,         VOLD_EVT_UMS,         VOLD_ES_PVAL_UMS },
    { 0, NULL, NULL }
};


static int volmgr_readconfig(char *cfg_path);
static int volmgr_config_volume(cnode *node);
static volume_t *volmgr_lookup_volume_by_mediapath(char *media_path, boolean fuzzy);
static volume_t *volmgr_lookup_volume_by_dev(blkdev_t *dev);
static int _volmgr_start(volume_t *vol, blkdev_t *dev);
static int volmgr_start_fs(struct volmgr_fstable_entry *fs, volume_t *vol, blkdev_t *dev);
static void *volmgr_start_fs_thread(void *arg);
static void volmgr_start_fs_thread_sighandler(int signo);
static void volume_setstate(volume_t *vol, volume_state_t state);
static char *conv_volstate_to_eventstr(volume_state_t state);
static char *conv_volstate_to_propstr(volume_state_t state);
static int volume_send_state(volume_t *vol);
static void _cb_volstopped_for_ums_enable(volume_t *v);
static int _volmgr_enable_ums(volume_t *);
static int volmgr_shutdown_volume(volume_t *v, void (* cb) (volume_t *));
static int volmgr_stop_volume(volume_t *v, void (*cb) (volume_t *, void *), void *arg, int emit_statechange);
static void _cb_volume_stopped_for_eject(volume_t *v, void *arg);
static void _cb_volume_stopped_for_shutdown(volume_t *v, void *arg);
static int _volmgr_consider_disk_and_vol(volume_t *vol, blkdev_t *dev);
static void volmgr_uncage_reaper(volume_t *vol);
static void volmgr_reaper_thread_sighandler(int signo);

/*
 * Public functions
 */
int volmgr_bootstrap(void)
{
    int rc;

    if ((rc = volmgr_readconfig("/system/etc/vold.conf")) < 0) {
        LOGE("Unable to process config\n");
        return rc;
    }

    return 0;
}

int volmgr_send_states(void)
{
    volume_t *vol_scan = vol_root;
    int rc;

    while (vol_scan) {
        pthread_mutex_lock(&vol_scan->lock);
        if ((rc = volume_send_state(vol_scan)) < 0) {
            LOGE("Error sending state to framework (%d)\n", rc);
        }
        pthread_mutex_unlock(&vol_scan->lock);
        vol_scan = vol_scan->next;
    }

    return 0;
}

/*
 * Called when a block device is ready to be
 * evaluated by the volume manager.
 */
int volmgr_consider_disk(blkdev_t *dev)
{
    volume_t *vol;

    if (!(vol = volmgr_lookup_volume_by_mediapath(dev->media->devpath, true))) {
        LOG_VOL("volmgr ignoring '%s' - no matching volume found\n", dev->media->devpath);
        return 0;
    }

    pthread_mutex_lock(&vol->lock);
    int rc =  _volmgr_consider_disk_and_vol(vol, dev);
    pthread_mutex_unlock(&vol->lock);
    return rc;
}

int volmgr_start_volume_by_mountpoint(char *mount_point)
{
    volume_t *v = vol_root;

    while(v) {
        if (!strcmp(v->mount_point, mount_point)) {
            pthread_mutex_lock(&v->lock);
            if (!v->dev) {
                LOGE("Cannot start volume '%s' (volume is not bound to a blkdev)\n", mount_point);
                pthread_mutex_unlock(&v->lock);
                return -ENOENT;
            }

            if (_volmgr_consider_disk_and_vol(v, v->dev->disk) < 0) {
                LOGE("volmgr failed to start volume '%s'\n", v->mount_point);
            }
            pthread_mutex_unlock(&v->lock);
            return 0;
        }
        v = v->next;
    }

    return -ENOENT;
}

int volmgr_stop_volume_by_mountpoint(char *mount_point)
{
    volume_t *v = vol_root;

    while(v) {
        if (!strcmp(v->mount_point, mount_point)) {
            pthread_mutex_lock(&v->lock);
            if (volmgr_shutdown_volume(v, _cb_volstopped_for_ums_enable) < 0)
                LOGE("unable to shutdown volume '%s'\n", v->mount_point);
            pthread_mutex_unlock(&v->lock);
            return 0;
        }
        v = v->next;
    }

    return -ENOENT;
}

int volmgr_notify_eject(blkdev_t *dev, void (* cb) (blkdev_t *))
{
#if DEBUG_VOLMGR
    LOG_VOL("volmgr_notify_eject(%s)\n", dev->dev_fspath);
#endif

    volume_t *v;

    // XXX: Partitioning support is going to need us to stop *all*
    // devices in this volume
    if (!(v = volmgr_lookup_volume_by_dev(dev))) {
        if (cb)
            cb(dev);
        return 0;
    }
    
    pthread_mutex_lock(&v->lock);
    if (v->state == volstate_mounted) 
        volume_setstate(v, volstate_badremoval);

    int rc = volmgr_stop_volume(v, _cb_volume_stopped_for_eject, cb, false);

    pthread_mutex_unlock(&v->lock);
    return rc;
}

static void _cb_volume_stopped_for_eject(volume_t *v, void *arg)
{
    void (* eject_cb) (blkdev_t *) = arg;
    LOG_VOL("Volume %s has been stopped for eject\n", v->mount_point);

    eject_cb(v->dev);
    v->dev = NULL; // Clear dev because its being ejected
}

/*
 * Instructs the volume manager to enable or disable USB mass storage
 * on any volumes configured to use it.
 */
int volmgr_enable_ums(boolean enable)
{
    volume_t *v = vol_root;

    while(v) {
        if (v->ums_path) {
            int rc;

            pthread_mutex_lock(&v->lock);
            if (enable) {
                // Stop the volume, and enable UMS in the callback
                if ((rc = volmgr_shutdown_volume(v, _cb_volstopped_for_ums_enable)) < 0)
                    LOGE("unable to shutdown volume '%s'\n", v->mount_point);
            } else {
                // Disable UMS
                if ((rc = ums_disable(v->ums_path)) < 0) {
                    LOGE("unable to disable ums on '%s'\n", v->mount_point);
                    pthread_mutex_unlock(&v->lock);
                    continue;
                }
                volume_setstate(v, volstate_unmounted);

                LOG_VOL("Kick-starting volume '%s' after UMS disable\n", v->dev->disk->dev_fspath);
                // Start volume
                if ((rc = _volmgr_consider_disk_and_vol(v, v->dev->disk)) < 0) {
                    LOGE("volmgr failed to consider disk '%s'\n", v->dev->disk->dev_fspath);
                }
            }
            pthread_mutex_unlock(&v->lock);
        }
        v = v->next;
    }
    return 0;
}

/*
 * Static functions
 */

// vol->lock must be held!
static int _volmgr_consider_disk_and_vol(volume_t *vol, blkdev_t *dev)
{
    int rc = 0;

#if DEBUG_VOLMGR
    LOG_VOL("volmgr_consider_disk_and_vol(%s, %s):\n", vol->mount_point, dev->dev_fspath);
#endif

    if (vol->state != volstate_nomedia && vol->state != volstate_unmounted) {
        LOGE("Volume manager is already handling volume '%s' (currently in state %d)\n", vol->mount_point, vol->state);
        return -EADDRINUSE;
    }

    volume_setstate(vol, volstate_unmounted);

    LOG_VOL("Evaluating dev '%s' for mountable filesystems for '%s'\n", dev->devpath, vol->mount_point);

    if (dev->nr_parts == 0) {
        rc = _volmgr_start(vol, dev);
#if DEBUG_VOLMGR
        LOG_VOL("_volmgr_start(%s, %s) rc = %d\n", vol->mount_point, dev->dev_fspath ,rc);
#endif
    } else {
        /*
         * Device has multiple partitions
         * This is where interesting partition policies could be implemented.
         * For now just try them in sequence until one succeeds
         */
   
        rc = -ENODEV;
        int i;
        for (i = 0; i < dev->nr_parts; i++) {
            blkdev_t *part = blkdev_lookup_by_devno(dev->major, (i+1));
            if (!part) {
                LOGE("Error - unable to lookup partition for blkdev %d:%d\n", dev->major, (i+1));
                continue;
            }
            rc = _volmgr_start(vol, part);
#if DEBUG_VOLMGR
            LOG_VOL("_volmgr_start(%s, %s) rc = %d\n", vol->mount_point, part->dev_fspath, rc);
#endif
            if (!rc) 
                break;
        }

        if (rc == -ENODEV) {
            // Assert to make sure each partition had a backing blkdev
            LOGE("Internal consistency error\n");
            return 0;
        }
    }

    if (rc == -ENODATA) {
        LOGE("Device %s contains no usable filesystems\n", dev->dev_fspath);
        rc = 0;
    }

    return rc;
}

static void volmgr_reaper_thread_sighandler(int signo)
{
    LOGE("volmgr reaper thread got signal %d\n", signo);
}

static void __reaper_cleanup(void *arg)
{
    volume_t *vol = (volume_t *) arg;

    LOG_VOL("__reaper_cleanup(%s):\n", vol->mount_point);

    vol->worker_running = false;

    // Wake up anyone that was waiting on this thread
    pthread_mutex_unlock(&vol->worker_sem);

    // Unlock the volume
    pthread_mutex_unlock(&vol->lock);
}

static void *volmgr_reaper_thread(void *arg)
{
    volume_t *vol = (volume_t *) arg;

    pthread_cleanup_push(__reaper_cleanup, arg);
    pthread_mutex_lock(&vol->lock);

    vol->worker_running = true;
    vol->worker_pid = getpid();

    struct sigaction actions;

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = volmgr_reaper_thread_sighandler;
    sigaction(SIGUSR1, &actions, NULL);

    LOG_VOL("Worker thread pid %d reaping %s\n", getpid(), vol->mount_point);

    boolean send_sig_kill = false;
    int i, rc;

    for (i = 0; i < 10; i++) {
        rc = umount(vol->mount_point);
        LOG_VOL("volmngr reaper umount(%s) attempt %d rc = %d\n",
                vol->mount_point, i + 1, rc);
        if (!rc)
            break;
        if (rc && (errno == EINVAL || errno == ENOENT)) {
            rc = 0;
            break;
        }
        KillProcessesWithOpenFiles(vol->mount_point, send_sig_kill, NULL, 0);
        sleep(1);
        if (!send_sig_kill)
            send_sig_kill = true;
    }

    if (!rc) {
        LOG_VOL("Reaper sucessfully unmounted %s\n", vol->mount_point);
        volume_setstate(vol, volstate_unmounted);
    } else {
        LOGE("Unable to unmount!! (%d)\n", rc);
    }

 out:
    pthread_cleanup_pop(1);
    pthread_exit(NULL);
    return NULL;
}

static void volmgr_uncage_reaper(volume_t *vol)
{
    if (vol->worker_running) {
        LOGE("Worker thread is currently running.. waiting..\n");
        pthread_mutex_lock(&vol->worker_sem);
        LOG_VOL("Worker thread now available\n");
    }

    vol->worker_args.fs = NULL;
    vol->worker_args.dev = NULL;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&vol->worker_thread, &attr, volmgr_reaper_thread, vol);
}

static int volmgr_stop_volume(volume_t *v, void (*cb) (volume_t *, void *), void *arg, boolean emit_statechange)
{
    int i, rc;

    if (v->state == volstate_mounted || v->state == volstate_badremoval) {
        // Try to unmount right away (5 retries)
        for (i = 0; i < 5; i++) {
            rc = umount(v->mount_point);
            LOG_VOL("volmngr quick stop umount(%s) attempt %d rc = %d\n",
                    v->mount_point, i + 1, rc);
            if (!rc)
                break;
            if (rc && (errno == EINVAL || errno == ENOENT)) {
                rc = 0;
                break;
            }
            sched_yield();
        }

        if (!rc) {
            LOG_VOL("volmgr_stop_volume(%s): Volume unmounted sucessfully\n",
                    v->mount_point);
            if (emit_statechange)
                volume_setstate(v, volstate_unmounted);
            goto out_cb_immed;
        }

        /*
         * Since the volume is still in use, dispatch the stopping to
         * a thread
         */
        LOG_VOL("Volume %s is busy (%d) - uncaging the reaper\n", v->mount_point, rc);
        volmgr_uncage_reaper(v);
        return -EINPROGRESS;
    } else if (v->state == volstate_checking) {
        volume_setstate(v, volstate_unmounted);
        if (v->worker_running) {
            LOG_VOL("Cancelling worker thread\n");
            pthread_kill(v->worker_thread, SIGUSR1);
        } else
            LOGE("Strange... we were in checking state but worker thread wasn't running..\n");
        goto out_cb_immed;
    }

    LOGE("volmgr: nothing to do to stop vol '%s' (in state %d)\n",
             v->mount_point, v->state);
 out_cb_immed:
    if (cb)
        cb(v, arg);
    return 0;
}


/*
 * Gracefully stop a volume
 */
static int volmgr_shutdown_volume(volume_t *v, void (* cb) (volume_t *))
{
    return volmgr_stop_volume(v, NULL, cb, true);
}

static void _cb_volume_stopped_for_shutdown(volume_t *v, void *arg)
{
    void (* shutdown_cb) (volume_t *) = arg;

    LOG_VOL("Volume %s has been stopped for shutdown\n", v->mount_point);
    shutdown_cb(v);
}

/*
 * Called when a volume is sucessfully unmounted for UMS enable
 */
static void _cb_volstopped_for_ums_enable(volume_t *v)
{
    int rc;

    if ((rc = ums_enable(v->dev->dev_fspath, v->ums_path)) < 0) {
        LOGE("Error enabling ums (%d)\n", rc);
        return;
    }
    volume_setstate(v, volstate_ums);
}

static int volmgr_readconfig(char *cfg_path)
{
    cnode *root = config_node("", "");
    cnode *node;

    config_load_file(root, cfg_path);
    node = root->first_child;

    while (node) {
        if (!strcmp(node->name, "volume"))
            volmgr_config_volume(node);
        else
            LOGE("Skipping unknown configuration node '%s'\n", node->name);
        node = node->next;
    }
    return 0;
}

static int volmgr_config_volume(cnode *node)
{
    volume_t *new;
    int rc = 0;

    if (!(new = malloc(sizeof(volume_t))))
        return -ENOMEM;
    memset(new, 0, sizeof(volume_t));

    new->state = volstate_nomedia;
    pthread_mutex_init(&new->lock, NULL);
    pthread_mutex_init(&new->worker_sem, NULL);

    cnode *child = node->first_child;

    while (child) {
        if (!strcmp(child->name, "media_path"))
            new->media_path = strdup(child->value);
        else if (!strcmp(child->name, "media_type")) {
            if (!strcmp(child->value, "mmc"))
                new->media_type = media_mmc;
            else {
                LOGE("Invalid media type '%s'\n", child->value);
                rc = -EINVAL;
                goto out_free;
            }
        } else if (!strcmp(child->name, "mount_point"))
            new->mount_point = strdup(child->value);
        else if (!strcmp(child->name, "ums_path"))
            new->ums_path = strdup(child->value);
        else
            LOGE("Ignoring unknown config entry '%s'\n", child->name);
        child = child->next;
    }

    if (!new->media_path || !new->mount_point || new->media_type == media_unknown) {
        LOGE("Required configuration parameter missing for volume\n");
        rc = -EINVAL;
        goto out_free;
    }

    if (!vol_root)
        vol_root = new;
    else {
        volume_t *scan = vol_root;
        while (scan->next)
            scan = scan->next;
        scan->next = new;
    }

    return rc;

 out_free:
    if (new->media_path)
        free(new->media_path);
    if (new->mount_point)
        free(new->mount_point);
    if (new->ums_path)
        free(new->ums_path);
    return rc;
}

static volume_t *volmgr_lookup_volume_by_dev(blkdev_t *dev)
{
    volume_t *scan = vol_root;
    while(scan) {
        if (scan->dev == dev)
            return scan;
        scan = scan->next;
    }
    return NULL;
}

static volume_t *volmgr_lookup_volume_by_mediapath(char *media_path, boolean fuzzy)
{
    volume_t *scan = vol_root;
    volume_t *res = NULL;

    while (scan) {
        if (fuzzy) {
            if (!strncmp(media_path, scan->media_path, strlen(scan->media_path))) {
                if (!res)
                    res = scan;
                else {
                    LOGE("Warning - multiple matching volumes for media '%s' - using first\n", media_path);
                    break;
                }
            }
        } else if (!strcmp(media_path, scan->media_path))
            return scan;

        scan = scan->next;
    }
    return res;
}

/*
 * Attempt to bring a volume online
 * Returns: 0 on success, errno on failure, with the following exceptions:
 *     - ENODATA - Unsupported filesystem type / blank
 * vol->lock MUST be held!
 */
static int _volmgr_start(volume_t *vol, blkdev_t *dev)
{
    struct volmgr_fstable_entry *fs;
    int rc = ENODATA;

#if DEBUG_VOLMGR
    LOG_VOL("_volmgr_start(%s, %s):\n", vol->mount_point, dev->dev_fspath);
#endif

    for (fs = fs_table; fs->name; fs++) {
        if (!fs->identify_fn(dev))
            break;
    }

    if (!fs) {
        LOGE("No supported filesystems on %s\n", dev->dev_fspath);
        volume_setstate(vol, volstate_nofs);
        return -ENODATA;
    }

    return volmgr_start_fs(fs, vol, dev);
}

// vol->lock MUST be held!
static int volmgr_start_fs(struct volmgr_fstable_entry *fs, volume_t *vol, blkdev_t *dev)
{
    /*
     * Spawn a thread to do the actual checking / mounting in
     */

    if (vol->worker_running) {
        LOGE("Worker thread is currently running.. waiting..\n");
        pthread_mutex_lock(&vol->worker_sem);
        LOG_VOL("Worker thread now available\n");
    }

    vol->dev = dev; 

    vol->worker_args.fs = fs;
    vol->worker_args.dev = dev;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&vol->worker_thread, &attr, volmgr_start_fs_thread, vol);

    return 0;
}

static void __start_fs_thread_lock_cleanup(void *arg)
{
    volume_t *vol = (volume_t *) arg;

    LOG_VOL("__start_fs_thread_lock_cleanup(%s):\n", vol->mount_point);

    vol->worker_running = false;

    // Wake up anyone that was waiting on this thread
    pthread_mutex_unlock(&vol->worker_sem);

    // Unlock the volume
    pthread_mutex_unlock(&vol->lock);
}

static void *volmgr_start_fs_thread(void *arg)
{
    volume_t *vol = (volume_t *) arg;

    pthread_cleanup_push(__start_fs_thread_lock_cleanup, arg);
    pthread_mutex_lock(&vol->lock);

    vol->worker_running = true;
    vol->worker_pid = getpid();

    struct sigaction actions;

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = volmgr_start_fs_thread_sighandler;
    sigaction(SIGUSR1, &actions, NULL);

    struct volmgr_fstable_entry *fs = vol->worker_args.fs;
    blkdev_t                    *dev = vol->worker_args.dev;
    int                          rc;
  
    LOG_VOL("Worker thread pid %d starting %s fs %s on %s\n", getpid(), fs->name, dev->dev_fspath, vol->mount_point);

    if (fs->check_fn) {
        LOG_VOL("Starting %s filesystem check on %s\n", fs->name, dev->dev_fspath);
        volume_setstate(vol, volstate_checking);
        pthread_mutex_unlock(&vol->lock);
        rc = fs->check_fn(dev);
        pthread_mutex_lock(&vol->lock);
        if (vol->state != volstate_checking) {
            LOG_VOL("filesystem check aborted\n");
            goto out;
        }
        
        if (rc < 0) {
            LOG_VOL("%s filesystem check failed on %s\n", fs->name, dev->dev_fspath);
            goto out_unmountable;
        }
        LOG_VOL("%s filesystem check of %s OK\n", fs->name, dev->dev_fspath);
    }

    rc = fs->mount_fn(dev, vol);
    if (!rc) {
        LOG_VOL("Sucessfully mounted %s filesystem %s on %s\n", fs->name, dev->devpath, vol->mount_point);
        volume_setstate(vol, volstate_mounted);
        goto out;
    }

    LOGE("%s filesystem mount of %s failed (%d)\n", fs->name, dev->devpath, rc);

 out_unmountable:
    volume_setstate(vol, volstate_damaged);
 out:
    pthread_cleanup_pop(1);
    pthread_exit(NULL);
    return NULL;
}

static void volmgr_start_fs_thread_sighandler(int signo)
{
    LOGE("volmgr thread got signal %d\n", signo);
}

static void volume_setstate(volume_t *vol, volume_state_t state)
{
    LOG_VOL("Volume %s state change from %d -> %d\n", vol->mount_point, vol->state, state);
    
    vol->state = state;
    
    char *prop_val = conv_volstate_to_propstr(vol->state);

    property_set(PROP_EXTERNAL_STORAGE_STATE, prop_val);
    volume_send_state(vol);
}

static int volume_send_state(volume_t *vol)
{
    char *event = conv_volstate_to_eventstr(vol->state);

    return send_msg_with_data(event, vol->mount_point);
}

static char *conv_volstate_to_eventstr(volume_state_t state)
{
    int i;

    for (i = 0; volume_state_strings[i].event != NULL; i++) {
        if (volume_state_strings[i].state == state)
            break;
    }

    if (!volume_state_strings[i].event)
        LOGE("conv_volstate_to_eventstr(%d): Invalid state\n", state);
    return volume_state_strings[i].event;
}

static char *conv_volstate_to_propstr(volume_state_t state)
{
    int i;

    for (i = 0; volume_state_strings[i].event != NULL; i++) {
        if (volume_state_strings[i].state == state)
            break;
    }

    if (!volume_state_strings[i].event)
        LOGE("conv_volstate_to_propval(%d): Invalid state\n", state);
    return volume_state_strings[i].property_val;
}

