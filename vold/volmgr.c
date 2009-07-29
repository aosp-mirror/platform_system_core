
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
#include "format.h"
#include "devmapper.h"

#include "volmgr_ext3.h"
#include "volmgr_vfat.h"

#define DEBUG_VOLMGR 0

static volume_t *vol_root = NULL;
static boolean safe_mode = true;

static struct volmgr_fstable_entry fs_table[] = {
//    { "ext3", ext_identify, ext_check, ext_mount , true },
    { "vfat", vfat_identify, vfat_check, vfat_mount , false },
    { NULL, NULL, NULL, NULL , false}
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
static void _cb_volstopped_for_ums_enable(volume_t *v, void *arg);
static int _volmgr_enable_ums(volume_t *);
static int volmgr_shutdown_volume(volume_t *v, void (* cb) (volume_t *, void *arg), boolean emit_statechange);
static int volmgr_stop_volume(volume_t *v, void (*cb) (volume_t *, void *), void *arg, boolean emit_statechange);
static void _cb_volume_stopped_for_eject(volume_t *v, void *arg);
static void _cb_volume_stopped_for_shutdown(volume_t *v, void *arg);
static int _volmgr_consider_disk_and_vol(volume_t *vol, blkdev_t *dev);
static void volmgr_uncage_reaper(volume_t *vol, void (* cb) (volume_t *, void *arg), void *arg);
static void volmgr_reaper_thread_sighandler(int signo);
static void volmgr_add_mediapath_to_volume(volume_t *v, char *media_path);
static int volmgr_send_eject_request(volume_t *v);
static volume_t *volmgr_lookup_volume_by_mountpoint(char *mount_point, boolean leave_locked);

static boolean _mountpoint_mounted(char *mp)
{
    char device[256];
    char mount_path[256];
    char rest[256];
    FILE *fp;
    char line[1024];

    if (!(fp = fopen("/proc/mounts", "r"))) {
        LOGE("Error opening /proc/mounts (%s)", strerror(errno));
        return false;
    }

    while(fgets(line, sizeof(line), fp)) {
        line[strlen(line)-1] = '\0';
        sscanf(line, "%255s %255s %255s\n", device, mount_path, rest);
        if (!strcmp(mount_path, mp)) {
            fclose(fp);
            return true;
        }
        
    }

    fclose(fp);
    return false;
}

/*
 * Public functions
 */

int volmgr_set_volume_key(char *mount_point, unsigned char *key)
{
    volume_t *v = volmgr_lookup_volume_by_mountpoint(mount_point, true);
 
    if (!v)
        return -ENOENT;

    if (v->media_type != media_devmapper) {
        LOGE("Cannot set key on a non devmapper volume");
        pthread_mutex_unlock(&v->lock);
        return -EINVAL;
    }

    memcpy(v->dm->key, key, sizeof(v->dm->key));
    pthread_mutex_unlock(&v->lock);
    return 0;
}

int volmgr_format_volume(char *mount_point)
{
    int rc;
    volume_t *v;

    LOG_VOL("volmgr_format_volume(%s):", mount_point);

    v = volmgr_lookup_volume_by_mountpoint(mount_point, true);

    if (!v)
        return -ENOENT;

    if (v->state == volstate_mounted ||
        v->state == volstate_mounted_ro ||
        v->state == volstate_ums ||
        v->state == volstate_checking) {
            LOGE("Can't format '%s', currently in state %d", mount_point, v->state);
            pthread_mutex_unlock(&v->lock);
            return -EBUSY;
        } else if (v->state == volstate_nomedia &&
                   v->media_type != media_devmapper) {
            LOGE("Can't format '%s', (no media)", mount_point);
            pthread_mutex_unlock(&v->lock);
            return -ENOMEDIUM;
        }

    // XXX:Reject if the underlying source media is not present

    if (v->media_type == media_devmapper) {
        if ((rc = devmapper_genesis(v->dm)) < 0) {
            LOGE("devmapper genesis failed for %s (%d)", mount_point, rc);
            pthread_mutex_unlock(&v->lock);
            return rc;
        }
    } else {
        if ((rc = initialize_mbr(v->dev->disk)) < 0) {
            LOGE("MBR init failed for %s (%d)", mount_point, rc);
            pthread_mutex_unlock(&v->lock);
            return rc;
        }
    }

    volume_setstate(v, volstate_formatting);
    pthread_mutex_unlock(&v->lock);
    return rc;
}

int volmgr_bootstrap(void)
{
    int rc;

    if ((rc = volmgr_readconfig("/system/etc/vold.conf")) < 0) {
        LOGE("Unable to process config");
        return rc;
    }

    /*
     * Check to see if any of our volumes is mounted
     */
    volume_t *v = vol_root;
    while (v) {
        if (_mountpoint_mounted(v->mount_point)) {
            LOGW("Volume '%s' already mounted at startup", v->mount_point);
            v->state = volstate_mounted;
        }
        v = v->next;
    }

    return 0;
}

int volmgr_safe_mode(boolean enable)
{
    if (enable == safe_mode)
        return 0;

    safe_mode = enable;

    volume_t *v = vol_root;
    int rc;

    while (v) {
        pthread_mutex_lock(&v->lock);
        if (v->state == volstate_mounted && v->fs) {
            rc = v->fs->mount_fn(v->dev, v, safe_mode);
            if (!rc) {
                LOGI("Safe mode %s on %s", (enable ? "enabled" : "disabled"), v->mount_point);
            } else {
                LOGE("Failed to %s safe-mode on %s (%s)",
                     (enable ? "enable" : "disable" ), v->mount_point, strerror(-rc));
            }
        }

        pthread_mutex_unlock(&v->lock);
        v = v->next;
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
            LOGE("Error sending state to framework (%d)", rc);
        }
        pthread_mutex_unlock(&vol_scan->lock);
        vol_scan = vol_scan->next;
        break; // XXX:
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

    if (!(vol = volmgr_lookup_volume_by_mediapath(dev->media->devpath, true)))
        return 0;

    pthread_mutex_lock(&vol->lock);

    if (vol->state == volstate_mounted) {
        LOGE("Volume %s already mounted (did we just crash?)", vol->mount_point);
        pthread_mutex_unlock(&vol->lock);
        return 0;
    }

    int rc =  _volmgr_consider_disk_and_vol(vol, dev);
    pthread_mutex_unlock(&vol->lock);
    return rc;
}

int volmgr_start_volume_by_mountpoint(char *mount_point)
{ 
    volume_t *v;

    v = volmgr_lookup_volume_by_mountpoint(mount_point, true);
    if (!v)
        return -ENOENT;

    if (v->media_type == media_devmapper) {
        if (devmapper_start(v->dm) < 0)  {
            LOGE("volmgr failed to start devmapper volume '%s'",
                 v->mount_point);
        }
    } else if (v->media_type == media_mmc) {
        if (!v->dev) {
            LOGE("Cannot start volume '%s' (volume is not bound)", mount_point);
            pthread_mutex_unlock(&v->lock);
            return -ENOENT;
        }

        if (_volmgr_consider_disk_and_vol(v, v->dev->disk) < 0) {
            LOGE("volmgr failed to start volume '%s'", v->mount_point);
        }
    }

    pthread_mutex_unlock(&v->lock);
    return 0;
}

static void _cb_volstopped_for_devmapper_teardown(volume_t *v, void *arg)
{
    devmapper_stop(v->dm);
    volume_setstate(v, volstate_nomedia);
    pthread_mutex_unlock(&v->lock);
}

int volmgr_stop_volume_by_mountpoint(char *mount_point)
{
    int rc;
    volume_t *v;

    v = volmgr_lookup_volume_by_mountpoint(mount_point, true);
    if (!v)
        return -ENOENT;

    if (v->state == volstate_mounted)
        volmgr_send_eject_request(v);

    if (v->media_type == media_devmapper)
        rc = volmgr_shutdown_volume(v, _cb_volstopped_for_devmapper_teardown, false);
    else
        rc = volmgr_shutdown_volume(v, NULL, true);

    /*
     * If shutdown returns -EINPROGRESS,
     * do *not* release the lock as
     * it is now owned by the reaper thread
     */
    if (rc != -EINPROGRESS) {
        if (rc)
            LOGE("unable to shutdown volume '%s'", v->mount_point);
        pthread_mutex_unlock(&v->lock);
    }
    return 0;
}

int volmgr_notify_eject(blkdev_t *dev, void (* cb) (blkdev_t *))
{
    LOG_VOL("Volmgr notified of %d:%d eject", dev->major, dev->minor);

    volume_t *v;
    int rc;

    // XXX: Partitioning support is going to need us to stop *all*
    // devices in this volume
    if (!(v = volmgr_lookup_volume_by_dev(dev))) {
        if (cb)
            cb(dev);
        return 0;
    }
    
    pthread_mutex_lock(&v->lock);

    volume_state_t old_state = v->state;

    if (v->state == volstate_mounted ||
        v->state == volstate_ums ||
        v->state == volstate_checking) {

        volume_setstate(v, volstate_badremoval);

        /*
         * Stop any devmapper volumes which
         * are using us as a source
         * XXX: We may need to enforce stricter
         * order here
         */
        volume_t *dmvol = vol_root;
        while (dmvol) {
            if ((dmvol->media_type == media_devmapper) &&
                (dmvol->dm->src_type == dmsrc_loopback) &&
                (!strncmp(dmvol->dm->type_data.loop.loop_src, 
                          v->mount_point, strlen(v->mount_point)))) {

                pthread_mutex_lock(&dmvol->lock);
                if (dmvol->state != volstate_nomedia) {
                    rc = volmgr_shutdown_volume(dmvol, _cb_volstopped_for_devmapper_teardown, false);
                    if (rc != -EINPROGRESS) {
                        if (rc)
                            LOGE("unable to shutdown volume '%s'", v->mount_point);
                        pthread_mutex_unlock(&dmvol->lock);
                    }
                } else 
                    pthread_mutex_unlock(&dmvol->lock);
            }
            dmvol = dmvol->next;
        }

    } else if (v->state == volstate_formatting) {
        /*
         * The device is being ejected due to
         * kernel disk revalidation.
         */
        LOG_VOL("Volmgr ignoring eject of %d:%d (volume formatting)",
                dev->major, dev->minor);
        if (cb)
            cb(dev);
        pthread_mutex_unlock(&v->lock);
        return 0;
    } else
        volume_setstate(v, volstate_nomedia);
    
    if (old_state == volstate_ums) {
        ums_disable(v->ums_path);
        pthread_mutex_unlock(&v->lock);
    } else {
        int rc = volmgr_stop_volume(v, _cb_volume_stopped_for_eject, cb, false);
        if (rc != -EINPROGRESS) {
            if (rc)
                LOGE("unable to shutdown volume '%s'", v->mount_point);
            pthread_mutex_unlock(&v->lock);
        }
    }
    return 0; 
}

static void _cb_volume_stopped_for_eject(volume_t *v, void *arg)
{
    void (* eject_cb) (blkdev_t *) = arg;

#if DEBUG_VOLMGR
    LOG_VOL("Volume %s has been stopped for eject", v->mount_point);
#endif

    if (eject_cb)
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

            if (enable) {
                pthread_mutex_lock(&v->lock);
                if (v->state == volstate_mounted)
                    volmgr_send_eject_request(v);
                else if (v->state == volstate_ums) {
                    pthread_mutex_unlock(&v->lock);
                    goto next_vol;
                }

                // Stop the volume, and enable UMS in the callback
                rc = volmgr_shutdown_volume(v, _cb_volstopped_for_ums_enable, false);
                if (rc != -EINPROGRESS) {
                    if (rc)
                        LOGE("unable to shutdown volume '%s'", v->mount_point);
                    pthread_mutex_unlock(&v->lock);
                }
            } else {
                // Disable UMS
                pthread_mutex_lock(&v->lock);
                if (v->state != volstate_ums) {
                    pthread_mutex_unlock(&v->lock);
                    goto next_vol;
                }

                if ((rc = ums_disable(v->ums_path)) < 0) {
                    LOGE("unable to disable ums on '%s'", v->mount_point);
                    pthread_mutex_unlock(&v->lock);
                    continue;
                }

                LOG_VOL("Kick-starting volume %d:%d after UMS disable",
                        v->dev->disk->major, v->dev->disk->minor);
                // Start volume
                if ((rc = _volmgr_consider_disk_and_vol(v, v->dev->disk)) < 0) {
                    LOGE("volmgr failed to consider disk %d:%d",
                         v->dev->disk->major, v->dev->disk->minor);
                }
                pthread_mutex_unlock(&v->lock);
            }
        }
 next_vol:
        v = v->next;
    }
    return 0;
}

/*
 * Static functions
 */

static int volmgr_send_eject_request(volume_t *v)
{
    return send_msg_with_data(VOLD_EVT_EJECTING, v->mount_point);
}

// vol->lock must be held!
static int _volmgr_consider_disk_and_vol(volume_t *vol, blkdev_t *dev)
{
    int rc = 0;

#if DEBUG_VOLMGR
    LOG_VOL("volmgr_consider_disk_and_vol(%s, %d:%d):", vol->mount_point,
            dev->major, dev->minor); 
#endif

    if (vol->state == volstate_unknown ||
        vol->state == volstate_mounted ||
        vol->state == volstate_mounted_ro) {
        LOGE("Cannot consider volume '%s' because it is in state '%d", 
             vol->mount_point, vol->state);
        return -EADDRINUSE;
    }

    if (vol->state == volstate_formatting) {
        LOG_VOL("Evaluating dev '%s' for formattable filesystems for '%s'",
                dev->devpath, vol->mount_point);
        /*
         * Since we only support creating 1 partition (right now),
         * we can just lookup the target by devno
         */
        blkdev_t *part = blkdev_lookup_by_devno(dev->major, 1);
        if (!part) {
            part = blkdev_lookup_by_devno(dev->major, 0);
            if (!part) {
                LOGE("Unable to find device to format");
                return -ENODEV;
            }
        }

        if ((rc = format_partition(part,
                                   vol->media_type == media_devmapper ?
                                   FORMAT_TYPE_EXT2 : FORMAT_TYPE_FAT32)) < 0) {
            LOGE("format failed (%d)", rc);
            return rc;
        }
        
    }

    LOGI("Evaluating dev '%s' for mountable filesystems for '%s'",
            dev->devpath, vol->mount_point);

    if (dev->nr_parts == 0) {
        rc = _volmgr_start(vol, dev);
#if DEBUG_VOLMGR
        LOG_VOL("_volmgr_start(%s, %d:%d) rc = %d", vol->mount_point,
                dev->major, dev->minor, rc);
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
                LOGE("Error - unable to lookup partition for blkdev %d:%d", dev->major, (i+1));
                continue;
            }
            rc = _volmgr_start(vol, part);
#if DEBUG_VOLMGR
            LOG_VOL("_volmgr_start(%s, %d:%d) rc = %d",
                    vol->mount_point, part->major, part->minor, rc);
#endif
            if (!rc || rc == -EBUSY) 
                break;
        }

        if (rc == -ENODEV) {
            // Assert to make sure each partition had a backing blkdev
            LOGE("Internal consistency error");
            return 0;
        }
    }

    if (rc == -ENODATA) {
        LOGE("Device %d:%d contains no usable filesystems",
             dev->major, dev->minor);
        rc = 0;
    }

    return rc;
}

static void volmgr_reaper_thread_sighandler(int signo)
{
    LOGE("Volume reaper thread got signal %d", signo);
}

static void __reaper_cleanup(void *arg)
{
    volume_t *vol = (volume_t *) arg;

    if (vol->worker_args.reaper_args.cb)
        vol->worker_args.reaper_args.cb(vol, vol->worker_args.reaper_args.cb_arg);

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

    vol->worker_running = true;
    vol->worker_pid = getpid();

    struct sigaction actions;

    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = volmgr_reaper_thread_sighandler;
    sigaction(SIGUSR1, &actions, NULL);

    LOGW("Reaper here - working on %s", vol->mount_point);

    boolean send_sig_kill = false;
    int i, rc;

    for (i = 0; i < 10; i++) {
        errno = 0;
        rc = umount(vol->mount_point);
        LOGW("volmngr reaper umount(%s) attempt %d (%s)",
                vol->mount_point, i + 1, strerror(errno));
        if (!rc)
            break;
        if (rc && (errno == EINVAL || errno == ENOENT)) {
            rc = 0;
            break;
        }
        sleep(1);
        if (i >= 4) {
            KillProcessesWithOpenFiles(vol->mount_point, send_sig_kill, NULL, 0);
            if (!send_sig_kill)
                send_sig_kill = true;
        }
    }

    if (!rc) {
        LOGI("Reaper sucessfully unmounted %s", vol->mount_point);
        vol->fs = NULL;
        volume_setstate(vol, volstate_unmounted);
    } else {
        LOGE("Unable to unmount!! (%d)", rc);
    }

 out:
    pthread_cleanup_pop(1);
    pthread_exit(NULL);
    return NULL;
}

// vol->lock must be held!
static void volmgr_uncage_reaper(volume_t *vol, void (* cb) (volume_t *, void *arg), void *arg)
{

    if (vol->worker_running) {
        LOGE("Worker thread is currently running.. waiting..");
        pthread_mutex_lock(&vol->worker_sem);
        LOGI("Worker thread now available");
    }

    vol->worker_args.reaper_args.cb = cb;
    vol->worker_args.reaper_args.cb_arg = arg;

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
            if (!rc)
                break;

            if (rc && (errno == EINVAL || errno == ENOENT)) {
                rc = 0;
                break;
            }

            LOGI("volmngr quick stop umount(%s) attempt %d (%s)",
                    v->mount_point, i + 1, strerror(errno));

            if (i == 0)
                usleep(1000 * 250); // First failure, sleep for 250 ms 
            else
                sched_yield();
        }

        if (!rc) {
            LOGI("volmgr_stop_volume(%s): Volume unmounted sucessfully",
                    v->mount_point);
            if (emit_statechange)
                volume_setstate(v, volstate_unmounted);
            v->fs = NULL;
            goto out_cb_immed;
        }

        /*
         * Since the volume is still in use, dispatch the stopping to
         * a thread
         */
        LOGW("Volume %s is busy (%d) - uncaging the reaper", v->mount_point, rc);
        volmgr_uncage_reaper(v, cb, arg);
        return -EINPROGRESS;
    } else if (v->state == volstate_checking) {
        volume_setstate(v, volstate_unmounted);
        if (v->worker_running) {
            LOG_VOL("Cancelling worker thread");
            pthread_kill(v->worker_thread, SIGUSR1);
        } else
            LOGE("Strange... we were in checking state but worker thread wasn't running..");
        goto out_cb_immed;
    }

 out_cb_immed:
    if (cb)
        cb(v, arg);
    return 0;
}


/*
 * Gracefully stop a volume
 * v->lock must be held!
 * if we return -EINPROGRESS, do NOT release the lock as the reaper
 * is using the volume
 */
static int volmgr_shutdown_volume(volume_t *v, void (* cb) (volume_t *, void *), boolean emit_statechange)
{
    return volmgr_stop_volume(v, cb, NULL, emit_statechange);
}

static void _cb_volume_stopped_for_shutdown(volume_t *v, void *arg)
{
    void (* shutdown_cb) (volume_t *) = arg;

#if DEBUG_VOLMGR
    LOG_VOL("Volume %s has been stopped for shutdown", v->mount_point);
#endif
    shutdown_cb(v);
}


/*
 * Called when a volume is sucessfully unmounted for UMS enable
 */
static void _cb_volstopped_for_ums_enable(volume_t *v, void *arg)
{
    int rc;
    char *devdir_path;

#if DEBUG_VOLMGR
    LOG_VOL("_cb_volstopped_for_ums_enable(%s):", v->mount_point);
#endif
    devdir_path = blkdev_get_devpath(v->dev->disk);

    if ((rc = ums_enable(devdir_path, v->ums_path)) < 0) {
        free(devdir_path);
        LOGE("Error enabling ums (%d)", rc);
        return;
    }
    free(devdir_path);
    volume_setstate(v, volstate_ums);
    pthread_mutex_unlock(&v->lock);
}

static int volmgr_readconfig(char *cfg_path)
{
    cnode *root = config_node("", "");
    cnode *node;

    config_load_file(root, cfg_path);
    node = root->first_child;

    while (node) {
        if (!strncmp(node->name, "volume_", 7))
            volmgr_config_volume(node);
        else
            LOGE("Skipping unknown configuration node '%s'", node->name);
        node = node->next;
    }
    return 0;
}

static void volmgr_add_mediapath_to_volume(volume_t *v, char *media_path)
{
    int i;

#if DEBUG_VOLMGR
    LOG_VOL("volmgr_add_mediapath_to_volume(%p, %s):", v, media_path);
#endif
    for (i = 0; i < VOLMGR_MAX_MEDIAPATHS_PER_VOLUME; i++) {
        if (!v->media_paths[i]) {
            v->media_paths[i] = strdup(media_path);
            return;
        }
    }
    LOGE("Unable to add media path '%s' to volume (out of media slots)", media_path);
}

static int volmgr_config_volume(cnode *node)
{
    volume_t *new;
    int rc = 0, i;

    char *dm_src, *dm_src_type, *dm_tgt, *dm_param, *dm_tgtfs;
    uint32_t dm_size_mb = 0;

    dm_src = dm_src_type = dm_tgt = dm_param = dm_tgtfs = NULL;
#if DEBUG_VOLMGR
    LOG_VOL("volmgr_configure_volume(%s):", node->name);
#endif
    if (!(new = malloc(sizeof(volume_t))))
        return -ENOMEM;
    memset(new, 0, sizeof(volume_t));

    new->state = volstate_nomedia;
    pthread_mutex_init(&new->lock, NULL);
    pthread_mutex_init(&new->worker_sem, NULL);

    cnode *child = node->first_child;

    while (child) {
        if (!strcmp(child->name, "media_path"))
            volmgr_add_mediapath_to_volume(new, child->value);
        else if (!strcmp(child->name, "emu_media_path"))
            volmgr_add_mediapath_to_volume(new, child->value);
        else if (!strcmp(child->name, "media_type")) {
            if (!strcmp(child->value, "mmc"))
                new->media_type = media_mmc;
            else if (!strcmp(child->value, "devmapper"))
                new->media_type = media_devmapper;
            else {
                LOGE("Invalid media type '%s'", child->value);
                rc = -EINVAL;
                goto out_free;
            }
        } else if (!strcmp(child->name, "mount_point"))
            new->mount_point = strdup(child->value);
        else if (!strcmp(child->name, "ums_path"))
            new->ums_path = strdup(child->value);
        else if (!strcmp(child->name, "dm_src")) 
            dm_src = strdup(child->value);
        else if (!strcmp(child->name, "dm_src_type")) 
            dm_src_type = strdup(child->value);
        else if (!strcmp(child->name, "dm_src_size_mb")) 
            dm_size_mb = atoi(child->value);
        else if (!strcmp(child->name, "dm_target")) 
            dm_tgt = strdup(child->value);
        else if (!strcmp(child->name, "dm_target_params")) 
            dm_param = strdup(child->value);
        else if (!strcmp(child->name, "dm_target_fs")) 
            dm_tgtfs = strdup(child->value);
        else
            LOGE("Ignoring unknown config entry '%s'", child->name);
        child = child->next;
    }

    if (new->media_type == media_mmc) {
        if (!new->media_paths[0] || !new->mount_point || new->media_type == media_unknown) {
            LOGE("Required configuration parameter missing for mmc volume");
            rc = -EINVAL;
            goto out_free;
        }
    } else if (new->media_type == media_devmapper) {
        if (!dm_src || !dm_src_type || !dm_tgt ||
            !dm_param || !dm_tgtfs || !dm_size_mb) {
            LOGE("Required configuration parameter missing for devmapper volume");
            rc = -EINVAL;
            goto out_free;
        }

        char dm_mediapath[255];
        if (!(new->dm = devmapper_init(dm_src, dm_src_type, dm_size_mb,
                                       dm_tgt, dm_param, dm_tgtfs, dm_mediapath))) {
            LOGE("Unable to initialize devmapping");
            goto out_free;
        }
        LOG_VOL("media path for devmapper volume = '%s'", dm_mediapath);
        volmgr_add_mediapath_to_volume(new, dm_mediapath);
    }

    if (!vol_root)
        vol_root = new;
    else {
        volume_t *scan = vol_root;
        while (scan->next)
            scan = scan->next;
        scan->next = new;
    }

    if (dm_src)
        free(dm_src);
    if (dm_src_type)
        free(dm_src_type);
    if (dm_tgt)
        free(dm_tgt);
    if (dm_param)
        free(dm_param);
    if (dm_tgtfs)
        free(dm_tgtfs);

    return rc;

 out_free:

    if (dm_src)
        free(dm_src);
    if (dm_src_type)
        free(dm_src_type);
    if (dm_tgt)
        free(dm_tgt);
    if (dm_param)
        free(dm_param);
    if (dm_tgtfs)
        free(dm_tgtfs);


    for (i = 0; i < VOLMGR_MAX_MEDIAPATHS_PER_VOLUME; i++) {
        if (new->media_paths[i])
            free(new->media_paths[i]);
    }
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

static volume_t *volmgr_lookup_volume_by_mountpoint(char *mount_point, boolean leave_locked)
{
    volume_t *v = vol_root;

    while(v) {
        pthread_mutex_lock(&v->lock);
        if (!strcmp(v->mount_point, mount_point)) {
            if (!leave_locked)
                pthread_mutex_unlock(&v->lock);
            return v;
        }
        pthread_mutex_unlock(&v->lock);
        v = v->next;
    }
    return NULL;
}

static volume_t *volmgr_lookup_volume_by_mediapath(char *media_path, boolean fuzzy)
{
    volume_t *scan = vol_root;
    int i;

    while (scan) {

        for (i = 0; i < VOLMGR_MAX_MEDIAPATHS_PER_VOLUME; i++) {
            if (!scan->media_paths[i])
                continue;

            if (fuzzy && !strncmp(media_path, scan->media_paths[i], strlen(scan->media_paths[i])))
                return scan;
            else if (!fuzzy && !strcmp(media_path, scan->media_paths[i]))
                return scan;
        }

        scan = scan->next;
    }
    return NULL;
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
    LOG_VOL("_volmgr_start(%s, %d:%d):", vol->mount_point,
            dev->major, dev->minor);
#endif

    if (vol->state == volstate_mounted) {
        LOGE("Unable to start volume '%s' (already mounted)", vol->mount_point);
        return -EBUSY;
    }

    for (fs = fs_table; fs->name; fs++) {
        if (!fs->identify_fn(dev))
            break;
    }

    if (!fs) {
        LOGE("No supported filesystems on %d:%d", dev->major, dev->minor);
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
        LOGE("Worker thread is currently running.. waiting..");
        pthread_mutex_lock(&vol->worker_sem);
        LOGI("Worker thread now available");
    }

    vol->dev = dev; 

    if (bootstrap) {
        LOGI("Aborting start of %s (bootstrap = %d)\n", vol->mount_point,
             bootstrap);
        vol->state = volstate_unmounted;
        return -EBUSY;
    }

    vol->worker_args.start_args.fs = fs;
    vol->worker_args.start_args.dev = dev;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&vol->worker_thread, &attr, volmgr_start_fs_thread, vol);

    return 0;
}

static void __start_fs_thread_lock_cleanup(void *arg)
{
    volume_t *vol = (volume_t *) arg;

#if DEBUG_VOLMGR
    LOG_VOL("__start_fs_thread_lock_cleanup(%s):", vol->mount_point);
#endif

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

    struct volmgr_fstable_entry *fs = vol->worker_args.start_args.fs;
    blkdev_t                    *dev = vol->worker_args.start_args.dev;
    int                          rc;
  
#if DEBUG_VOLMGR
    LOG_VOL("Worker thread pid %d starting %s fs %d:%d on %s", getpid(),
             fs->name, dev->major, dev->minor, vol->mount_point);
#endif

    if (fs->check_fn) {
#if DEBUG_VOLMGR
        LOG_VOL("Starting %s filesystem check on %d:%d", fs->name,
                dev->major, dev->minor);
#endif
        volume_setstate(vol, volstate_checking);
        pthread_mutex_unlock(&vol->lock);
        rc = fs->check_fn(dev);
        pthread_mutex_lock(&vol->lock);
        if (vol->state != volstate_checking) {
            LOGE("filesystem check aborted");
            goto out;
        }
        
        if (rc < 0) {
            LOGE("%s filesystem check failed on %d:%d (%s)", fs->name,
                    dev->major, dev->minor, strerror(-rc));
            if (rc == -ENODATA) {
               volume_setstate(vol, volstate_nofs);
               goto out;
            }
            goto out_unmountable;
        }
#if DEBUG_VOLMGR
        LOGI("%s filesystem check of %d:%d OK", fs->name,
                dev->major, dev->minor);
#endif
    }

    rc = fs->mount_fn(dev, vol, safe_mode);
    if (!rc) {
        LOGI("Sucessfully mounted %s filesystem %d:%d on %s (safe-mode %s)",
                fs->name, dev->major, dev->minor, vol->mount_point,
                (safe_mode ? "on" : "off"));
        vol->fs = fs;
        volume_setstate(vol, volstate_mounted);
        goto out;
    }

    LOGE("%s filesystem mount of %d:%d failed (%d)", fs->name, dev->major,
         dev->minor, rc);

 out_unmountable:
    volume_setstate(vol, volstate_damaged);
 out:
    pthread_cleanup_pop(1);
    pthread_exit(NULL);
    return NULL;
}

static void volmgr_start_fs_thread_sighandler(int signo)
{
    LOGE("Volume startup thread got signal %d", signo);
}

static void volume_setstate(volume_t *vol, volume_state_t state)
{
    if (state == vol->state)
        return;

#if DEBUG_VOLMGR
    LOG_VOL("Volume %s state change from %d -> %d", vol->mount_point, vol->state, state);
#endif
    
    vol->state = state;
    
    char *prop_val = conv_volstate_to_propstr(vol->state);

    if (prop_val) {
        property_set(PROP_EXTERNAL_STORAGE_STATE, prop_val);
        volume_send_state(vol);
    }
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

    return volume_state_strings[i].event;
}

static char *conv_volstate_to_propstr(volume_state_t state)
{
    int i;

    for (i = 0; volume_state_strings[i].event != NULL; i++) {
        if (volume_state_strings[i].state == state)
            break;
    }

    return volume_state_strings[i].property_val;
}

