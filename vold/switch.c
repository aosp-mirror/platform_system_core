
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
#include <dirent.h>
#include <errno.h>

#include <sys/types.h>

#include "vold.h"
#include "switch.h"

#define DEBUG_BOOTSTRAP 0

static int mmc_bootstrap_switch(char *sysfs_path);

int switch_bootstrap()
{
    DIR *d;
    struct dirent *de;

    if (!(d = opendir(SYSFS_CLASS_SWITCH_PATH))) {
        LOG_ERROR("Unable to open '%s' (%s)", SYSFS_CLASS_SWITCH_PATH,
                   strerror(errno));
        return -errno;
    }

    while ((de = readdir(d))) {
        char tmp[255];

        if (de->d_name[0] == '.')
            continue;

        sprintf(tmp, "%s/%s", SYSFS_CLASS_SWITCH_PATH, de->d_name);
        if (mmc_bootstrap_switch(tmp)) {
            LOG_ERROR("Error bootstrapping switch '%s' (%s)", tmp,
                      strerror(errno));
        }
    }

    closedir(d);

    return 0;
}

static int mmc_bootstrap_switch(char *sysfs_path)
{
#if DEBUG_BOOTSTRAP
    LOG_VOL("bootstrap_switch(%s):", sysfs_path);
#endif

    char filename[255];
    char name[255];
    char state[255];
    char tmp[255];
    char *uevent_params[3];
    char devpath[255];
    FILE *fp;

    /*
     * Read switch name
     */
    sprintf(filename, "%s/name", sysfs_path);
    if (!(fp = fopen(filename, "r"))) {
        LOGE("Error opening switch name path '%s' (%s)",
             sysfs_path, strerror(errno));
       return -errno;
    }
    if (!fgets(name, sizeof(name), fp)) {
        LOGE("Unable to read switch name");
        fclose(fp);
        return -EIO;
    }
    fclose(fp);

    name[strlen(name) -1] = '\0';
    sprintf(devpath, "/devices/virtual/switch/%s", name);
    sprintf(tmp, "SWITCH_NAME=%s", name);
    uevent_params[0] = (char *) strdup(tmp);

    /*
     * Read switch state
     */
    sprintf(filename, "%s/state", sysfs_path);
    if (!(fp = fopen(filename, "r"))) {
        LOGE("Error opening switch state path '%s' (%s)",
             sysfs_path, strerror(errno));
       return -errno;
    }
    if (!fgets(state, sizeof(state), fp)) {
        LOGE("Unable to read switch state");
        fclose(fp);
        return -EIO;
    }
    fclose(fp);

    state[strlen(state) -1] = '\0';
    sprintf(tmp, "SWITCH_STATE=%s", state);
    uevent_params[1] = (char *) strdup(tmp);

    uevent_params[2] = (char *) NULL;

    if (simulate_uevent("switch", devpath, "add", uevent_params) < 0) {
        LOGE("Error simulating uevent (%s)", strerror(errno));
        return -errno;
    }

    return 0;   
}
