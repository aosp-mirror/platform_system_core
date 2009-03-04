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
**    mountd main program
*/

#include "mountd.h"

#include <cutils/config_utils.h>
#include <cutils/cpu_info.h>
#include <cutils/properties.h>

#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/capability.h>
#include <linux/prctl.h>

#include <private/android_filesystem_config.h>

#ifdef MOUNTD_LOG
FILE*    logFile;
#endif

struct asec_cfg {
    const char *name;
    const char *backing_file;
    const char *size;
    const char *mount_point;
    const char *crypt;
};

static int ProcessAsecData(cnode *node, struct asec_cfg *stores, int idx)
{
    cnode *child = node->first_child;
    const char *name = NULL;
    const char *file = NULL;
    const char *size = NULL;
    const char *mp = NULL;
    const char *crypt = NULL;

    LOG_ASEC("ProcessAsecData(%s, %p, %d)\n", node->name, stores, idx);

    while (child) {
        if (!strcmp(child->name, "name"))
            name = child->value;
        else if (!strcmp(child->name, "backing_file"))
            file = child->value;
        else if (!strcmp(child->name, "size"))
            size = child->value;
        else if (!strcmp(child->name, "mount_point"))
            mp = child->value;
        else if (!strcmp(child->name, "crypt"))
            crypt = child->value;
        child = child->next;
    }

    if (!name || !file || !size || !mp || !crypt) {
        LOG_ERROR("Missing required token from config. Skipping ASEC volume\n");
        return -1;
    } else if (idx == ASEC_STORES_MAX) {
        LOG_ERROR("Maximum # of ASEC stores already defined\n");
        return -1;
    }

    stores[idx].name = name;
    stores[idx].backing_file = file;
    stores[idx].size = size;
    stores[idx].mount_point = mp;
    stores[idx].crypt = crypt;
    return ++idx;
}

static void ReadConfigFile(const char* path)
{
    cnode* root = config_node("", "");
    cnode* node;

    config_load_file(root, path);
    node = root->first_child;

    while (node)
    {
        if (strcmp(node->name, "mount") == 0)
        {
            const char* block_device = NULL;
            const char* mount_point = NULL;
            const char* driver_store_path = NULL;
            boolean enable_ums = false;
            cnode* child = node->first_child;
            struct asec_cfg asec_stores[ASEC_STORES_MAX];
            int    asec_idx = 0;

            memset(asec_stores, 0, sizeof(asec_stores));

            while (child)
            {
                const char* name = child->name;
                const char* value = child->value;

                if (!strncmp(name, "asec_", 5)) {
                     int rc = ProcessAsecData(child, asec_stores, asec_idx);
                     if (rc < 0) {
                         LOG_ERROR("Error processing ASEC cfg data\n");
                     } else
                         asec_idx = rc;
                } else if (strcmp(name, "block_device") == 0)
                    block_device = value;
                else if (strcmp(name, "mount_point") == 0)
                    mount_point = value;
                else if (strcmp(name, "driver_store_path") == 0)
                    driver_store_path = value;
                else if (strcmp(name, "enable_ums") == 0 &&
                        strcmp(value, "true") == 0)
                    enable_ums = true;
                
                child = child->next;
            }

            // mount point and removable fields are optional
            if (block_device && mount_point)
            {
                void *mp = AddMountPoint(block_device, mount_point, driver_store_path, enable_ums);
                int i;

                for (i = 0; i < asec_idx; i++) {
                    AddAsecToMountPoint(mp, asec_stores[i].name, asec_stores[i].backing_file,
                                        asec_stores[i].size, asec_stores[i].mount_point,
                                        asec_stores[i].crypt);
                }
            }
        }
            
        node = node->next;
    }
}

int main(int argc, char* argv[])
{
    const char*     configPath = "/system/etc/mountd.conf";
    int             i;    

    for (i = 1; i < argc; i++)
    {
        const char* arg = argv[i];
        
        if (strcmp(arg, "-f") == 0)
        {
            if (i < argc - 1)
                configPath = argv[++i];
        }
    }
        
    ReadConfigFile(configPath);
    StartAutoMounter();
    return RunServer();
}
