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
            boolean enable_ums = false;
            cnode* child = node->first_child;
            
            while (child)
            {
                const char* name = child->name;
                const char* value = child->value;
                
                if (strcmp(name, "block_device") == 0)
                    block_device = value;
                else if (strcmp(name, "mount_point") == 0)
                    mount_point = value;
                else if (strcmp(name, "enable_ums") == 0 &&
                        strcmp(value, "true") == 0)
                    enable_ums = true;
                
                child = child->next;
            }

            // mount point and removable fields are optional
            if (block_device && mount_point)
            {
                AddMountPoint(block_device, mount_point, enable_ums);
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
