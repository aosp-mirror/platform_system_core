/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fs_mgr_priv.h"

#ifdef _LIBGEN_H
#warning "libgen.h must not be included"
#endif

char *me = nullptr;

static void usage(void)
{
    LERROR << me << ": usage: " << me
           << " <-a | -n mnt_point blk_dev | -u> <fstab_file>";
    exit(1);
}

/* Parse the command line.  If an error is encountered, print an error message
 * and exit the program, do not return to the caller.
 * Return the number of argv[] entries consumed.
 */
static void parse_options(int argc, char * const argv[], int *a_flag, int *u_flag, int *n_flag,
                     const char **n_name, const char **n_blk_dev)
{
    me = basename(argv[0]);

    if (argc <= 1) {
        usage();
    }

    if (!strcmp(argv[1], "-a")) {
        if (argc != 3) {
            usage();
        }
        *a_flag = 1;
    }
    if (!strcmp(argv[1], "-n")) {
        if (argc != 5) {
            usage();
        }
        *n_flag = 1;
        *n_name = argv[2];
        *n_blk_dev = argv[3];
    }
    if (!strcmp(argv[1], "-u")) {
        if (argc != 3) {
            usage();
        }
        *u_flag = 1;
    }

    /* If no flag is specified, it's an error */
    if (!(*a_flag | *n_flag | *u_flag)) {
        usage();
    }

    /* If more than one flag is specified, it's an error */
    if ((*a_flag + *n_flag + *u_flag) > 1) {
        usage();
    }

    return;
}

int main(int argc, char * const argv[])
{
    int a_flag=0;
    int u_flag=0;
    int n_flag=0;
    const char *n_name=NULL;
    const char *n_blk_dev=NULL;
    const char *fstab_file=NULL;
    struct fstab *fstab=NULL;

    setenv("ANDROID_LOG_TAGS", "*:i", 1); // Set log level to INFO
    android::base::InitLogging(
        const_cast<char **>(argv), &android::base::KernelLogger);

    parse_options(argc, argv, &a_flag, &u_flag, &n_flag, &n_name, &n_blk_dev);

    /* The name of the fstab file is last, after the option */
    fstab_file = argv[argc - 1];

    fstab = fs_mgr_read_fstab(fstab_file);

    if (a_flag) {
        return fs_mgr_mount_all(fstab, MOUNT_MODE_DEFAULT);
    } else if (n_flag) {
        return fs_mgr_do_mount(fstab, n_name, (char *)n_blk_dev, 0);
    } else if (u_flag) {
        return fs_mgr_unmount_all(fstab);
    } else {
        LERROR << me << ": Internal error, unknown option";
        exit(1);
    }

    fs_mgr_free_fstab(fstab);

    /* Should not get here */
    exit(1);
}
