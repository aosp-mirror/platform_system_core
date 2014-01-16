/*
 * Copyright (C) 2013 The Android Open Source Project
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <memtrack/memtrack.h>

#include <pagemap/pagemap.h>

#define DIV_ROUND_UP(x,y) (((x) + (y) - 1) / (y))

static int getprocname(pid_t pid, char *buf, int len) {
    char *filename;
    FILE *f;
    int rc = 0;
    static const char* unknown_cmdline = "<unknown>";

    if (len <= 0) {
        return -1;
    }

    if (asprintf(&filename, "/proc/%d/cmdline", pid) < 0) {
        rc = 1;
        goto exit;
    }

    f = fopen(filename, "r");
    if (f == NULL) {
        rc = 2;
        goto releasefilename;
    }

    if (fgets(buf, len, f) == NULL) {
        rc = 3;
        goto closefile;
    }

closefile:
    (void) fclose(f);
releasefilename:
    free(filename);
exit:
    if (rc != 0) {
        /*
         * The process went away before we could read its process name. Try
         * to give the user "<unknown>" here, but otherwise they get to look
         * at a blank.
         */
        if (strlcpy(buf, unknown_cmdline, (size_t)len) >= (size_t)len) {
            rc = 4;
        }
    }

    return rc;
}

int main(int argc, char *argv[])
{
    int ret;
    pm_kernel_t *ker;
    size_t num_procs;
    pid_t *pids;
    struct memtrack_proc *p;
    size_t i;

    (void)argc;
    (void)argv;

    ret = memtrack_init();
    if (ret < 0) {
        fprintf(stderr, "failed to initialize HAL: %s (%d)\n", strerror(-ret), ret);
        exit(EXIT_FAILURE);
    }

    ret = pm_kernel_create(&ker);
    if (ret) {
        fprintf(stderr, "Error creating kernel interface -- "
                        "does this kernel have pagemap?\n");
        exit(EXIT_FAILURE);
    }

    ret = pm_kernel_pids(ker, &pids, &num_procs);
    if (ret) {
        fprintf(stderr, "Error listing processes.\n");
        exit(EXIT_FAILURE);
    }

    p = memtrack_proc_new();
    if (ret) {
        fprintf(stderr, "failed to create memtrack process handle\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < num_procs; i++) {
        pid_t pid = pids[i];
        char cmdline[256];
        size_t v1;
        size_t v2;
        size_t v3;
        size_t v4;
        size_t v5;
        size_t v6;

        getprocname(pid, cmdline, (int)sizeof(cmdline));

        ret = memtrack_proc_get(p, pid);
        if (ret) {
            fprintf(stderr, "failed to get memory info for pid %d: %s (%d)\n",
                    pid, strerror(-ret), ret);
            continue;
        }

        v1 = DIV_ROUND_UP(memtrack_proc_graphics_total(p), 1024);
        v2 = DIV_ROUND_UP(memtrack_proc_graphics_pss(p), 1024);
        v3 = DIV_ROUND_UP(memtrack_proc_gl_total(p), 1024);
        v4 = DIV_ROUND_UP(memtrack_proc_gl_pss(p), 1024);
        v5 = DIV_ROUND_UP(memtrack_proc_other_total(p), 1024);
        v6 = DIV_ROUND_UP(memtrack_proc_other_pss(p), 1024);

        if (v1 | v2 | v3 | v4 | v5 | v6) {
            printf("%5d %6zu %6zu %6zu %6zu %6zu %6zu %s\n", pid,
                   v1, v2, v3, v4, v5, v6, cmdline);
        }
    }

    memtrack_proc_destroy(p);

    return 0;
}
