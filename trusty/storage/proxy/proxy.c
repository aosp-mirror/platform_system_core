/*
 * Copyright (C) 2016 The Android Open Source Project
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
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android/binder_process.h>
#include <cutils/android_filesystem_config.h>

#include "checkpoint_handling.h"
#include "ipc.h"
#include "log.h"
#include "rpmb.h"
#include "storage.h"
#include "watchdog.h"

#define REQ_BUFFER_SIZE 4096
static uint8_t req_buffer[REQ_BUFFER_SIZE + 1];

static const char* ss_data_root;
static const char* trusty_devname;
static const char* rpmb_devname;
static const char* ss_srv_name = STORAGE_DISK_PROXY_PORT;
static const char* max_file_size_from;

static enum dev_type dev_type = MMC_RPMB;

/* List head for storage mapping, elements added at init, and never removed */
static struct storage_mapping_node* storage_mapping_head;

static enum dev_type parse_dev_type(const char* dev_type_name) {
    if (!strcmp(dev_type_name, "mmc")) {
        return MMC_RPMB;
    } else if (!strcmp(dev_type_name, "virt")) {
        return VIRT_RPMB;
    } else if (!strcmp(dev_type_name, "sock")) {
        return SOCK_RPMB;
    } else if (!strcmp(dev_type_name, "ufs")) {
        return UFS_RPMB;
    } else {
        return UNKNOWN_RPMB;
    }
}

static int parse_and_append_file_mapping(const char* file_mapping) {
    if (file_mapping == NULL) {
        ALOGE("Provided file mapping is null\n");
        return -1;
    }
    char* file_mapping_dup = strdup(file_mapping);
    if (file_mapping_dup == NULL) {
        ALOGE("Couldn't duplicate string: %s\n", file_mapping);
        return -1;
    }
    const char* file_name = strtok(file_mapping_dup, ":");
    if (file_name == NULL) {
        ALOGE("No file name found\n");
        return -1;
    }
    const char* backing_storage = strtok(NULL, ":");
    if (backing_storage == NULL) {
        ALOGE("No backing storage found\n");
        return -1;
    }

    struct storage_mapping_node* new_node = malloc(sizeof(struct storage_mapping_node));
    if (new_node == NULL) {
        ALOGE("Couldn't allocate additional storage_mapping_node\n");
        return -1;
    }
    *new_node = (struct storage_mapping_node){.file_name = file_name,
                                              .backing_storage = backing_storage,
                                              .next = storage_mapping_head,
                                              .fd = -1};
    storage_mapping_head = new_node;
    return 0;
}

static const char* _sopts = "hp:d:r:t:m:f:";
static const struct option _lopts[] = {{"help", no_argument, NULL, 'h'},
                                       {"trusty_dev", required_argument, NULL, 'd'},
                                       {"data_path", required_argument, NULL, 'p'},
                                       {"rpmb_dev", required_argument, NULL, 'r'},
                                       {"dev_type", required_argument, NULL, 't'},
                                       {"max_file_size_from", required_argument, NULL, 'm'},
                                       {"file_storage_mapping", required_argument, NULL, 'f'},
                                       {0, 0, 0, 0}};

static void show_usage_and_exit(int code) {
    ALOGE("usage: storageproxyd -d <trusty_dev> -p <data_path> -r <rpmb_dev> -t <dev_type>  [-m "
          "<file>] [-f <file>:<mapping>]\n");
    ALOGE("Available dev types: mmc, virt\n");
    ALOGE("-f = Maps secure storage files like `0` and `persist/0`\n"
          "to block devices.  Storageproxyd will handle creating the\n"
          "appropriate symlinks in the root datapath.\n");
    ALOGE("-m = Specifies the max size constraint for file backed storages.\n"
          "The constraint is chosen by giving a file, this allows for passing a\n"
          "block device for which a max file size can be queried.  File based\n"
          "storages will be constrained to that size as well.\n");
    exit(code);
}

static int handle_req(struct storage_msg* msg, const void* req, size_t req_len) {
    int rc;

    struct watcher* watcher = watch_start("request", msg);

    if ((msg->flags & STORAGE_MSG_FLAG_POST_COMMIT) && msg->cmd != STORAGE_RPMB_SEND &&
        msg->cmd != STORAGE_FILE_WRITE) {
        /*
         * handling post commit messages on commands other than rpmb and write
         * operations are not implemented as there is no use case for this yet.
         */
        ALOGE("cmd 0x%x: post commit option is not implemented\n", msg->cmd);
        msg->result = STORAGE_ERR_UNIMPLEMENTED;
        goto err_response;
    }

    if (msg->flags & STORAGE_MSG_FLAG_PRE_COMMIT) {
        rc = storage_sync_checkpoint(watcher);
        if (rc < 0) {
            msg->result = STORAGE_ERR_SYNC_FAILURE;
            goto err_response;
        }
    }

    if (msg->flags & STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT) {
        bool is_checkpoint_active = false;

        rc = is_data_checkpoint_active(&is_checkpoint_active);
        if (rc != 0) {
            ALOGE("is_data_checkpoint_active failed in an unexpected way. Aborting.\n");
            msg->result = STORAGE_ERR_GENERIC;
            goto err_response;
        } else if (is_checkpoint_active) {
            ALOGE("Checkpoint in progress, dropping write ...\n");
            msg->result = STORAGE_ERR_GENERIC;
            goto err_response;
        }
    }

    switch (msg->cmd) {
        case STORAGE_FILE_DELETE:
            rc = storage_file_delete(msg, req, req_len, watcher);
            break;

        case STORAGE_FILE_OPEN:
            rc = storage_file_open(msg, req, req_len, watcher);
            break;

        case STORAGE_FILE_CLOSE:
            rc = storage_file_close(msg, req, req_len, watcher);
            break;

        case STORAGE_FILE_WRITE:
            rc = storage_file_write(msg, req, req_len, watcher);
            break;

        case STORAGE_FILE_READ:
            rc = storage_file_read(msg, req, req_len, watcher);
            break;

        case STORAGE_FILE_GET_SIZE:
            rc = storage_file_get_size(msg, req, req_len, watcher);
            break;

        case STORAGE_FILE_SET_SIZE:
            rc = storage_file_set_size(msg, req, req_len, watcher);
            break;

        case STORAGE_FILE_GET_MAX_SIZE:
            rc = storage_file_get_max_size(msg, req, req_len, watcher);
            break;

        case STORAGE_RPMB_SEND:
            rc = rpmb_send(msg, req, req_len, watcher);
            break;

        default:
            ALOGE("unhandled command 0x%x\n", msg->cmd);
            msg->result = STORAGE_ERR_UNIMPLEMENTED;
            goto err_response;
    }

    /* response was sent in handler */
    goto finish;

err_response:
    rc = ipc_respond(msg, NULL, 0);

finish:
    watch_finish(watcher);
    return rc;
}

static int proxy_loop(void) {
    ssize_t rc;
    struct storage_msg msg;

    /* enter main message handling loop */
    while (true) {
        /* get incoming message */
        rc = ipc_get_msg(&msg, req_buffer, REQ_BUFFER_SIZE);
        if (rc < 0) return rc;

        /* handle request */
        req_buffer[rc] = 0; /* force zero termination */
        rc = handle_req(&msg, req_buffer, rc);
        if (rc) return rc;
    }

    return 0;
}

static void parse_args(int argc, char* argv[]) {
    int opt;
    int oidx = 0;
    int rc = 0;

    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1) {
        switch (opt) {
            case 'd':
                trusty_devname = strdup(optarg);
                break;

            case 'p':
                ss_data_root = strdup(optarg);
                break;

            case 'r':
                rpmb_devname = strdup(optarg);
                break;

            case 't':
                dev_type = parse_dev_type(optarg);
                if (dev_type == UNKNOWN_RPMB) {
                    ALOGE("Unrecognized dev type: %s\n", optarg);
                    show_usage_and_exit(EXIT_FAILURE);
                }
                break;

            case 'f':
                rc = parse_and_append_file_mapping(optarg);
                if (rc < 0) {
                    ALOGE("Failed to parse file mapping: %s\n", optarg);
                    show_usage_and_exit(EXIT_FAILURE);
                }
                break;

            case 'm':
                max_file_size_from = strdup(optarg);
                break;

            default:
                ALOGE("unrecognized option (%c):\n", opt);
                show_usage_and_exit(EXIT_FAILURE);
        }
    }

    if (ss_data_root == NULL || trusty_devname == NULL || rpmb_devname == NULL) {
        ALOGE("missing required argument(s)\n");
        show_usage_and_exit(EXIT_FAILURE);
    }

    ALOGI("starting storageproxyd\n");
    ALOGI("storage data root: %s\n", ss_data_root);
    ALOGI("trusty dev: %s\n", trusty_devname);
    ALOGI("rpmb dev: %s\n", rpmb_devname);
    ALOGI("File Mappings: \n");
    const struct storage_mapping_node* curr = storage_mapping_head;
    for (; curr != NULL; curr = curr->next) {
        ALOGI("\t%s -> %s\n", curr->file_name, curr->backing_storage);
    }
    ALOGI("max file size from: %s\n", max_file_size_from ? max_file_size_from : "(unset)");
}

int main(int argc, char* argv[]) {
    int rc;

    /*
     * No access for group and other. We need execute access for user to create
     * an accessible directory.
     */
    umask(S_IRWXG | S_IRWXO);

    /* parse arguments */
    parse_args(argc, argv);

    /*
     * Start binder threadpool. At least one extra binder thread is needed to
     * connect to the wakelock service without relying on polling. If we poll on
     * the main thread we end up pausing for at least 1s even if the service
     * starts faster. We set the max thread count to 0 because startThreadPool
     * "Starts one thread, PLUS those requested in setThreadPoolMaxThreadCount,
     * PLUS those manually requested in joinThreadPool." We only need a single
     * binder thread to receive notifications on.
     */
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    ABinderProcess_startThreadPool();

    /* initialize secure storage directory */
    rc = storage_init(ss_data_root, storage_mapping_head, max_file_size_from);
    if (rc < 0) return EXIT_FAILURE;

    /* open rpmb device */
    rc = rpmb_open(rpmb_devname, dev_type);
    if (rc < 0) return EXIT_FAILURE;

    /* connect to Trusty secure storage server */
    rc = ipc_connect(trusty_devname, ss_srv_name);
    if (rc < 0) return EXIT_FAILURE;

    /* enter main loop */
    rc = proxy_loop();
    ALOGE("exiting proxy loop with status (%d)\n", rc);

    ipc_disconnect();
    rpmb_close();

    return (rc < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
