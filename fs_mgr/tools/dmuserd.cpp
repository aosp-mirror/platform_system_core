// SPDX-License-Identifier: Apache-2.0

#define _LARGEFILE64_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <iostream>
#include <string>

#define SECTOR_SIZE ((__u64)512)
#define BUFFER_BYTES 4096

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* This should be replaced with linux/dm-user.h. */
#ifndef _LINUX_DM_USER_H
#define _LINUX_DM_USER_H

#include <linux/types.h>

#define DM_USER_REQ_MAP_READ 0
#define DM_USER_REQ_MAP_WRITE 1
#define DM_USER_REQ_MAP_FLUSH 2
#define DM_USER_REQ_MAP_DISCARD 3
#define DM_USER_REQ_MAP_SECURE_ERASE 4
#define DM_USER_REQ_MAP_WRITE_SAME 5
#define DM_USER_REQ_MAP_WRITE_ZEROES 6
#define DM_USER_REQ_MAP_ZONE_OPEN 7
#define DM_USER_REQ_MAP_ZONE_CLOSE 8
#define DM_USER_REQ_MAP_ZONE_FINISH 9
#define DM_USER_REQ_MAP_ZONE_APPEND 10
#define DM_USER_REQ_MAP_ZONE_RESET 11
#define DM_USER_REQ_MAP_ZONE_RESET_ALL 12

#define DM_USER_REQ_MAP_FLAG_FAILFAST_DEV 0x00001
#define DM_USER_REQ_MAP_FLAG_FAILFAST_TRANSPORT 0x00002
#define DM_USER_REQ_MAP_FLAG_FAILFAST_DRIVER 0x00004
#define DM_USER_REQ_MAP_FLAG_SYNC 0x00008
#define DM_USER_REQ_MAP_FLAG_META 0x00010
#define DM_USER_REQ_MAP_FLAG_PRIO 0x00020
#define DM_USER_REQ_MAP_FLAG_NOMERGE 0x00040
#define DM_USER_REQ_MAP_FLAG_IDLE 0x00080
#define DM_USER_REQ_MAP_FLAG_INTEGRITY 0x00100
#define DM_USER_REQ_MAP_FLAG_FUA 0x00200
#define DM_USER_REQ_MAP_FLAG_PREFLUSH 0x00400
#define DM_USER_REQ_MAP_FLAG_RAHEAD 0x00800
#define DM_USER_REQ_MAP_FLAG_BACKGROUND 0x01000
#define DM_USER_REQ_MAP_FLAG_NOWAIT 0x02000
#define DM_USER_REQ_MAP_FLAG_CGROUP_PUNT 0x04000
#define DM_USER_REQ_MAP_FLAG_NOUNMAP 0x08000
#define DM_USER_REQ_MAP_FLAG_HIPRI 0x10000
#define DM_USER_REQ_MAP_FLAG_DRV 0x20000
#define DM_USER_REQ_MAP_FLAG_SWAP 0x40000

#define DM_USER_RESP_SUCCESS 0
#define DM_USER_RESP_ERROR 1
#define DM_USER_RESP_UNSUPPORTED 2

struct dm_user_message {
    __u64 seq;
    __u64 type;
    __u64 flags;
    __u64 sector;
    __u64 len;
    __u8 buf[];
};

#endif

static bool verbose = false;

ssize_t write_all(int fd, void* buf, size_t len) {
    char* buf_c = (char*)buf;
    ssize_t total = 0;
    ssize_t once;

    while (total < static_cast<ssize_t>(len)) {
        once = write(fd, buf_c + total, len - total);
        if (once < 0) return once;
        if (once == 0) {
            errno = ENOSPC;
            return 0;
        }
        total += once;
    }

    return total;
}

ssize_t read_all(int fd, void* buf, size_t len) {
    char* buf_c = (char*)buf;
    ssize_t total = 0;
    ssize_t once;

    while (total < static_cast<ssize_t>(len)) {
        once = read(fd, buf_c + total, len - total);
        if (once < 0) return once;
        if (once == 0) {
            errno = ENOSPC;
            return 0;
        }
        total += once;
    }

    return total;
}

int not_splice(int from, int to, __u64 count) {
    while (count > 0) {
        char buf[BUFFER_BYTES];
        __u64 max = count > BUFFER_BYTES ? BUFFER_BYTES : count;

        if (read_all(from, buf, max) <= 0) {
            perror("Unable to read");
            return -EIO;
        }

        if (write_all(to, buf, max) <= 0) {
            perror("Unable to write");
            return -EIO;
        }

        count -= max;
    }

    return 0;
}

static int simple_daemon(const std::string& control_path, const std::string& backing_path) {
    int control_fd = open(control_path.c_str(), O_RDWR);
    if (control_fd < 0) {
        fprintf(stderr, "Unable to open control device %s\n", control_path.c_str());
        return -1;
    }

    int backing_fd = open(backing_path.c_str(), O_RDWR);
    if (backing_fd < 0) {
        fprintf(stderr, "Unable to open backing device %s\n", backing_path.c_str());
        return -1;
    }

    while (1) {
        struct dm_user_message msg;
        char* base;
        __u64 type;

        if (verbose) std::cerr << "dmuserd: Waiting for message...\n";

        if (read_all(control_fd, &msg, sizeof(msg)) < 0) {
            if (errno == ENOTBLK) return 0;

            perror("unable to read msg");
            return -1;
        }

        if (verbose) {
            std::string type;
            switch (msg.type) {
                case DM_USER_REQ_MAP_WRITE:
                    type = "write";
                    break;
                case DM_USER_REQ_MAP_READ:
                    type = "read";
                    break;
                case DM_USER_REQ_MAP_FLUSH:
                    type = "flush";
                    break;
                default:
                    /*
                     * FIXME: Can't I do "whatever"s here rather that
                     * std::string("whatever")?
                     */
                    type = std::string("(unknown, id=") + std::to_string(msg.type) + ")";
                    break;
            }

            std::string flags;
            if (msg.flags & DM_USER_REQ_MAP_FLAG_SYNC) {
                if (!flags.empty()) flags += "|";
                flags += "S";
            }
            if (msg.flags & DM_USER_REQ_MAP_FLAG_META) {
                if (!flags.empty()) flags += "|";
                flags += "M";
            }
            if (msg.flags & DM_USER_REQ_MAP_FLAG_FUA) {
                if (!flags.empty()) flags += "|";
                flags += "FUA";
            }
            if (msg.flags & DM_USER_REQ_MAP_FLAG_PREFLUSH) {
                if (!flags.empty()) flags += "|";
                flags += "F";
            }

            std::cerr << "dmuserd: Got " << type << " request " << flags << " for sector "
                      << std::to_string(msg.sector) << " with length " << std::to_string(msg.len)
                      << "\n";
        }

        type = msg.type;
        switch (type) {
            case DM_USER_REQ_MAP_READ:
                msg.type = DM_USER_RESP_SUCCESS;
                break;
            case DM_USER_REQ_MAP_WRITE:
                if (msg.flags & DM_USER_REQ_MAP_FLAG_PREFLUSH ||
                    msg.flags & DM_USER_REQ_MAP_FLAG_FUA) {
                    if (fsync(backing_fd) < 0) {
                        perror("Unable to fsync(), just sync()ing instead");
                        sync();
                    }
                }
                msg.type = DM_USER_RESP_SUCCESS;
                if (lseek64(backing_fd, msg.sector * SECTOR_SIZE, SEEK_SET) < 0) {
                    perror("Unable to seek");
                    return -1;
                }
                if (not_splice(control_fd, backing_fd, msg.len) < 0) {
                    if (errno == ENOTBLK) return 0;
                    std::cerr << "unable to handle write data\n";
                    return -1;
                }
                if (msg.flags & DM_USER_REQ_MAP_FLAG_FUA) {
                    if (fsync(backing_fd) < 0) {
                        perror("Unable to fsync(), just sync()ing instead");
                        sync();
                    }
                }
                break;
            case DM_USER_REQ_MAP_FLUSH:
                msg.type = DM_USER_RESP_SUCCESS;
                if (fsync(backing_fd) < 0) {
                    perror("Unable to fsync(), just sync()ing instead");
                    sync();
                }
                break;
            default:
                std::cerr << "dmuserd: unsupported op " << std::to_string(msg.type) << "\n";
                msg.type = DM_USER_RESP_UNSUPPORTED;
                break;
        }

        if (verbose) std::cerr << "dmuserd: Responding to message\n";

        if (write_all(control_fd, &msg, sizeof(msg)) < 0) {
            if (errno == ENOTBLK) return 0;
            perror("unable to write msg");
            return -1;
        }

        switch (type) {
            case DM_USER_REQ_MAP_READ:
                if (verbose) std::cerr << "dmuserd: Sending read data\n";
                if (lseek64(backing_fd, msg.sector * SECTOR_SIZE, SEEK_SET) < 0) {
                    perror("Unable to seek");
                    return -1;
                }
                if (not_splice(backing_fd, control_fd, msg.len) < 0) {
                    if (errno == ENOTBLK) return 0;
                    std::cerr << "unable to handle read data\n";
                    return -1;
                }
                break;
        }
    }

    /* The daemon doesn't actully terminate for this test. */
    perror("Unable to read from control device");
    return -1;
}

void usage(char* prog) {
    printf("Usage: %s\n", prog);
    printf("	Handles block requests in userspace, backed by memory\n");
    printf("  -h			Display this help message\n");
    printf("  -c <control dev>		Control device to use for the test\n");
    printf("  -b <store path>		The file to use as a backing store, otherwise memory\n");
    printf("  -v                        Enable verbose mode\n");
}

int main(int argc, char* argv[]) {
    std::string control_path;
    std::string backing_path;
    char* store;
    int c;

    prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0);

    while ((c = getopt(argc, argv, "h:c:s:b:v")) != -1) {
        switch (c) {
            case 'h':
                usage(basename(argv[0]));
                exit(0);
            case 'c':
                control_path = optarg;
                break;
            case 'b':
                backing_path = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                usage(basename(argv[0]));
                exit(1);
        }
    }

    int r = simple_daemon(control_path, backing_path);
    if (r) fprintf(stderr, "simple_daemon() errored out\n");
    return r;
}
