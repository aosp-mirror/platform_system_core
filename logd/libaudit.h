/*
 * Copyright 2012, Samsung Telecommunications of America
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Written by William Roberts <w.roberts@sta.samsung.com>
 */

#ifndef _LIBAUDIT_H_
#define _LIBAUDIT_H_

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/audit.h>
#include <linux/netlink.h>

__BEGIN_DECLS

#define MAX_AUDIT_MESSAGE_LENGTH 8970

typedef enum { GET_REPLY_BLOCKING = 0, GET_REPLY_NONBLOCKING } reply_t;

/* type == AUDIT_SIGNAL_INFO */
struct audit_sig_info {
    uid_t uid;
    pid_t pid;
    char ctx[0];
};

struct audit_message {
    struct nlmsghdr nlh;
    char data[MAX_AUDIT_MESSAGE_LENGTH];
};

/**
 * Opens a connection to the Audit netlink socket
 * @return
 *  A valid fd on success or < 0 on error with errno set.
 *  Returns the same errors as man 2 socket.
 */
extern int audit_open(void);

/**
 * Closes the fd returned from audit_open()
 * @param fd
 *  The fd to close
 */
extern void audit_close(int fd);

/**
 *
 * @param fd
 *  The fd returned by a call to audit_open()
 * @param rep
 *  The response struct to store the response in.
 * @param block
 *  Whether or not to block on IO
 * @param peek
 *  Whether or not we are to remove the message from
 *  the queue when we do a read on the netlink socket.
 * @return
 *  This function returns 0 on success, else -errno.
 */
extern int audit_get_reply(int fd, struct audit_message* rep, reply_t block,
                           int peek);

/**
 * Sets a pid to receive audit netlink events from the kernel
 * @param fd
 *  The fd returned by a call to audit_open()
 * @param pid
 *  The pid whom to set as the receiver of audit messages
 * @return
 *  This function returns 0 on success, -errno on error.
 */
extern int audit_setup(int fd, pid_t pid);

/* Max audit messages per second  */
#define AUDIT_RATE_LIMIT 5

__END_DECLS

#endif
