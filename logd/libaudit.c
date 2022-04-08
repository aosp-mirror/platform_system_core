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
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "libaudit.h"

/**
 * Waits for an ack from the kernel
 * @param fd
 *  The netlink socket fd
 * @return
 *  This function returns 0 on success, else -errno.
 */
static int get_ack(int fd) {
    int rc;
    struct audit_message rep;

    /* Sanity check, this is an internal interface this shouldn't happen */
    if (fd < 0) {
        return -EINVAL;
    }

    rc = audit_get_reply(fd, &rep, GET_REPLY_BLOCKING, MSG_PEEK);
    if (rc < 0) {
        return rc;
    }

    if (rep.nlh.nlmsg_type == NLMSG_ERROR) {
        audit_get_reply(fd, &rep, GET_REPLY_BLOCKING, 0);
        rc = ((struct nlmsgerr*)rep.data)->error;
        if (rc) {
            return -rc;
        }
    }

    return 0;
}

/**
 *
 * @param fd
 *  The netlink socket fd
 * @param type
 *  The type of netlink message
 * @param data
 *  The data to send
 * @param size
 *  The length of the data in bytes
 * @return
 *  This function returns a positive sequence number on success, else -errno.
 */
static int audit_send(int fd, int type, const void* data, size_t size) {
    int rc;
    static int16_t sequence = 0;
    struct audit_message req;
    struct sockaddr_nl addr;

    memset(&req, 0, sizeof(req));
    memset(&addr, 0, sizeof(addr));

    /* We always send netlink messaged */
    addr.nl_family = AF_NETLINK;

    /* Set up the netlink headers */
    req.nlh.nlmsg_type = type;
    req.nlh.nlmsg_len = NLMSG_SPACE(size);
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    /*
     * Check for a valid fd, even though sendto would catch this, its easier
     * to always blindly increment the sequence number
     */
    if (fd < 0) {
        return -EBADF;
    }

    /* Ensure the message is not too big */
    if (NLMSG_SPACE(size) > MAX_AUDIT_MESSAGE_LENGTH) {
        return -EINVAL;
    }

    /* Only memcpy in the data if it was specified */
    if (size && data) {
        memcpy(NLMSG_DATA(&req.nlh), data, size);
    }

    /*
     * Only increment the sequence number on a guarantee
     * you will send it to the kernel.
     *
     * Also, the sequence is defined as a u32 in the kernel
     * struct. Using an int here might not work on 32/64 bit splits. A
     * signed 64 bit value can overflow a u32..but a u32
     * might not fit in the response, so we need to use s32.
     * Which is still kind of hackish since int could be 16 bits
     * in size. The only safe type to use here is a signed 16
     * bit value.
     */
    req.nlh.nlmsg_seq = ++sequence;

    /* While failing and its due to interrupts */

    rc = TEMP_FAILURE_RETRY(sendto(fd, &req, req.nlh.nlmsg_len, 0,
                                   (struct sockaddr*)&addr, sizeof(addr)));

    /* Not all the bytes were sent */
    if (rc < 0) {
        rc = -errno;
        goto out;
    } else if ((uint32_t)rc != req.nlh.nlmsg_len) {
        rc = -EPROTO;
        goto out;
    }

    /* We sent all the bytes, get the ack */
    rc = get_ack(fd);

    /* If the ack failed, return the error, else return the sequence number */
    rc = (rc == 0) ? (int)sequence : rc;

out:
    /* Don't let sequence roll to negative */
    if (sequence < 0) {
        sequence = 0;
    }

    return rc;
}

int audit_setup(int fd, pid_t pid) {
    int rc;
    struct audit_message rep;
    struct audit_status status;

    memset(&status, 0, sizeof(status));

    /*
     * In order to set the auditd PID we send an audit message over the netlink
     * socket with the pid field of the status struct set to our current pid,
     * and the the mask set to AUDIT_STATUS_PID
     */
    status.pid = pid;
    status.mask = AUDIT_STATUS_PID;

    /* Let the kernel know this pid will be registering for audit events */
    rc = audit_send(fd, AUDIT_SET, &status, sizeof(status));
    if (rc < 0) {
        return rc;
    }

    /*
     * In a request where we need to wait for a response, wait for the message
     * and discard it. This message confirms and sync's us with the kernel.
     * This daemon is now registered as the audit logger.
     *
     * TODO
     * If the daemon dies and restarts the message didn't come back,
     * so I went to non-blocking and it seemed to fix the bug.
     * Need to investigate further.
     */
    audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);

    return 0;
}

int audit_open() {
    return socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT);
}

int audit_rate_limit(int fd, uint32_t limit) {
    struct audit_status status;
    memset(&status, 0, sizeof(status));
    status.mask = AUDIT_STATUS_RATE_LIMIT;
    status.rate_limit = limit; /* audit entries per second */
    return audit_send(fd, AUDIT_SET, &status, sizeof(status));
}

int audit_get_reply(int fd, struct audit_message* rep, reply_t block, int peek) {
    ssize_t len;
    int flags;
    int rc = 0;

    struct sockaddr_nl nladdr;
    socklen_t nladdrlen = sizeof(nladdr);

    if (fd < 0) {
        return -EBADF;
    }

    /* Set up the flags for recv from */
    flags = (block == GET_REPLY_NONBLOCKING) ? MSG_DONTWAIT : 0;
    flags |= peek;

    /*
     * Get the data from the netlink socket but on error we need to be carefull,
     * the interface shows that EINTR can never be returned, other errors,
     * however, can be returned.
     */
    len = TEMP_FAILURE_RETRY(recvfrom(fd, rep, sizeof(*rep), flags,
                                      (struct sockaddr*)&nladdr, &nladdrlen));

    /*
     * EAGAIN should be re-tried until success or another error manifests.
     */
    if (len < 0) {
        rc = -errno;
        if (block == GET_REPLY_NONBLOCKING && rc == -EAGAIN) {
            /* If request is non blocking and errno is EAGAIN, just return 0 */
            return 0;
        }
        return rc;
    }

    if (nladdrlen != sizeof(nladdr)) {
        return -EPROTO;
    }

    /* Make sure the netlink message was not spoof'd */
    if (nladdr.nl_pid) {
        return -EINVAL;
    }

    /* Check if the reply from the kernel was ok */
    if (!NLMSG_OK(&rep->nlh, (size_t)len)) {
        rc = (len == sizeof(*rep)) ? -EFBIG : -EBADE;
    }

    return rc;
}

void audit_close(int fd) {
    close(fd);
}
