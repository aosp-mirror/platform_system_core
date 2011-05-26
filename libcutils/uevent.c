/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <cutils/uevent.h>

#include <errno.h>
#include <strings.h>

#include <linux/netlink.h>

/**
 * Like recv(), but checks that messages actually originate from the kernel.
 */
ssize_t uevent_kernel_multicast_recv(int socket, void *buffer, size_t length) {
    struct iovec iov = { buffer, length };
    struct sockaddr_nl addr;
    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr hdr = {
        &addr,
        sizeof(addr),
        &iov,
        1,
        control,
        sizeof(control),
        0,
    };

    ssize_t n = recvmsg(socket, &hdr, 0);
    if (n <= 0) {
        return n;
    }

    if (addr.nl_groups == 0 || addr.nl_pid != 0) {
        /* ignoring non-kernel or unicast netlink message */
        goto out;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
        /* ignoring netlink message with no sender credentials */
        goto out;
    }

    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
    if (cred->uid != 0) {
        /* ignoring netlink message from non-root user */
        goto out;
    }

    return n;

out:
    /* clear residual potentially malicious data */
    bzero(buffer, length);
    errno = EIO;
    return -1;
}
