/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "libtrusty"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/vm_sockets.h> /* must be after sys/socket.h */
#include <log/log.h>

#include <trusty/ipc.h>

static const char* strip_prefix(const char* str, const char* prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(str, prefix, prefix_len) == 0) {
        return str + prefix_len;
    } else {
        return NULL;
    }
}

static bool use_vsock_connection = false;
static int tipc_vsock_connect(const char* type_cid_port_str, const char* srv_name) {
    int ret;
    const char* cid_port_str;
    char* port_str;
    char* end_str;
    int socket_type;
    if ((cid_port_str = strip_prefix(type_cid_port_str, "STREAM:"))) {
        socket_type = SOCK_STREAM;
    } else if ((cid_port_str = strip_prefix(type_cid_port_str, "SEQPACKET:"))) {
        socket_type = SOCK_SEQPACKET;
    } else {
        /*
         * Default to SOCK_STREAM if neither type is specified.
         *
         * TODO: use SOCK_SEQPACKET by default instead of SOCK_STREAM when SOCK_SEQPACKET is fully
         * supported since it matches tipc better. At the moment SOCK_SEQPACKET is not supported by
         * crosvm. It is also significantly slower since the Linux kernel implementation (as of
         * v6.7-rc1) sends credit update packets every time it receives a data packet while the
         * SOCK_STREAM version skips these unless the remaining buffer space is "low".
         */
        socket_type = SOCK_STREAM;
        cid_port_str = type_cid_port_str;
    }
    long cid = strtol(cid_port_str, &port_str, 0);
    if (port_str[0] != ':') {
        ALOGE("%s: invalid VSOCK str, \"%s\", need cid:port missing : after cid\n", __func__,
              cid_port_str);
        return -EINVAL;
    }
    long port = strtol(port_str + 1, &end_str, 0);
    if (end_str[0] != '\0') {
        ALOGE("%s: invalid VSOCK str, \"%s\", need cid:port got %ld:%ld\n", __func__, cid_port_str,
              cid, port);
        return -EINVAL;
    }
    int fd = socket(AF_VSOCK, socket_type, 0);
    if (fd < 0) {
        ret = -errno;
        ALOGE("%s: can't get vsock %ld:%ld socket for tipc service \"%s\" (err=%d)\n", __func__,
              cid, port, srv_name, errno);
        return ret < 0 ? ret : -1;
    }
    struct timeval connect_timeout = {.tv_sec = 60, .tv_usec = 0};
    ret = setsockopt(fd, AF_VSOCK, SO_VM_SOCKETS_CONNECT_TIMEOUT, &connect_timeout,
                     sizeof(connect_timeout));
    if (ret) {
        ALOGE("%s: vsock %ld:%ld: Failed to set connect timeout (err=%d)\n", __func__, cid, port,
              errno);
        /* failed to set longer timeout, but try to connect anyway */
    }
    struct sockaddr_vm sa = {
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = cid,
    };
    int retry = 10;
    do {
        ret = TEMP_FAILURE_RETRY(connect(fd, (struct sockaddr*)&sa, sizeof(sa)));
        if (ret && (errno == ENODEV || errno == ESOCKTNOSUPPORT) && --retry) {
            /*
             * The kernel returns ESOCKTNOSUPPORT instead of ENODEV if the socket type is
             * SOCK_SEQPACKET and the guest CID we are trying to connect to is not ready yet.
             */
            ALOGE("%s: Can't connect to vsock %ld:%ld for tipc service \"%s\" (err=%d) %d retries "
                  "remaining\n",
                  __func__, cid, port, srv_name, errno, retry);
            sleep(1);
        } else {
            retry = 0;
        }
    } while (retry);
    if (ret) {
        ret = -errno;
        ALOGE("%s: Can't connect to vsock %ld:%ld for tipc service \"%s\" (err=%d)\n", __func__,
              cid, port, srv_name, errno);
        close(fd);
        return ret < 0 ? ret : -1;
    }
    /*
     * TODO: Current vsock tipc bridge in trusty expects a port name in the
     * first packet. We need to replace this with a protocol that also does DICE
     * based authentication.
     */
    ret = TEMP_FAILURE_RETRY(write(fd, srv_name, strlen(srv_name)));
    if (ret != strlen(srv_name)) {
        ret = -errno;
        ALOGE("%s: vsock %ld:%ld: failed to send tipc service name \"%s\" (err=%d)\n", __func__,
              cid, port, srv_name, errno);
        close(fd);
        return ret < 0 ? ret : -1;
    }
    /*
     * Work around lack of seq packet support. Read a status byte to prevent
     * the caller from sending more data until srv_name has been read.
     */
    int8_t status;
    ret = TEMP_FAILURE_RETRY(read(fd, &status, sizeof(status)));
    if (ret != sizeof(status)) {
        ALOGE("%s: vsock %ld:%ld: failed to read status byte for connect to tipc service name "
              "\"%s\" (err=%d)\n",
              __func__, cid, port, srv_name, errno);
        close(fd);
        return ret < 0 ? ret : -1;
    }
    use_vsock_connection = true;
    return fd;
}

static size_t tipc_vsock_send(int fd, const struct iovec* iov, int iovcnt, struct trusty_shm* shms,
                              int shmcnt) {
    int ret;

    (void)shms;
    if (shmcnt != 0) {
        ALOGE("%s: vsock does not yet support passing fds\n", __func__);
        return -ENOTSUP;
    }
    ret = TEMP_FAILURE_RETRY(writev(fd, iov, iovcnt));
    if (ret < 0) {
        ret = -errno;
        ALOGE("%s: failed to send message (err=%d)\n", __func__, errno);
        return ret < 0 ? ret : -1;
    }

    return ret;
}

int tipc_connect(const char* dev_name, const char* srv_name) {
    int fd;
    int rc;

    const char* type_cid_port_str = strip_prefix(dev_name, "VSOCK:");
    if (type_cid_port_str) {
        return tipc_vsock_connect(type_cid_port_str, srv_name);
    }

    fd = TEMP_FAILURE_RETRY(open(dev_name, O_RDWR));
    if (fd < 0) {
        rc = -errno;
        ALOGE("%s: cannot open tipc device \"%s\": %s\n", __func__, dev_name, strerror(errno));
        return rc < 0 ? rc : -1;
    }

    rc = TEMP_FAILURE_RETRY(ioctl(fd, TIPC_IOC_CONNECT, srv_name));
    if (rc < 0) {
        rc = -errno;
        ALOGE("%s: can't connect to tipc service \"%s\" (err=%d)\n", __func__, srv_name, errno);
        close(fd);
        return rc < 0 ? rc : -1;
    }

    ALOGV("%s: connected to \"%s\" fd %d\n", __func__, srv_name, fd);
    return fd;
}

ssize_t tipc_send(int fd, const struct iovec* iov, int iovcnt, struct trusty_shm* shms,
                  int shmcnt) {
    if (use_vsock_connection) {
        return tipc_vsock_send(fd, iov, iovcnt, shms, shmcnt);
    }
    struct tipc_send_msg_req req;
    req.iov = (__u64)iov;
    req.iov_cnt = (__u64)iovcnt;
    req.shm = (__u64)shms;
    req.shm_cnt = (__u64)shmcnt;

    int rc = TEMP_FAILURE_RETRY(ioctl(fd, TIPC_IOC_SEND_MSG, &req));
    if (rc < 0) {
        ALOGE("%s: failed to send message (err=%d)\n", __func__, rc);
    }

    return rc;
}

void tipc_close(int fd) {
    close(fd);
}
