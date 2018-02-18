/*
 *   Copyright 2013 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <ion/ion.h>
#include <linux/ion.h>

size_t len = 1024*1024, align = 0;
int prot = PROT_READ | PROT_WRITE;
int map_flags = MAP_SHARED;
int alloc_flags = 0;
int heap_mask = 1;
int test = -1;
size_t stride;

int _ion_alloc_test(int *fd, ion_user_handle_t *handle)
{
    int ret;

    *fd = ion_open();
    if (*fd < 0)
        return *fd;

    ret = ion_alloc(*fd, len, align, heap_mask, alloc_flags, handle);

    if (ret)
        printf("%s failed: %s\n", __func__, strerror(ret));
    return ret;
}

void ion_alloc_test()
{
    int fd, ret;
    ion_user_handle_t handle;

    if(_ion_alloc_test(&fd, &handle))
        return;

    ret = ion_free(fd, handle);
    if (ret) {
        printf("%s failed: %s %d\n", __func__, strerror(ret), handle);
        return;
    }
    ion_close(fd);
    printf("ion alloc test: passed\n");
}

void ion_map_test()
{
    int fd, map_fd, ret;
    size_t i;
    ion_user_handle_t handle;
    unsigned char *ptr;

    if(_ion_alloc_test(&fd, &handle))
        return;

    ret = ion_map(fd, handle, len, prot, map_flags, 0, &ptr, &map_fd);
    if (ret)
        return;

    for (i = 0; i < len; i++) {
        ptr[i] = (unsigned char)i;
    }
    for (i = 0; i < len; i++)
        if (ptr[i] != (unsigned char)i)
            printf("%s failed wrote %zu read %d from mapped "
                   "memory\n", __func__, i, ptr[i]);
    /* clean up properly */
    ret = ion_free(fd, handle);
    ion_close(fd);
    munmap(ptr, len);
    close(map_fd);

    _ion_alloc_test(&fd, &handle);
    close(fd);

#if 0
    munmap(ptr, len);
    close(map_fd);
    ion_close(fd);

    _ion_alloc_test(len, align, flags, &fd, &handle);
    close(map_fd);
    ret = ion_map(fd, handle, len, prot, flags, 0, &ptr, &map_fd);
    /* don't clean up */
#endif
}

void ion_share_test()

{
    ion_user_handle_t handle;
    int sd[2];
    int num_fd = 1;
    struct iovec count_vec = {
        .iov_base = &num_fd,
        .iov_len = sizeof num_fd,
    };
    char buf[CMSG_SPACE(sizeof(int))];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sd);
    if (fork()) {
        struct msghdr msg = {
            .msg_control = buf,
            .msg_controllen = sizeof buf,
            .msg_iov = &count_vec,
            .msg_iovlen = 1,
        };

        struct cmsghdr *cmsg;
        int fd, share_fd, ret;
        char *ptr;
        /* parent */
        if(_ion_alloc_test(&fd, &handle))
            return;
        ret = ion_share(fd, handle, &share_fd);
        if (ret)
            printf("share failed %s\n", strerror(errno));
        ptr = mmap(NULL, len, prot, map_flags, share_fd, 0);
        if (ptr == MAP_FAILED) {
            return;
        }
        strcpy(ptr, "master");
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(cmsg) = share_fd;
        /* send the fd */
        printf("master? [%10s] should be [master]\n", ptr);
        printf("master sending msg 1\n");
        sendmsg(sd[0], &msg, 0);
        if (recvmsg(sd[0], &msg, 0) < 0)
            perror("master recv msg 2");
        printf("master? [%10s] should be [child]\n", ptr);

        /* send ping */
        sendmsg(sd[0], &msg, 0);
        printf("master->master? [%10s]\n", ptr);
        if (recvmsg(sd[0], &msg, 0) < 0)
            perror("master recv 1");
        close(fd);
        _exit(0);
    } else {
        struct cmsghdr *cmsg;
        char* ptr;
        int fd, recv_fd;
        char* child_buf[100];
        /* child */
        struct iovec count_vec = {
            .iov_base = child_buf,
            .iov_len = sizeof child_buf,
        };

        struct msghdr child_msg = {
            .msg_control = buf,
            .msg_controllen = sizeof buf,
            .msg_iov = &count_vec,
            .msg_iovlen = 1,
        };

        if (recvmsg(sd[1], &child_msg, 0) < 0)
            perror("child recv msg 1");
        cmsg = CMSG_FIRSTHDR(&child_msg);
        if (cmsg == NULL) {
            printf("no cmsg rcvd in child");
            return;
        }
        recv_fd = *(int*)CMSG_DATA(cmsg);
        if (recv_fd < 0) {
            printf("could not get recv_fd from socket");
            return;
        }
        printf("child %d\n", recv_fd);
        fd = ion_open();
        ptr = mmap(NULL, len, prot, map_flags, recv_fd, 0);
        if (ptr == MAP_FAILED) {
            return;
        }
        printf("child? [%10s] should be [master]\n", ptr);
        strcpy(ptr, "child");
        printf("child sending msg 2\n");
        sendmsg(sd[1], &child_msg, 0);
        close(fd);
    }
}

int main(int argc, char* argv[]) {
    int c;
    enum tests {
        ALLOC_TEST = 0, MAP_TEST, SHARE_TEST,
    };

    while (1) {
        static struct option opts[] = {
            {"alloc", no_argument, 0, 'a'},
            {"alloc_flags", required_argument, 0, 'f'},
            {"heap_mask", required_argument, 0, 'h'},
            {"map", no_argument, 0, 'm'},
            {"share", no_argument, 0, 's'},
            {"len", required_argument, 0, 'l'},
            {"align", required_argument, 0, 'g'},
            {"map_flags", required_argument, 0, 'z'},
            {"prot", required_argument, 0, 'p'},
        };
        int i = 0;
        c = getopt_long(argc, argv, "af:h:l:mr:st", opts, &i);
        if (c == -1)
            break;

        switch (c) {
        case 'l':
            len = atol(optarg);
            break;
        case 'g':
            align = atol(optarg);
            break;
        case 'z':
            map_flags = 0;
            map_flags |= strstr(optarg, "PROT_EXEC") ? PROT_EXEC : 0;
            map_flags |= strstr(optarg, "PROT_READ") ? PROT_READ: 0;
            map_flags |= strstr(optarg, "PROT_WRITE") ? PROT_WRITE: 0;
            map_flags |= strstr(optarg, "PROT_NONE") ? PROT_NONE: 0;
            break;
        case 'p':
            prot = 0;
            prot |= strstr(optarg, "MAP_PRIVATE") ? MAP_PRIVATE : 0;
            prot |= strstr(optarg, "MAP_SHARED") ? MAP_SHARED : 0;
            break;
        case 'f':
            alloc_flags = atol(optarg);
            break;
        case 'h':
            heap_mask = atol(optarg);
            break;
        case 'a':
            test = ALLOC_TEST;
            break;
        case 'm':
            test = MAP_TEST;
            break;
        case 's':
            test = SHARE_TEST;
            break;
        }
    }
    printf("test %d, len %zu, align %zu, map_flags %d, prot %d, heap_mask %d,"
           " alloc_flags %d\n", test, len, align, map_flags, prot,
           heap_mask, alloc_flags);
    switch (test) {
        case ALLOC_TEST:
            ion_alloc_test();
            break;
        case MAP_TEST:
            ion_map_test();
            break;
        case SHARE_TEST:
            ion_share_test();
            break;
        default:
            printf("must specify a test (alloc, map, share)\n");
    }
    return 0;
}
