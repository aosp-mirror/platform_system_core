/* libcutils/qtaguid.c
**
** Copyright 2011, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "qtaguid"

#include <cutils/qtaguid.h>
#include <cutils/log.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int set_qtaguid(int sockfd, int tag, uid_t uid) {
    char lineBuf[128];
    int fd, cnt = 0;
    uint64_t kTag = (uint64_t)tag << 32;
    snprintf(lineBuf, sizeof(lineBuf), "t %d %llu %d", sockfd, kTag, uid);

    LOGV("Tagging Socket with command %s\n", lineBuf);
    /* TODO: Enable after the kernel module is fixed.
       fd = open("/proc/net/xt_qtaguid/ctrl", O_WRONLY);
       if (fd < 0) {
           return -1;
       }

       cnt = write(fd, lineBuf, strlen(lineBuf));
       close(fd);
    */
    return (cnt>0?0:-1);
}
