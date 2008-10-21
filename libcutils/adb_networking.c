/* libs/utils/adb_networking.c
**
** Copyright 2006, The Android Open Source Project
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

#define ADB_PORT 5037

#define _GNU_SOURCE     /* for asprintf */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <cutils/adb_networking.h>
#include <cutils/sockets.h>
#include <cutils/properties.h>

#define ADB_RESPONSE_SIZE 4

/**
 * Unfortunately, java.net.Socket wants to create it's filedescriptor early
 * So, this function takes an fd that must be an unconnected
 * PF_LOCAL SOCK_STREAM
 */
int adb_networking_connect_fd(int fd, struct sockaddr_in *p_address)
{
    struct sockaddr_in local_addr;
    socklen_t alen;
    char *cmd;
    char buf[ADB_RESPONSE_SIZE + 1];
    ssize_t count_read;
    int ret;
    int err;
    /* for impl of inet_ntoa below*/
    union {
        uint8_t  b[4];
        uint32_t l;
    } a;

    /* First, connect to adb */
   
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(ADB_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    do {
        err = connect(fd, (struct sockaddr *) &local_addr, sizeof(local_addr));
    } while (err < 0 && errno == EINTR);

    if (err < 0) {
        return -1;
    }

    a.l = p_address->sin_addr.s_addr;

    // compose the command
    asprintf(&cmd, "tcp:%u:%u.%u.%u.%u", 
                (unsigned int)ntohs(p_address->sin_port), 
                a.b[0],a.b[1],a.b[2],a.b[3]);

    // buf is now the ascii hex length of cmd
    snprintf(buf, sizeof(buf), "%04X", strlen(cmd));

    // write the 4-byte length
    do {
        err = write(fd, buf, 4);        
    } while (err < 0 && errno == EINTR);

    // write the command
    do {
        err = write(fd, cmd, strlen(cmd));        
    } while (err < 0 && errno == EINTR);

    // read the result
    do {
        count_read = read(fd, buf, sizeof(buf) - 1);
    } while (count_read < 0 && errno != EINTR);

    if (count_read == ADB_RESPONSE_SIZE 
            && 0 == strncmp(buf, "OKAY", ADB_RESPONSE_SIZE)) {
        ret = 0;
    } else {
        /* what errno here? <shrug? */
        errno = ENETUNREACH;
        ret = -1;
    }

    free(cmd);
    
    return ret;
}

/**
 * Fills in *p_out_addr and returns 0 on success
 * Memset's *p_out_addr and returns -1 on fail
 */

int adb_networking_gethostbyname(const char *name, struct in_addr *p_out_addr)
{
    int fd;
    char *cmd = NULL;
    char buf[ADB_RESPONSE_SIZE + 1];
    int err;
    ssize_t count_read;
    
    fd = socket_loopback_client(ADB_PORT, SOCK_STREAM);

    if (fd < 0) {
        return -1;
    }

    // compose the command
    asprintf(&cmd, "dns:%s", name);

    // buf is now the ascii hex length of cmd
    snprintf(buf, sizeof(buf), "%04X", strlen(cmd));

    // write the 4-byte length
    do {
        err = write(fd, buf, 4);        
    } while (err < 0 && errno == EINTR);

    // write the command
    do {
        err = write(fd, cmd, strlen(cmd));        
    } while (err < 0 && errno == EINTR);

    // read the result
    do {
        count_read = read(fd, buf, ADB_RESPONSE_SIZE);
    } while (count_read < 0 && errno != EINTR);

    if (count_read != ADB_RESPONSE_SIZE 
            || 0 != strncmp(buf, "OKAY", ADB_RESPONSE_SIZE)) {
        goto error;
    }

    // read the actual IP address
    do {
        count_read = read(fd, &(p_out_addr->s_addr), sizeof(p_out_addr->s_addr));
    } while (count_read < 0 && errno != EINTR);

    if (count_read != 4) {
        goto error;
    }

    free(cmd);
    close(fd);
    return 0;
error:
    free(cmd);
    close(fd);
    memset(p_out_addr, 0, sizeof(struct in_addr));
    return -1;
}

