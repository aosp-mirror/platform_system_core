/*
 *  Copyright 2018 Google, Inc
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

#ifndef _LMKD_H_
#define _LMKD_H_

#include <arpa/inet.h>
#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

/*
 * Supported LMKD commands
 */
enum lmk_cmd {
    LMK_TARGET = 0,  /* Associate minfree with oom_adj_score */
    LMK_PROCPRIO,    /* Register a process and set its oom_adj_score */
    LMK_PROCREMOVE,  /* Unregister a process */
    LMK_PROCPURGE,   /* Purge all registered processes */
};

/*
 * Max number of targets in LMK_TARGET command.
 */
#define MAX_TARGETS 6

/*
 * Max packet length in bytes.
 * Longest packet is LMK_TARGET followed by MAX_TARGETS
 * of minfree and oom_adj_score values
 */
#define CTRL_PACKET_MAX_SIZE (sizeof(int) * (MAX_TARGETS * 2 + 1))

/* LMKD packet - first int is lmk_cmd followed by payload */
typedef int LMKD_CTRL_PACKET[CTRL_PACKET_MAX_SIZE / sizeof(int)];

/* Get LMKD packet command */
inline enum lmk_cmd lmkd_pack_get_cmd(LMKD_CTRL_PACKET pack) {
    return (enum lmk_cmd)ntohl(pack[0]);
}

/* LMK_TARGET packet payload */
struct lmk_target {
    int minfree;
    int oom_adj_score;
};

/*
 * For LMK_TARGET packet get target_idx-th payload.
 * Warning: no checks performed, caller should ensure valid parameters.
 */
inline void lmkd_pack_get_target(LMKD_CTRL_PACKET packet,
                                 int target_idx, struct lmk_target *target) {
    target->minfree = ntohl(packet[target_idx * 2 + 1]);
    target->oom_adj_score = ntohl(packet[target_idx * 2 + 2]);
}

/*
 * Prepare LMK_TARGET packet and return packet size in bytes.
 * Warning: no checks performed, caller should ensure valid parameters.
 */
inline size_t lmkd_pack_set_target(LMKD_CTRL_PACKET packet,
                                   struct lmk_target *targets,
                                   size_t target_cnt) {
    int idx = 0;
    packet[idx++] = htonl(LMK_TARGET);
    while (target_cnt) {
        packet[idx++] = htonl(targets->minfree);
        packet[idx++] = htonl(targets->oom_adj_score);
        targets++;
        target_cnt--;
    }
    return idx * sizeof(int);
}

/* LMK_PROCPRIO packet payload */
struct lmk_procprio {
    pid_t pid;
    uid_t uid;
    int oomadj;
};

/*
 * For LMK_PROCPRIO packet get its payload.
 * Warning: no checks performed, caller should ensure valid parameters.
 */
inline void lmkd_pack_get_procprio(LMKD_CTRL_PACKET packet,
                                   struct lmk_procprio *params) {
    params->pid = (pid_t)ntohl(packet[1]);
    params->uid = (uid_t)ntohl(packet[2]);
    params->oomadj = ntohl(packet[3]);
}

/*
 * Prepare LMK_PROCPRIO packet and return packet size in bytes.
 * Warning: no checks performed, caller should ensure valid parameters.
 */
inline size_t lmkd_pack_set_procprio(LMKD_CTRL_PACKET packet,
                                   struct lmk_procprio *params) {
    packet[0] = htonl(LMK_PROCPRIO);
    packet[1] = htonl(params->pid);
    packet[2] = htonl(params->uid);
    packet[3] = htonl(params->oomadj);
    return 4 * sizeof(int);
}

/* LMK_PROCREMOVE packet payload */
struct lmk_procremove {
    pid_t pid;
};

/*
 * For LMK_PROCREMOVE packet get its payload.
 * Warning: no checks performed, caller should ensure valid parameters.
 */
inline void lmkd_pack_get_procremove(LMKD_CTRL_PACKET packet,
                                   struct lmk_procremove *params) {
    params->pid = (pid_t)ntohl(packet[1]);
}

/*
 * Prepare LMK_PROCREMOVE packet and return packet size in bytes.
 * Warning: no checks performed, caller should ensure valid parameters.
 */
inline size_t lmkd_pack_set_procremove(LMKD_CTRL_PACKET packet,
                                   struct lmk_procprio *params) {
    packet[0] = htonl(LMK_PROCREMOVE);
    packet[1] = htonl(params->pid);
    return 2 * sizeof(int);
}

/*
 * Prepare LMK_PROCPURGE packet and return packet size in bytes.
 * Warning: no checks performed, caller should ensure valid parameters.
 */
inline size_t lmkd_pack_set_procpurge(LMKD_CTRL_PACKET packet) {
    packet[0] = htonl(LMK_PROCPURGE);
    return sizeof(int);
}

__END_DECLS

#endif /* _LMKD_H_ */
