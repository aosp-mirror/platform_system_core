/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "rpmb_mock"

#include "rpmb_protocol.h"

#include <assert.h>
#include <cutils/sockets.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <log/log.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* verbose is an int for getopt */
static int verbose = false;

#if OPENSSL_VERSION_NUMBER < 0x10100000L

HMAC_CTX* HMAC_CTX_new(void) {
    HMAC_CTX* ctx = malloc(sizeof(*ctx));
    if (ctx != NULL) {
        HMAC_CTX_init(ctx);
    }
    return ctx;
}

void HMAC_CTX_free(HMAC_CTX* ctx) {
    if (ctx != NULL) {
        HMAC_CTX_cleanup(ctx);
        free(ctx);
    }
}

#endif

#define MAX_WRITE_COUNTER (0xffffffff)

struct rpmb_data_header {
    uint32_t write_counter;
    uint16_t max_block;
    uint8_t pad1;
    uint8_t key_programmed;
    struct rpmb_key key;
    uint8_t pad[512 - 4 - 2 - 1 - 1 - sizeof(struct rpmb_key)];
};

#define MAX_PACKET_COUNT (8)

struct rpmb_dev_state {
    struct rpmb_data_header header;
    struct rpmb_packet cmd[MAX_PACKET_COUNT];
    struct rpmb_packet res[MAX_PACKET_COUNT];
    uint16_t cmd_count;
    uint16_t res_count;
    int data_fd;
};

/* TODO: move to common location */
static int rpmb_mac(struct rpmb_key key, struct rpmb_packet* packet, size_t packet_count,
                    struct rpmb_key* mac) {
    size_t i;
    int hmac_ret;
    unsigned int md_len;
    HMAC_CTX* hmac_ctx;

    hmac_ctx = HMAC_CTX_new();
    hmac_ret = HMAC_Init_ex(hmac_ctx, &key, sizeof(key), EVP_sha256(), NULL);
    if (!hmac_ret) {
        ALOGE("HMAC_Init_ex failed\n");
        goto err;
    }
    for (i = 0; i < packet_count; i++) {
        hmac_ret = HMAC_Update(hmac_ctx, packet[i].data, 284);
        if (!hmac_ret) {
            ALOGE("HMAC_Update failed\n");
            goto err;
        }
    }
    hmac_ret = HMAC_Final(hmac_ctx, mac->byte, &md_len);
    if (md_len != sizeof(mac->byte)) {
        ALOGE("bad md_len %d != %zd\n", md_len, sizeof(mac->byte));
        exit(1);
    }
    if (!hmac_ret) {
        ALOGE("HMAC_Final failed\n");
        goto err;
    }

err:
    HMAC_CTX_free(hmac_ctx);
    return hmac_ret ? 0 : -1;
}

static int rpmb_file_seek(struct rpmb_dev_state* s, uint16_t addr) {
    int ret;
    int pos = addr * RPMB_PACKET_DATA_SIZE + sizeof(s->header);
    ret = lseek(s->data_fd, pos, SEEK_SET);
    if (ret != pos) {
        ALOGE("rpmb_dev: seek to %d failed, got %d\n", pos, ret);
        return -1;
    }
    return 0;
}

static uint16_t rpmb_dev_program_key(struct rpmb_dev_state* s) {
    int ret;

    if (s->header.key_programmed) {
        return RPMB_RES_WRITE_FAILURE;
    }

    s->header.key = s->cmd[0].key_mac;
    s->header.key_programmed = 1;

    ret = lseek(s->data_fd, 0, SEEK_SET);
    if (ret) {
        ALOGE("rpmb_dev: Failed to seek rpmb data file\n");
        return RPMB_RES_WRITE_FAILURE;
    }

    ret = write(s->data_fd, &s->header, sizeof(s->header));
    if (ret != sizeof(s->header)) {
        ALOGE("rpmb_dev: Failed to write rpmb key: %d, %s\n", ret, strerror(errno));

        return RPMB_RES_WRITE_FAILURE;
    }

    return RPMB_RES_OK;
}

static uint16_t rpmb_dev_get_counter(struct rpmb_dev_state* s) {
    s->res[0].write_counter = rpmb_u32(s->header.write_counter);

    return RPMB_RES_OK;
}

static uint16_t rpmb_dev_data_write(struct rpmb_dev_state* s) {
    uint16_t addr = rpmb_get_u16(s->cmd[0].address);
    uint16_t block_count = s->cmd_count;
    uint32_t write_counter;
    int ret;

    if (s->header.write_counter == MAX_WRITE_COUNTER) {
        if (verbose) {
            ALOGE("rpmb_dev: Write counter expired\n");
        }
        return RPMB_RES_WRITE_FAILURE;
    }

    write_counter = rpmb_get_u32(s->cmd[0].write_counter);
    if (s->header.write_counter != write_counter) {
        if (verbose) {
            ALOGE("rpmb_dev: Invalid write counter %u. Expected: %u\n", write_counter,
                  s->header.write_counter);
        }
        return RPMB_RES_COUNT_FAILURE;
    }

    ret = rpmb_file_seek(s, addr);
    if (ret) {
        ALOGE("rpmb_dev: Failed to seek rpmb data file\n");
        return RPMB_RES_WRITE_FAILURE;
    }

    for (int i = 0; i < block_count; i++) {
        ret = write(s->data_fd, s->cmd[i].data, RPMB_PACKET_DATA_SIZE);
        if (ret != RPMB_PACKET_DATA_SIZE) {
            ALOGE("rpmb_dev: Failed to write rpmb data file: %d, %s\n", ret, strerror(errno));
            return RPMB_RES_WRITE_FAILURE;
        }
    }

    s->header.write_counter++;

    ret = lseek(s->data_fd, 0, SEEK_SET);
    if (ret) {
        ALOGE("rpmb_dev: Failed to seek rpmb data file\n");
        return RPMB_RES_WRITE_FAILURE;
    }

    ret = write(s->data_fd, &s->header.write_counter, sizeof(s->header.write_counter));
    if (ret != sizeof(s->header.write_counter)) {
        ALOGE("rpmb_dev: Failed to write rpmb write counter: %d, %s\n", ret, strerror(errno));

        return RPMB_RES_WRITE_FAILURE;
    }

    s->res[0].write_counter = rpmb_u32(s->header.write_counter);
    return RPMB_RES_OK;
}

static uint16_t rpmb_dev_data_read(struct rpmb_dev_state* s) {
    uint16_t addr;
    uint16_t block_count;
    int ret;

    addr = rpmb_get_u16(s->cmd[0].address);
    block_count = s->res_count;

    rpmb_file_seek(s, addr);

    for (int i = 0; i < block_count; i++) {
        ret = read(s->data_fd, s->res[i].data, RPMB_PACKET_DATA_SIZE);
        if (ret != 0 && ret != RPMB_PACKET_DATA_SIZE) {
            ALOGE("rpmb_dev: Failed to read rpmb data file: %d, %s\n", ret, strerror(errno));
            return RPMB_RES_READ_FAILURE;
        }
    }

    return RPMB_RES_OK;
}

struct rpmb_dev_cmd {
    uint16_t (*func)(struct rpmb_dev_state* s);
    uint16_t resp;
    bool key_mac_is_key;
    bool check_mac;
    bool check_result_read;
    bool check_key_programmed;
    bool check_addr;
    bool multi_packet_cmd;
    bool multi_packet_res;
    bool res_mac;
};

static struct rpmb_dev_cmd rpmb_dev_cmd_table[] = {
        [RPMB_REQ_PROGRAM_KEY] =
                {
                        .func = rpmb_dev_program_key,
                        .resp = RPMB_RESP_PROGRAM_KEY,
                        .key_mac_is_key = true,
                        .check_result_read = true,
                },
        [RPMB_REQ_GET_COUNTER] =
                {
                        .func = rpmb_dev_get_counter,
                        .resp = RPMB_RESP_GET_COUNTER,
                        .check_key_programmed = true,
                        .res_mac = true,
                },
        [RPMB_REQ_DATA_WRITE] =
                {
                        .func = rpmb_dev_data_write,
                        .resp = RPMB_RESP_DATA_WRITE,
                        .check_mac = true,
                        .check_result_read = true,
                        .check_key_programmed = true,
                        .check_addr = true,
                        .multi_packet_cmd = true,
                        .res_mac = true,
                },
        [RPMB_REQ_DATA_READ] =
                {
                        .func = rpmb_dev_data_read,
                        .resp = RPMB_RESP_DATA_READ,
                        .check_key_programmed = true,
                        .check_addr = true,
                        .multi_packet_res = true,
                        .res_mac = true,
                },
};

#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

static void rpmb_dev_process_cmd(struct rpmb_dev_state* s) {
    assert(s->cmd_count > 0);
    assert(s->res_count > 0);
    uint16_t req_resp = rpmb_get_u16(s->cmd[0].req_resp);
    uint16_t addr = rpmb_get_u16(s->cmd[0].address);
    uint16_t sub_req;
    uint16_t cmd_index = req_resp < countof(rpmb_dev_cmd_table) ? req_resp : 0;
    struct rpmb_dev_cmd* cmd = &rpmb_dev_cmd_table[cmd_index];
    uint16_t result = RPMB_RES_GENERAL_FAILURE;
    struct rpmb_key mac;
    uint16_t block_count = 0;

    if (cmd->check_result_read) {
        sub_req = rpmb_get_u16(s->cmd[s->cmd_count - 1].req_resp);
        if (sub_req != RPMB_REQ_RESULT_READ) {
            if (verbose) {
                ALOGE("rpmb_dev: Request %d, missing result read request, got %d, cmd_count %d\n",
                      req_resp, sub_req, s->cmd_count);
            }
            goto err;
        }
        assert(s->cmd_count > 1);
        s->cmd_count--;
    }

    if (cmd->check_mac) {
        if (rpmb_mac(s->header.key, s->cmd, s->cmd_count, &mac) != 0) {
            ALOGE("rpmb_dev: failed to caclulate mac\n");
            goto err;
        }
    } else if (cmd->key_mac_is_key) {
        mac = s->cmd[s->cmd_count - 1].key_mac;
    } else {
        memset(mac.byte, 0, sizeof(mac.byte));
    }

    if (memcmp(&mac, s->cmd[s->cmd_count - 1].key_mac.byte, sizeof(mac))) {
        if (verbose) {
            ALOGE("rpmb_dev: Request %d, invalid MAC, cmd_count %d\n", req_resp, s->cmd_count);
        }
        if (cmd->check_mac) {
            result = RPMB_RES_AUTH_FAILURE;
        }
        goto err;
    }

    if (cmd->multi_packet_cmd) {
        block_count = s->cmd_count;
    }
    if (cmd->multi_packet_res) {
        block_count = s->res_count;
    }

    if (cmd->check_addr && (addr + block_count > s->header.max_block + 1)) {
        if (verbose) {
            ALOGE("rpmb_dev: Request %d, invalid addr: 0x%x count 0x%x, Out of bounds. Max addr "
                  "0x%x\n",
                  req_resp, addr, block_count, s->header.max_block + 1);
        }
        result = RPMB_RES_ADDR_FAILURE;
        goto err;
    }
    if (!cmd->check_addr && addr) {
        if (verbose) {
            ALOGE("rpmb_dev: Request %d, invalid addr: 0x%x != 0\n", req_resp, addr);
        }
        goto err;
    }

    for (int i = 1; i < s->cmd_count; i++) {
        sub_req = rpmb_get_u16(s->cmd[i].req_resp);
        if (sub_req != req_resp) {
            if (verbose) {
                ALOGE("rpmb_dev: Request %d, sub-request mismatch, %d, at %d\n", req_resp, i,
                      sub_req);
            }
            goto err;
        }
    }
    if (!cmd->multi_packet_cmd && s->cmd_count != 1) {
        if (verbose) {
            ALOGE("rpmb_dev: Request %d, bad cmd count %d, expected 1\n", req_resp, s->cmd_count);
        }
        goto err;
    }
    if (!cmd->multi_packet_res && s->res_count != 1) {
        if (verbose) {
            ALOGE("rpmb_dev: Request %d, bad res count %d, expected 1\n", req_resp, s->res_count);
        }
        goto err;
    }

    if (cmd->check_key_programmed && !s->header.key_programmed) {
        if (verbose) {
            ALOGE("rpmb_dev: Request %d, key is not programmed\n", req_resp);
        }
        s->res[0].result = rpmb_u16(RPMB_RES_NO_AUTH_KEY);
        return;
    }

    if (!cmd->func) {
        if (verbose) {
            ALOGE("rpmb_dev: Unsupported request: %d\n", req_resp);
        }
        goto err;
    }

    result = cmd->func(s);

err:
    if (s->header.write_counter == MAX_WRITE_COUNTER) {
        result |= RPMB_RES_WRITE_COUNTER_EXPIRED;
    }

    for (int i = 0; i < s->res_count; i++) {
        s->res[i].nonce = s->cmd[0].nonce;
        s->res[i].address = rpmb_u16(addr);
        s->res[i].block_count = rpmb_u16(block_count);
        s->res[i].result = rpmb_u16(result);
        s->res[i].req_resp = rpmb_u16(cmd->resp);
    }
    if (cmd->res_mac) {
        rpmb_mac(s->header.key, s->res, s->res_count, &s->res[s->res_count - 1].key_mac);
    }
}

/*
 * Receives data until one of the following is true:
 * - The buffer is full (return will be len)
 * - The connection closed (return > 0, < len)
 * - An error occurred (return will be the negative error code from recv)
 */
ssize_t recv_until(int sock, void* dest_in, size_t len) {
    size_t bytes_recvd = 0;
    char* dest = dest_in;
    while (bytes_recvd < len) {
        ssize_t ret = recv(sock, dest, len - bytes_recvd, 0);
        if (ret < 0) {
            return ret;
        }
        dest += ret;
        bytes_recvd += ret;
        if (ret == 0) {
            break;
        }
    }
    return bytes_recvd;
}

/*
 * Handles an incoming connection to the rpmb daemon.
 * Returns 0 if the client disconnects without violating the protocol.
 * Returns a negative value if we terminated the connection abnormally.
 *
 * Arguments:
 *   conn_sock - an fd to send/recv on
 *   s - an initialized rpmb device
 */
int handle_conn(struct rpmb_dev_state* s, int conn_sock) {
    int ret;

    while (true) {
        memset(s->res, 0, sizeof(s->res));
        ret = recv_until(conn_sock, &s->res_count, sizeof(s->res_count));

        /*
         * Disconnected while not in the middle of anything.
         */
        if (ret <= 0) {
            return 0;
        }

        if (s->res_count > MAX_PACKET_COUNT) {
            ALOGE("rpmb_dev: Receive count too large: %d\n", s->res_count);
            return -1;
        }
        if (s->res_count <= 0) {
            ALOGE("rpmb_dev: Receive count too small: %d\n", s->res_count);
            return -1;
        }

        ret = recv_until(conn_sock, &s->cmd_count, sizeof(s->cmd_count));
        if (ret != sizeof(s->cmd_count)) {
            ALOGE("rpmb_dev: Failed to read cmd_count");
            return -1;
        }

        if (s->cmd_count == 0) {
            ALOGE("rpmb_dev: Must contain at least one command\n");
            return -1;
        }

        if (s->cmd_count > MAX_PACKET_COUNT) {
            ALOGE("rpmb_dev: Command count is too large\n");
            return -1;
        }

        size_t cmd_size = s->cmd_count * sizeof(s->cmd[0]);
        ret = recv_until(conn_sock, s->cmd, cmd_size);
        if (ret != (int)cmd_size) {
            ALOGE("rpmb_dev: Failed to read command: "
                  "cmd_size: %zu ret: %d, %s\n",
                  cmd_size, ret, strerror(errno));
            return -1;
        }

        rpmb_dev_process_cmd(s);

        size_t resp_size = sizeof(s->res[0]) * s->res_count;
        ret = send(conn_sock, s->res, resp_size, 0);
        if (ret != (int)resp_size) {
            ALOGE("rpmb_dev: Failed to send response: %d, %s\n", ret, strerror(errno));
            return -1;
        }
    }
}

void usage(const char* argv0) {
    fprintf(stderr, "Usage: %s [-d|--dev] <datafile> [--sock] <socket_path>\n", argv0);
    fprintf(stderr, "or:    %s [-d|--dev] <datafile> [--size <size>] [--key key]\n", argv0);
}

int main(int argc, char** argv) {
    struct rpmb_dev_state s;
    int ret;
    int cmdres_sock;
    struct sockaddr_un cmdres_sockaddr;
    const char* data_file_name = NULL;
    const char* socket_path = NULL;
    int open_flags;
    int init = false;

    struct option long_options[] = {{"size", required_argument, 0, 0},
                                    {"key", required_argument, 0, 0},
                                    {"sock", required_argument, 0, 0},
                                    {"dev", required_argument, 0, 'd'},
                                    {"init", no_argument, &init, true},
                                    {"verbose", no_argument, &verbose, true},
                                    {0, 0, 0, 0}};

    memset(&s.header, 0, sizeof(s.header));

    while (1) {
        int c;
        int option_index = 0;
        c = getopt_long(argc, argv, "d:", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            /* long args */
            case 0:
                switch (option_index) {
                    /* size */
                    case 0:
                        s.header.max_block = atoi(optarg) - 1;
                        break;
                    /* key */
                    case 1:
                        for (size_t i = 0; i < sizeof(s.header.key.byte); i++) {
                            if (!optarg) {
                                break;
                            }
                            s.header.key.byte[i] = strtol(optarg, &optarg, 16);
                            s.header.key_programmed = 1;
                        }
                        break;
                    /* sock */
                    case 2:
                        socket_path = optarg;
                        break;
                }
                break;
            /* dev */
            case 'd':
                data_file_name = optarg;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    /*
     * We always need a data file, and at exactly one of --init or --sock
     * must be specified.
     */
    if (!data_file_name || (!init == !socket_path)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /*
     * If the file is already initialized, exit early.
     */
    if (init && !access(data_file_name, F_OK)) {
        return EXIT_SUCCESS;
    }

    open_flags = O_RDWR | O_SYNC;
    if (init) {
        open_flags |= O_CREAT | O_TRUNC;
    }
    s.data_fd = open(data_file_name, open_flags, S_IWUSR | S_IRUSR);
    if (s.data_fd < 0) {
        ALOGE("rpmb_dev: Failed to open rpmb data file, %s: %s\n", data_file_name, strerror(errno));
        return EXIT_FAILURE;
    }

    if (init) {
        /* Create new rpmb data file */
        if (s.header.max_block == 0) {
            s.header.max_block = 512 - 1;
        }
        ret = write(s.data_fd, &s.header, sizeof(s.header));
        if (ret != sizeof(s.header)) {
            ALOGE("rpmb_dev: Failed to write rpmb data file: %d, %s\n", ret, strerror(errno));
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    ret = read(s.data_fd, &s.header, sizeof(s.header));
    if (ret != sizeof(s.header)) {
        ALOGE("rpmb_dev: Failed to read rpmb data file: %d, %s\n", ret, strerror(errno));
        return EXIT_FAILURE;
    }

    cmdres_sock = android_get_control_socket(socket_path);
    if (cmdres_sock < 0) {
        ALOGW("android_get_control_socket(%s) failed, fall back to create it\n", socket_path);
        cmdres_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (cmdres_sock < 0) {
            ALOGE("rpmb_dev: Failed to create command/response socket: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        cmdres_sockaddr.sun_family = AF_UNIX;
        strncpy(cmdres_sockaddr.sun_path, socket_path, sizeof(cmdres_sockaddr.sun_path));

        ret = bind(cmdres_sock, (struct sockaddr*)&cmdres_sockaddr, sizeof(struct sockaddr_un));
        if (ret < 0) {
            ALOGE("rpmb_dev: Failed to bind command/response socket: %s: %s\n", socket_path,
                  strerror(errno));
            return EXIT_FAILURE;
        }
    }

    ret = listen(cmdres_sock, 1);
    if (ret < 0) {
        ALOGE("rpmb_dev: Failed to listen on command/response socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    while (true) {
        int conn_sock = accept(cmdres_sock, NULL, NULL);
        if (conn_sock < 0) {
            ALOGE("rpmb_dev: Could not accept connection: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        ret = handle_conn(&s, conn_sock);
        close(conn_sock);
        if (ret) {
            ALOGE("rpmb_dev: Connection terminated: %d", ret);
        }
    }
}
