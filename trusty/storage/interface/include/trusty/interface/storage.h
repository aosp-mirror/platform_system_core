/*
 * Copyright (C) 2015-2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

/*
 * Storage port names
 * @STORAGE_CLIENT_TD_PORT:     Port used by clients that require tamper and
 *                              rollback detection.
 * @STORAGE_CLIENT_TDEA_PORT:   Port used by clients that require storage before
 *                              the non-secure os has booted.
 * @STORAGE_CLIENT_TP_PORT:     Port used by clients that require tamper proof
 *                              storage. Note that non-secure code can prevent
                                read and write operations from succeeding, but
                                it cannot modify on-disk data.
 * @STORAGE_DISK_PROXY_PORT:    Port used by non-secure proxy server
 */
#define STORAGE_CLIENT_TD_PORT     "com.android.trusty.storage.client.td"
#define STORAGE_CLIENT_TDEA_PORT   "com.android.trusty.storage.client.tdea"
#define STORAGE_CLIENT_TP_PORT     "com.android.trusty.storage.client.tp"
#define STORAGE_DISK_PROXY_PORT    "com.android.trusty.storage.proxy"

enum storage_cmd {
	STORAGE_REQ_SHIFT = 1,
	STORAGE_RESP_BIT  = 1,

	STORAGE_RESP_MSG_ERR   = STORAGE_RESP_BIT,

	STORAGE_FILE_DELETE    = 1 << STORAGE_REQ_SHIFT,
	STORAGE_FILE_OPEN      = 2 << STORAGE_REQ_SHIFT,
	STORAGE_FILE_CLOSE     = 3 << STORAGE_REQ_SHIFT,
	STORAGE_FILE_READ      = 4 << STORAGE_REQ_SHIFT,
	STORAGE_FILE_WRITE     = 5 << STORAGE_REQ_SHIFT,
	STORAGE_FILE_GET_SIZE  = 6 << STORAGE_REQ_SHIFT,
	STORAGE_FILE_SET_SIZE  = 7 << STORAGE_REQ_SHIFT,

	STORAGE_RPMB_SEND      = 8 << STORAGE_REQ_SHIFT,

	/* transaction support */
	STORAGE_END_TRANSACTION = 9 << STORAGE_REQ_SHIFT,
};

/**
 * enum storage_err - error codes for storage protocol
 * @STORAGE_NO_ERROR:           all OK
 * @STORAGE_ERR_GENERIC:        unknown error. Can occur when there's an internal server
 *                              error, e.g. the server runs out of memory or is in a bad state.
 * @STORAGE_ERR_NOT_VALID:      input not valid. May occur if the arguments passed
 *                              into the command are not valid, for example if the file handle
 *                              passed in is not a valid one.
 * @STORAGE_ERR_UNIMPLEMENTED:  the command passed in is not recognized
 * @STORAGE_ERR_ACCESS:         the file is not accessible in the requested mode
 * @STORAGE_ERR_NOT_FOUND:      the file was not found
 * @STORAGE_ERR_EXIST           the file exists when it shouldn't as in with OPEN_CREATE | OPEN_EXCLUSIVE.
 * @STORAGE_ERR_TRANSACT        returned by various operations to indicate that current transaction
 *                              is in error state. Such state could be only cleared by sending
 *                              STORAGE_END_TRANSACTION message.
 * @STORAGE_ERR_SYNC_FAILURE    indicates that the current operation failed to sync
 *                              to disk. Only returned if STORAGE_MSG_FLAG_PRE_COMMIT or
 *                              STORAGE_MSG_FLAG_POST_COMMIT was set for the request.
 */
enum storage_err {
	STORAGE_NO_ERROR          = 0,
	STORAGE_ERR_GENERIC       = 1,
	STORAGE_ERR_NOT_VALID     = 2,
	STORAGE_ERR_UNIMPLEMENTED = 3,
	STORAGE_ERR_ACCESS        = 4,
	STORAGE_ERR_NOT_FOUND     = 5,
	STORAGE_ERR_EXIST         = 6,
	STORAGE_ERR_TRANSACT      = 7,
	STORAGE_ERR_SYNC_FAILURE  = 8,
};

/**
 * storage_delete_flag - flags for controlling delete semantics
 */
enum storage_file_delete_flag {
	STORAGE_FILE_DELETE_MASK = 0,
};

/**
 * storage_file_flag - Flags to control 'open' semantics.
 * @STORAGE_FILE_OPEN_CREATE:           if this file does not exist, create it.
 * @STORAGE_FILE_OPEN_CREATE_EXCLUSIVE: causes STORAGE_FILE_OPEN_CREATE to fail if the file
 *                                      already exists. Only meaningful if used in combination
 *                                      with STORAGE_FILE_OPEN_CREATE.
 * @STORAGE_FILE_OPEN_TRUNCATE:         if this file already exists, discard existing content
 *                                      and open it as a new file. No change in semantics if the
 *                                      file does not exist.
 * @STORAGE_FILE_OPEN_MASK:             mask for all open flags supported in current protocol.
 *                                      All other bits must be set to 0.
 */
enum storage_file_open_flag {
	STORAGE_FILE_OPEN_CREATE             = (1 << 0),
	STORAGE_FILE_OPEN_CREATE_EXCLUSIVE   = (1 << 1),
	STORAGE_FILE_OPEN_TRUNCATE           = (1 << 2),
	STORAGE_FILE_OPEN_MASK               = STORAGE_FILE_OPEN_CREATE |
					       STORAGE_FILE_OPEN_TRUNCATE |
					       STORAGE_FILE_OPEN_CREATE_EXCLUSIVE,
};

/**
 * enum storage_msg_flag - protocol-level flags in struct storage_msg
 * @STORAGE_MSG_FLAG_BATCH:                 if set, command belongs to a batch transaction.
 *                                          No response will be sent by the server until
 *                                          it receives a command with this flag unset, at
 *                                          which point a cumulative result for all messages
 *                                          sent with STORAGE_MSG_FLAG_BATCH will be sent.
 *                                          This is only supported by the non-secure disk proxy
 *                                          server.
 * @STORAGE_MSG_FLAG_PRE_COMMIT:            if set, indicates that server need to commit
 *                                          pending changes before processing this message.
 * @STORAGE_MSG_FLAG_POST_COMMIT:           if set, indicates that server need to commit
 *                                          pending changes after processing this message.
 * @STORAGE_MSG_FLAG_TRANSACT_COMPLETE:     if set, indicates that server need to commit
 *                                          current transaction after processing this message.
 *                                          It is an alias for STORAGE_MSG_FLAG_POST_COMMIT.
 * @STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT: if set, indicates that server needs to ensure
 *                                          that there is not a pending checkpoint for
 *                                          userdata before processing this message.
 */
enum storage_msg_flag {
    STORAGE_MSG_FLAG_BATCH = 0x1,
    STORAGE_MSG_FLAG_PRE_COMMIT = 0x2,
    STORAGE_MSG_FLAG_POST_COMMIT = 0x4,
    STORAGE_MSG_FLAG_TRANSACT_COMPLETE = STORAGE_MSG_FLAG_POST_COMMIT,
    STORAGE_MSG_FLAG_PRE_COMMIT_CHECKPOINT = 0x8,
};

/*
 * The following declarations are the message-specific contents of
 * the 'payload' element inside struct storage_msg.
 */

/**
 * struct storage_file_delete_req - request format for STORAGE_FILE_DELETE
 * @flags: currently unused, must be set to 0.
 * @name:  the name of the file
 */
struct storage_file_delete_req {
	uint32_t flags;
	char name[0];
};

/**
 * struct storage_file_open_req - request format for STORAGE_FILE_OPEN
 * @flags: any of enum storage_file_flag or'ed together
 * @name:  the name of the file
 */
struct storage_file_open_req {
	uint32_t flags;
	char     name[0];
};

/**
 * struct storage_file_open_resp - response format for STORAGE_FILE_OPEN
 * @handle: opaque handle to the opened file. Only present on success.
 */
struct storage_file_open_resp {
	uint32_t handle;
};

/**
 * struct storage_file_close_req - request format for STORAGE_FILE_CLOSE
 * @handle: the handle for the file to close
 */
struct storage_file_close_req {
	uint32_t handle;
};

/**
 * struct storage_file_read_req - request format for STORAGE_FILE_READ
 * @handle: the handle for the file from which to read
 * @size:   the quantity of bytes to read from the file
 * @offset: the offset in the file from whence to read
 */
struct storage_file_read_req {
	uint32_t handle;
	uint32_t size;
	uint64_t offset;
};

/**
 * struct storage_file_read_resp - response format for STORAGE_FILE_READ
 * @data: beginning of data retrieved from file
 */
struct storage_file_read_resp {
	uint8_t data[0];
};

/**
 * struct storage_file_write_req - request format for STORAGE_FILE_WRITE
 * @handle:     the handle for the file to write to
 * @offset:     the offset in the file from whence to write
 * @__reserved: unused, must be set to 0.
 * @data:       beginning of the data to be written
 */
struct storage_file_write_req {
	uint64_t offset;
	uint32_t handle;
	uint32_t __reserved;
	uint8_t  data[0];
};

/**
 * struct storage_file_get_size_req - request format for STORAGE_FILE_GET_SIZE
 * @handle: handle for which the size is requested
 */
struct storage_file_get_size_req {
	uint32_t handle;
};

/**
 * struct storage_file_get_size_resp - response format for STORAGE_FILE_GET_SIZE
 * @size:   the size of the file
 */
struct storage_file_get_size_resp {
	uint64_t size;
};

/**
 * struct storage_file_set_size_req - request format for STORAGE_FILE_SET_SIZE
 * @handle: the file handle
 * @size:   the desired size of the file
 */
struct storage_file_set_size_req {
	uint64_t size;
	uint32_t handle;
};

/**
 * struct storage_rpmb_send_req - request format for STORAGE_RPMB_SEND
 * @reliable_write_size:        size in bytes of reliable write region
 * @write_size:                 size in bytes of write region
 * @read_size:                  number of bytes to read for a read request
 * @__reserved:                 unused, must be set to 0
 * @payload:                    start of reliable write region, followed by
 *                              write region.
 *
 * Only used in proxy<->server interface.
 */
struct storage_rpmb_send_req {
	uint32_t reliable_write_size;
	uint32_t write_size;
	uint32_t read_size;
	uint32_t __reserved;
	uint8_t  payload[0];
};

/**
 * struct storage_rpmb_send_resp: response type for STORAGE_RPMB_SEND
 * @data: the data frames frames retrieved from the MMC.
 */
struct storage_rpmb_send_resp {
	uint8_t data[0];
};

/**
 * struct storage_msg - generic req/resp format for all storage commands
 * @cmd:        one of enum storage_cmd
 * @op_id:      client chosen operation identifier for an instance
 *              of a command or atomic grouping of commands (transaction).
 * @flags:      one or many of enum storage_msg_flag or'ed together.
 * @size:       total size of the message including this header
 * @result:     one of enum storage_err
 * @__reserved: unused, must be set to 0.
 * @payload:    beginning of command specific message format
 */
struct storage_msg {
	uint32_t cmd;
	uint32_t op_id;
	uint32_t flags;
	uint32_t size;
	int32_t  result;
	uint32_t __reserved;
	uint8_t  payload[0];
};

