/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>

#include "backed_block.h"
#include "sparse_defs.h"

struct data_block {
	u32 block;
	u32 len;
	void *data;
	const char *filename;
	int64_t offset;
	struct data_block *next;
	u32 fill_val;
	u8 fill;
	u8 pad1;
	u16 pad2;
};

static struct data_block *data_blocks = NULL;
static struct data_block *last_used = NULL;

static void queue_db(struct data_block *new_db)
{
	struct data_block *db;

	if (data_blocks == NULL) {
		data_blocks = new_db;
		return;
	}

	if (data_blocks->block > new_db->block) {
		new_db->next = data_blocks;
		data_blocks = new_db;
		return;
	}

	/* Optimization: blocks are mostly queued in sequence, so save the
	   pointer to the last db that was added, and start searching from
	   there if the next block number is higher */
	if (last_used && new_db->block > last_used->block)
		db = last_used;
	else
		db = data_blocks;
	last_used = new_db;

	for (; db->next && db->next->block < new_db->block; db = db->next)
		;

	if (db->next == NULL) {
		db->next = new_db;
	} else {
		new_db->next = db->next;
		db->next = new_db;
	}
}

/* Queues a fill block of memory to be written to the specified data blocks */
void queue_fill_block(unsigned int fill_val, unsigned int len, unsigned int block)
{
	struct data_block *db = malloc(sizeof(struct data_block));
	if (db == NULL) {
		error_errno("malloc");
		return;
	}

	db->block = block;
	db->len = len;
	db->fill = 1;
	db->fill_val = fill_val;
	db->data = NULL;
	db->filename = NULL;
	db->next = NULL;

	queue_db(db);
}

/* Queues a block of memory to be written to the specified data blocks */
void queue_data_block(void *data, unsigned int len, unsigned int block)
{
	struct data_block *db = malloc(sizeof(struct data_block));
	if (db == NULL) {
		error_errno("malloc");
		return;
	}

	db->block = block;
	db->len = len;
	db->data = data;
	db->filename = NULL;
	db->fill = 0;
	db->next = NULL;

	queue_db(db);
}

/* Queues a chunk of a file on disk to be written to the specified data blocks */
void queue_data_file(const char *filename, int64_t offset, unsigned int len,
		unsigned int block)
{
	struct data_block *db = malloc(sizeof(struct data_block));
	if (db == NULL) {
		error_errno("malloc");
		return;
	}

	db->block = block;
	db->len = len;
	db->filename = strdup(filename);
	db->offset = offset;
	db->data = NULL;
	db->fill = 0;
	db->next = NULL;

	queue_db(db);
}

/* Iterates over the queued data blocks, calling data_func for each contiguous
   data block, and file_func for each contiguous file block */
void for_each_data_block(data_block_callback_t data_func,
	data_block_file_callback_t file_func,
	data_block_fill_callback_t fill_func, void *priv, unsigned int block_size)
{
	struct data_block *db;
	u32 last_block = 0;

	for (db = data_blocks; db; db = db->next) {
		if (db->block < last_block)
			error("data blocks out of order: %u < %u", db->block, last_block);
		last_block = db->block + DIV_ROUND_UP(db->len, block_size) - 1;

		if (db->filename)
			file_func(priv, (u64)db->block * block_size, db->filename, db->offset, db->len);
		else if (db->fill)
			fill_func(priv, (u64)db->block * block_size, db->fill_val, db->len);
		else
			data_func(priv, (u64)db->block * block_size, db->data, db->len);
	}
}

/* Frees the memory used by the linked list of data blocks */
void free_data_blocks()
{
	if (!data_blocks) return;
	struct data_block *db = data_blocks;
	while (db) {
		struct data_block *next = db->next;
		free((void*)db->filename);

                // There used to be a free() of db->data here, but it
		// made the function crash since queue_data_block() is
		// sometimes passed pointers it can't take ownership of
		// (like a pointer into the middle of an allocated
		// block).  It's not clear what the queue_data_block
		// contract is supposed to be, but we'd rather leak
		// memory than crash.

		free(db);
		db = next;
	}
	data_blocks = NULL;
	last_used = NULL;
}
