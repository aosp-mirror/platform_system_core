/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <assert.h>
#include <stdlib.h>

#include <sparse/sparse.h>

#include "sparse_file.h"

#include "output_file.h"
#include "backed_block.h"
#include "sparse_defs.h"

struct sparse_file *sparse_file_new(unsigned int block_size, int64_t len)
{
	struct sparse_file *s = calloc(sizeof(struct sparse_file), 1);
	if (!s) {
		return NULL;
	}

	s->backed_block_list = backed_block_list_new();
	if (!s->backed_block_list) {
		free(s);
		return NULL;
	}

	s->block_size = block_size;
	s->len = len;

	return s;
}

void sparse_file_destroy(struct sparse_file *s)
{
	backed_block_list_destroy(s->backed_block_list);
	free(s);
}

int sparse_file_add_data(struct sparse_file *s,
		void *data, unsigned int len, unsigned int block)
{
	return backed_block_add_data(s->backed_block_list, data, len, block);
}

int sparse_file_add_fill(struct sparse_file *s,
		uint32_t fill_val, unsigned int len, unsigned int block)
{
	return backed_block_add_fill(s->backed_block_list, fill_val, len, block);
}

int sparse_file_add_file(struct sparse_file *s,
		const char *filename, int64_t file_offset, unsigned int len,
		unsigned int block)
{
	return backed_block_add_file(s->backed_block_list, filename, file_offset,
			len, block);
}

int sparse_file_add_fd(struct sparse_file *s,
		int fd, int64_t file_offset, unsigned int len, unsigned int block)
{
	return backed_block_add_fd(s->backed_block_list, fd, file_offset,
			len, block);
}
unsigned int sparse_count_chunks(struct sparse_file *s)
{
	struct backed_block *bb;
	unsigned int last_block = 0;
	unsigned int chunks = 0;

	for (bb = backed_block_iter_new(s->backed_block_list); bb;
			bb = backed_block_iter_next(bb)) {
		if (backed_block_block(bb) > last_block) {
			/* If there is a gap between chunks, add a skip chunk */
			chunks++;
		}
		chunks++;
		last_block = backed_block_block(bb) +
				DIV_ROUND_UP(backed_block_len(bb), s->block_size);
	}
	if (last_block < DIV_ROUND_UP(s->len, s->block_size)) {
		chunks++;
	}

	return chunks;
}

int sparse_file_write(struct sparse_file *s, int fd, bool gz, bool sparse,
		bool crc)
{
	struct backed_block *bb;
	unsigned int last_block = 0;
	int64_t pad;
	int chunks;
	struct output_file *out;

	chunks = sparse_count_chunks(s);
	out = open_output_fd(fd, s->block_size, s->len, gz, sparse, chunks, crc);

	if (!out)
		return -ENOMEM;

	for (bb = backed_block_iter_new(s->backed_block_list); bb;
			bb = backed_block_iter_next(bb)) {
		if (backed_block_block(bb) > last_block) {
			unsigned int blocks = backed_block_block(bb) - last_block;
			write_skip_chunk(out, (int64_t)blocks * s->block_size);
		}
		switch (backed_block_type(bb)) {
		case BACKED_BLOCK_DATA:
			write_data_chunk(out, backed_block_len(bb), backed_block_data(bb));
			break;
		case BACKED_BLOCK_FILE:
			write_file_chunk(out, backed_block_len(bb),
					backed_block_filename(bb), backed_block_file_offset(bb));
			break;
		case BACKED_BLOCK_FD:
			write_fd_chunk(out, backed_block_len(bb),
					backed_block_fd(bb), backed_block_file_offset(bb));
			break;
		case BACKED_BLOCK_FILL:
			write_fill_chunk(out, backed_block_len(bb),
					backed_block_fill_val(bb));
			break;
		}
		last_block = backed_block_block(bb) +
				DIV_ROUND_UP(backed_block_len(bb), s->block_size);
	}

	pad = s->len - last_block * s->block_size;
	assert(pad >= 0);
	if (pad > 0) {
		write_skip_chunk(out, pad);
	}

	close_output_file(out);

	return 0;
}

void sparse_file_verbose(struct sparse_file *s)
{
	s->verbose = true;
}
