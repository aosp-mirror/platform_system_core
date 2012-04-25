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
	queue_data_block(s->backed_block_list, data, len, block);

	return 0;
}

int sparse_file_add_fill(struct sparse_file *s,
		uint32_t fill_val, unsigned int len, unsigned int block)
{
	queue_fill_block(s->backed_block_list, fill_val, len, block);

	return 0;
}

int sparse_file_add_file(struct sparse_file *s,
		const char *filename, int64_t file_offset, unsigned int len,
		unsigned int block)
{
	queue_data_file(s->backed_block_list, filename, file_offset, len, block);

	return 0;
}

struct count_chunks {
	unsigned int chunks;
	int64_t cur_ptr;
	unsigned int block_size;
};

static void count_data_block(void *priv, int64_t off, void *data, int len)
{
	struct count_chunks *count_chunks = priv;
	if (off > count_chunks->cur_ptr)
		count_chunks->chunks++;
	count_chunks->cur_ptr = off + ALIGN(len, count_chunks->block_size);
	count_chunks->chunks++;
}

static void count_fill_block(void *priv, int64_t off, unsigned int fill_val, int len)
{
	struct count_chunks *count_chunks = priv;
	if (off > count_chunks->cur_ptr)
		count_chunks->chunks++;
	count_chunks->cur_ptr = off + ALIGN(len, count_chunks->block_size);
	count_chunks->chunks++;
}

static void count_file_block(void *priv, int64_t off, const char *file,
		int64_t offset, int len)
{
	struct count_chunks *count_chunks = priv;
	if (off > count_chunks->cur_ptr)
		count_chunks->chunks++;
	count_chunks->cur_ptr = off + ALIGN(len, count_chunks->block_size);
	count_chunks->chunks++;
}

static int count_sparse_chunks(struct backed_block_list *b,
		unsigned int block_size, int64_t len)
{
	struct count_chunks count_chunks = {0, 0, block_size};

	for_each_data_block(b, count_data_block, count_file_block,
			count_fill_block, &count_chunks, block_size);

	if (count_chunks.cur_ptr != len)
		count_chunks.chunks++;

	return count_chunks.chunks;
}

static void ext4_write_data_block(void *priv, int64_t off, void *data, int len)
{
	write_data_block(priv, off, data, len);
}

static void ext4_write_fill_block(void *priv, int64_t off, unsigned int fill_val, int len)
{
	write_fill_block(priv, off, fill_val, len);
}

static void ext4_write_data_file(void *priv, int64_t off, const char *file,
		int64_t offset, int len)
{
	write_data_file(priv, off, file, offset, len);
}

int sparse_file_write(struct sparse_file *s, int fd, bool gz, bool sparse,
		bool crc)
{
	int chunks = count_sparse_chunks(s->backed_block_list, s->block_size,
			s->len);
	struct output_file *out = open_output_fd(fd, s->block_size, s->len,
			gz, sparse, chunks, crc);

	if (!out)
		return -ENOMEM;

	for_each_data_block(s->backed_block_list, ext4_write_data_block,
			ext4_write_data_file, ext4_write_fill_block, out, s->block_size);

	if (s->len)
		pad_output_file(out, s->len);

	close_output_file(out);

	return 0;
}
