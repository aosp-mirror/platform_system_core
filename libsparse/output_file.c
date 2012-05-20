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

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include "output_file.h"
#include "sparse_format.h"
#include "sparse_crc32.h"

#ifndef USE_MINGW
#include <sys/mman.h>
#define O_BINARY 0
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define lseek64 lseek
#define ftruncate64 ftruncate
#define mmap64 mmap
#define off64_t off_t
#endif

#ifdef __BIONIC__
extern void*  __mmap2(void *, size_t, int, int, int, off_t);
static inline void *mmap64(void *addr, size_t length, int prot, int flags,
        int fd, off64_t offset)
{
    return __mmap2(addr, length, prot, flags, fd, offset >> 12);
}
#endif

#define SPARSE_HEADER_MAJOR_VER 1
#define SPARSE_HEADER_MINOR_VER 0
#define SPARSE_HEADER_LEN       (sizeof(sparse_header_t))
#define CHUNK_HEADER_LEN (sizeof(chunk_header_t))

struct output_file_ops {
	int (*seek)(struct output_file *, int64_t);
	int (*write)(struct output_file *, u8 *, int);
	void (*close)(struct output_file *);
};

struct output_file {
	int fd;
	gzFile gz_fd;
	bool close_fd;
	int sparse;
	int64_t cur_out_ptr;
	u32 chunk_cnt;
	u32 crc32;
	struct output_file_ops *ops;
	int use_crc;
	unsigned int block_size;
	int64_t len;
};

static int file_seek(struct output_file *out, int64_t off)
{
	off64_t ret;

	ret = lseek64(out->fd, off, SEEK_SET);
	if (ret < 0) {
		error_errno("lseek64");
		return -1;
	}
	return 0;
}

static int file_write(struct output_file *out, u8 *data, int len)
{
	int ret;
	ret = write(out->fd, data, len);
	if (ret < 0) {
		error_errno("write");
		return -1;
	} else if (ret < len) {
		error("incomplete write");
		return -1;
	}

	return 0;
}

static void file_close(struct output_file *out)
{
	if (out->close_fd) {
		close(out->fd);
	}
}


static struct output_file_ops file_ops = {
	.seek = file_seek,
	.write = file_write,
	.close = file_close,
};

static int gz_file_seek(struct output_file *out, int64_t off)
{
	off64_t ret;

	ret = gzseek(out->gz_fd, off, SEEK_SET);
	if (ret < 0) {
		error_errno("gzseek");
		return -1;
	}
	return 0;
}

static int gz_file_write(struct output_file *out, u8 *data, int len)
{
	int ret;
	ret = gzwrite(out->gz_fd, data, len);
	if (ret < 0) {
		error_errno("gzwrite");
		return -1;
	} else if (ret < len) {
		error("incomplete gzwrite");
		return -1;
	}

	return 0;
}

static void gz_file_close(struct output_file *out)
{
	gzclose(out->gz_fd);
}

static struct output_file_ops gz_file_ops = {
	.seek = gz_file_seek,
	.write = gz_file_write,
	.close = gz_file_close,
};

static sparse_header_t sparse_header = {
	.magic = SPARSE_HEADER_MAGIC,
	.major_version = SPARSE_HEADER_MAJOR_VER,
	.minor_version = SPARSE_HEADER_MINOR_VER,
	.file_hdr_sz = SPARSE_HEADER_LEN,
	.chunk_hdr_sz = CHUNK_HEADER_LEN,
	.blk_sz = 0,
	.total_blks = 0,
	.total_chunks = 0,
	.image_checksum = 0
};

static u8 *zero_buf;

static int emit_skip_chunk(struct output_file *out, u64 skip_len)
{
	chunk_header_t chunk_header;
	int ret, chunk;

	//DBG printf("skip chunk: 0x%llx bytes\n", skip_len);

	if (skip_len % out->block_size) {
		error("don't care size %llu is not a multiple of the block size %u",
				skip_len, out->block_size);
		return -1;
	}

	/* We are skipping data, so emit a don't care chunk. */
	chunk_header.chunk_type = CHUNK_TYPE_DONT_CARE;
	chunk_header.reserved1 = 0;
	chunk_header.chunk_sz = skip_len / out->block_size;
	chunk_header.total_sz = CHUNK_HEADER_LEN;
	ret = out->ops->write(out, (u8 *)&chunk_header, sizeof(chunk_header));
	if (ret < 0)
		return -1;

	out->cur_out_ptr += skip_len;
	out->chunk_cnt++;

	return 0;
}

static int write_chunk_fill(struct output_file *out, int64_t off, u32 fill_val, int len)
{
	chunk_header_t chunk_header;
	int rnd_up_len, zero_len, count;
	int ret;
	unsigned int i;
	u32 fill_buf[4096/sizeof(u32)]; /* Maximum size of a block */

	/* We can assume that all the chunks to be written are in
	 * ascending order, block-size aligned, and non-overlapping.
	 * So, if the offset is less than the current output pointer,
	 * throw an error, and if there is a gap, emit a "don't care"
	 * chunk.  The first write (of the super block) may not be
	 * blocksize aligned, so we need to deal with that too.
	 */
	//DBG printf("write chunk: offset 0x%llx, length 0x%x bytes\n", off, len);

	if (off < out->cur_out_ptr) {
		error("offset %llu is less than the current output offset %llu",
				off, out->cur_out_ptr);
		return -1;
	}

	if (off > out->cur_out_ptr) {
		emit_skip_chunk(out, off - out->cur_out_ptr);
	}

	if (off % out->block_size) {
		error("write chunk offset %llu is not a multiple of the block size %u",
				off, out->block_size);
		return -1;
	}

	if (off != out->cur_out_ptr) {
		error("internal error, offset accounting screwy in write_chunk_raw()");
		return -1;
	}

	/* Round up the file length to a multiple of the block size */
	rnd_up_len = (len + (out->block_size - 1)) & (~(out->block_size -1));

	/* Finally we can safely emit a chunk of data */
	chunk_header.chunk_type = CHUNK_TYPE_FILL;
	chunk_header.reserved1 = 0;
	chunk_header.chunk_sz = rnd_up_len / out->block_size;
	chunk_header.total_sz = CHUNK_HEADER_LEN + sizeof(fill_val);
	ret = out->ops->write(out, (u8 *)&chunk_header, sizeof(chunk_header));

	if (ret < 0)
		return -1;
	ret = out->ops->write(out, (u8 *)&fill_val, sizeof(fill_val));
	if (ret < 0)
		return -1;

	if (out->use_crc) {
                /* Initialize fill_buf with the fill_val */
		for (i = 0; i < (out->block_size / sizeof(u32)); i++) {
			fill_buf[i] = fill_val;
		}

		count = chunk_header.chunk_sz;
		while (count) {
			out->crc32 = sparse_crc32(out->crc32, fill_buf, out->block_size);
			count--;
		}
	}

	out->cur_out_ptr += rnd_up_len;
	out->chunk_cnt++;

	return 0;
}

static int write_chunk_raw(struct output_file *out, int64_t off, u8 *data, int len)
{
	chunk_header_t chunk_header;
	int rnd_up_len, zero_len;
	int ret;

	/* We can assume that all the chunks to be written are in
	 * ascending order, block-size aligned, and non-overlapping.
	 * So, if the offset is less than the current output pointer,
	 * throw an error, and if there is a gap, emit a "don't care"
	 * chunk.  The first write (of the super block) may not be
	 * blocksize aligned, so we need to deal with that too.
	 */
	//DBG printf("write chunk: offset 0x%llx, length 0x%x bytes\n", off, len);

	if (off < out->cur_out_ptr) {
		error("offset %llu is less than the current output offset %llu",
				off, out->cur_out_ptr);
		return -1;
	}

	if (off > out->cur_out_ptr) {
		emit_skip_chunk(out, off - out->cur_out_ptr);
	}

	if (off % out->block_size) {
		error("write chunk offset %llu is not a multiple of the block size %u",
				off, out->block_size);
		return -1;
	}

	if (off != out->cur_out_ptr) {
		error("internal error, offset accounting screwy in write_chunk_raw()");
		return -1;
	}

	/* Round up the file length to a multiple of the block size */
	rnd_up_len = (len + (out->block_size - 1)) & (~(out->block_size -1));
	zero_len = rnd_up_len - len;

	/* Finally we can safely emit a chunk of data */
	chunk_header.chunk_type = CHUNK_TYPE_RAW;
	chunk_header.reserved1 = 0;
	chunk_header.chunk_sz = rnd_up_len / out->block_size;
	chunk_header.total_sz = CHUNK_HEADER_LEN + rnd_up_len;
	ret = out->ops->write(out, (u8 *)&chunk_header, sizeof(chunk_header));

	if (ret < 0)
		return -1;
	ret = out->ops->write(out, data, len);
	if (ret < 0)
		return -1;
	if (zero_len) {
		ret = out->ops->write(out, zero_buf, zero_len);
		if (ret < 0)
			return -1;
	}

	if (out->use_crc) {
		out->crc32 = sparse_crc32(out->crc32, data, len);
		if (zero_len)
			out->crc32 = sparse_crc32(out->crc32, zero_buf, zero_len);
	}

	out->cur_out_ptr += rnd_up_len;
	out->chunk_cnt++;

	return 0;
}

void close_output_file(struct output_file *out)
{
	int ret;
	chunk_header_t chunk_header;

	if (out->sparse) {
		if (out->use_crc) {
			chunk_header.chunk_type = CHUNK_TYPE_CRC32;
			chunk_header.reserved1 = 0;
			chunk_header.chunk_sz = 0;
			chunk_header.total_sz = CHUNK_HEADER_LEN + 4;

			out->ops->write(out, (u8 *)&chunk_header, sizeof(chunk_header));
			out->ops->write(out, (u8 *)&out->crc32, 4);

			out->chunk_cnt++;
		}

		if (out->chunk_cnt != sparse_header.total_chunks)
			error("sparse chunk count did not match: %d %d", out->chunk_cnt,
					sparse_header.total_chunks);
	}
	out->ops->close(out);
}

struct output_file *open_output_fd(int fd, unsigned int block_size, int64_t len,
		int gz, int sparse, int chunks, int crc)
{
	int ret;
	struct output_file *out = malloc(sizeof(struct output_file));
	if (!out) {
		error_errno("malloc struct out");
		return NULL;
	}
	zero_buf = malloc(out->block_size);
	if (!zero_buf) {
		error_errno("malloc zero_buf");
		free(out);
		return NULL;
	}
	memset(zero_buf, '\0', out->block_size);

	if (gz) {
		out->ops = &gz_file_ops;
		out->gz_fd = gzdopen(fd, "wb9");
		if (!out->gz_fd) {
			error_errno("gzopen");
			free(out);
			return NULL;
		}
	} else {
		out->fd = fd;
		out->ops = &file_ops;
	}
	out->close_fd = false;
	out->sparse = sparse;
	out->cur_out_ptr = 0ll;
	out->chunk_cnt = 0;

	/* Initialize the crc32 value */
	out->crc32 = 0;
	out->use_crc = crc;

	out->len = len;
	out->block_size = block_size;

	if (out->sparse) {
		sparse_header.blk_sz = out->block_size,
		sparse_header.total_blks = out->len / out->block_size,
		sparse_header.total_chunks = chunks;
		if (out->use_crc)
			sparse_header.total_chunks++;

		ret = out->ops->write(out, (u8 *)&sparse_header, sizeof(sparse_header));
		if (ret < 0)
			return NULL;
	}

	return out;
}

struct output_file *open_output_file(const char *filename,
		unsigned int block_size, int64_t len,
		int gz, int sparse, int chunks, int crc)
{
	int fd;
	struct output_file *file;

	if (strcmp(filename, "-")) {
		fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
		if (fd < 0) {
			error_errno("open");
			return NULL;
		}
	} else {
		fd = STDOUT_FILENO;
	}

	file = open_output_fd(fd, block_size, len, gz, sparse, chunks, crc);
	if (!file) {
		close(fd);
		return NULL;
	}

	file->close_fd = true; // we opened descriptor thus we responsible for closing it

	return file;
}

void pad_output_file(struct output_file *out, int64_t len)
{
	int ret;

	if (len > out->len) {
		error("attempted to pad file %llu bytes past end of filesystem",
				len - out->len);
		return;
	}
	if (out->sparse) {
		/* We need to emit a DONT_CARE chunk to pad out the file if the
		 * cur_out_ptr is not already at the end of the filesystem.
		 */
		if (len < out->cur_out_ptr) {
			error("attempted to pad file %llu bytes less than the current output pointer",
					out->cur_out_ptr - len);
			return;
		}
		if (len > out->cur_out_ptr) {
			emit_skip_chunk(out, len - out->cur_out_ptr);
		}
	} else {
		//KEN TODO: Fixme.  If the filesystem image needs no padding,
		//          this will overwrite the last byte in the file with 0
		//          The answer is to do accounting like the sparse image
		//          code does and know if there is already data there.
		ret = out->ops->seek(out, len - 1);
		if (ret < 0)
			return;

		ret = out->ops->write(out, (u8*)"", 1);
		if (ret < 0)
			return;
	}
}

/* Write a contiguous region of data blocks from a memory buffer */
void write_data_block(struct output_file *out, int64_t off, void *data, int len)
{
	int ret;

	if (off + len > out->len) {
		error("attempted to write block %llu past end of filesystem",
				off + len - out->len);
		return;
	}

	if (out->sparse) {
		write_chunk_raw(out, off, data, len);
	} else {
		ret = out->ops->seek(out, off);
		if (ret < 0)
			return;

		ret = out->ops->write(out, data, len);
		if (ret < 0)
			return;
	}
}

/* Write a contiguous region of data blocks with a fill value */
void write_fill_block(struct output_file *out, int64_t off, unsigned int fill_val, int len)
{
	int ret;
	unsigned int i;
	int write_len;
	u32 fill_buf[4096/sizeof(u32)]; /* Maximum size of a block */

	if (off + len > out->len) {
		error("attempted to write block %llu past end of filesystem",
				off + len - out->len);
		return;
	}

	if (out->sparse) {
		write_chunk_fill(out, off, fill_val, len);
	} else {
		/* Initialize fill_buf with the fill_val */
		for (i = 0; i < sizeof(fill_buf)/sizeof(u32); i++) {
			fill_buf[i] = fill_val;
		}

		ret = out->ops->seek(out, off);
		if (ret < 0)
			return;

		while (len) {
			write_len = (len > (int)sizeof(fill_buf) ? (int)sizeof(fill_buf) : len);
			ret = out->ops->write(out, (u8 *)fill_buf, write_len);
			if (ret < 0) {
				return;
			} else {
				len -= write_len;
			}
		}
	}
}

/* Write a contiguous region of data blocks from a file */
void write_data_file(struct output_file *out, int64_t off, const char *file,
		int64_t offset, int len)
{
	int ret;
	int64_t aligned_offset;
	int aligned_diff;
	int buffer_size;

	if (off + len >= out->len) {
		error("attempted to write block %llu past end of filesystem",
				off + len - out->len);
		return;
	}

	int file_fd = open(file, O_RDONLY | O_BINARY);
	if (file_fd < 0) {
		error_errno("open");
		return;
	}

	aligned_offset = offset & ~(4096 - 1);
	aligned_diff = offset - aligned_offset;
	buffer_size = len + aligned_diff;

#ifndef USE_MINGW
	u8 *data = mmap64(NULL, buffer_size, PROT_READ, MAP_SHARED, file_fd,
			aligned_offset);
	if (data == MAP_FAILED) {
		error_errno("mmap64");
		close(file_fd);
		return;
	}
#else
	u8 *data = malloc(buffer_size);
	if (!data) {
		error_errno("malloc");
		close(file_fd);
		return;
	}
	memset(data, 0, buffer_size);
#endif

	if (out->sparse) {
		write_chunk_raw(out, off, data + aligned_diff, len);
	} else {
		ret = out->ops->seek(out, off);
		if (ret < 0)
			goto err;

		ret = out->ops->write(out, data + aligned_diff, len);
		if (ret < 0)
			goto err;
	}

err:
#ifndef USE_MINGW
	munmap(data, buffer_size);
#else
	write(file_fd, data, buffer_size);
	free(data);
#endif
	close(file_fd);
}
