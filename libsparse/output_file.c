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

#define min(a, b) \
	({ typeof(a) _a = (a); typeof(b) _b = (b); (_a < _b) ? _a : _b; })

#define SPARSE_HEADER_MAJOR_VER 1
#define SPARSE_HEADER_MINOR_VER 0
#define SPARSE_HEADER_LEN       (sizeof(sparse_header_t))
#define CHUNK_HEADER_LEN (sizeof(chunk_header_t))

struct output_file_ops {
	int (*skip)(struct output_file *, int64_t);
	int (*write)(struct output_file *, void *, int);
	void (*close)(struct output_file *);
};

struct sparse_file_ops {
	int (*write_data_chunk)(struct output_file *out, unsigned int len,
			void *data);
	int (*write_fill_chunk)(struct output_file *out, unsigned int len,
			uint32_t fill_val);
	int (*write_skip_chunk)(struct output_file *out, int64_t len);
	int (*write_end_chunk)(struct output_file *out);
};

struct output_file {
	int fd;
	gzFile gz_fd;
	bool close_fd;
	int64_t cur_out_ptr;
	unsigned int chunk_cnt;
	uint32_t crc32;
	struct output_file_ops *ops;
	struct sparse_file_ops *sparse_ops;
	int use_crc;
	unsigned int block_size;
	int64_t len;
	char *zero_buf;
	uint32_t *fill_buf;
};

static int file_skip(struct output_file *out, int64_t cnt)
{
	off64_t ret;

	ret = lseek64(out->fd, cnt, SEEK_CUR);
	if (ret < 0) {
		error_errno("lseek64");
		return -1;
	}
	return 0;
}

static int file_write(struct output_file *out, void *data, int len)
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
	.skip = file_skip,
	.write = file_write,
	.close = file_close,
};

static int gz_file_skip(struct output_file *out, int64_t cnt)
{
	off64_t ret;

	ret = gzseek(out->gz_fd, cnt, SEEK_CUR);
	if (ret < 0) {
		error_errno("gzseek");
		return -1;
	}
	return 0;
}

static int gz_file_write(struct output_file *out, void *data, int len)
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
	.skip = gz_file_skip,
	.write = gz_file_write,
	.close = gz_file_close,
};

static int write_sparse_skip_chunk(struct output_file *out, int64_t skip_len)
{
	chunk_header_t chunk_header;
	int ret, chunk;

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
	ret = out->ops->write(out, &chunk_header, sizeof(chunk_header));
	if (ret < 0)
		return -1;

	out->cur_out_ptr += skip_len;
	out->chunk_cnt++;

	return 0;
}

static int write_sparse_fill_chunk(struct output_file *out, unsigned int len,
		uint32_t fill_val)
{
	chunk_header_t chunk_header;
	int rnd_up_len, zero_len, count;
	int ret;
	unsigned int i;

	/* Round up the fill length to a multiple of the block size */
	rnd_up_len = ALIGN(len, out->block_size);

	/* Finally we can safely emit a chunk of data */
	chunk_header.chunk_type = CHUNK_TYPE_FILL;
	chunk_header.reserved1 = 0;
	chunk_header.chunk_sz = rnd_up_len / out->block_size;
	chunk_header.total_sz = CHUNK_HEADER_LEN + sizeof(fill_val);
	ret = out->ops->write(out, &chunk_header, sizeof(chunk_header));

	if (ret < 0)
		return -1;
	ret = out->ops->write(out, &fill_val, sizeof(fill_val));
	if (ret < 0)
		return -1;

	if (out->use_crc) {
		count = out->block_size / sizeof(uint32_t);
		while (count--)
			out->crc32 = sparse_crc32(out->crc32, &fill_val, sizeof(uint32_t));
	}

	out->cur_out_ptr += rnd_up_len;
	out->chunk_cnt++;

	return 0;
}

static int write_sparse_data_chunk(struct output_file *out, unsigned int len,
		void *data)
{
	chunk_header_t chunk_header;
	int rnd_up_len, zero_len;
	int ret;

	/* Round up the data length to a multiple of the block size */
	rnd_up_len = ALIGN(len, out->block_size);
	zero_len = rnd_up_len - len;

	/* Finally we can safely emit a chunk of data */
	chunk_header.chunk_type = CHUNK_TYPE_RAW;
	chunk_header.reserved1 = 0;
	chunk_header.chunk_sz = rnd_up_len / out->block_size;
	chunk_header.total_sz = CHUNK_HEADER_LEN + rnd_up_len;
	ret = out->ops->write(out, &chunk_header, sizeof(chunk_header));

	if (ret < 0)
		return -1;
	ret = out->ops->write(out, data, len);
	if (ret < 0)
		return -1;
	if (zero_len) {
		ret = out->ops->write(out, out->zero_buf, zero_len);
		if (ret < 0)
			return -1;
	}

	if (out->use_crc) {
		out->crc32 = sparse_crc32(out->crc32, data, len);
		if (zero_len)
			out->crc32 = sparse_crc32(out->crc32, out->zero_buf, zero_len);
	}

	out->cur_out_ptr += rnd_up_len;
	out->chunk_cnt++;

	return 0;
}

int write_sparse_end_chunk(struct output_file *out)
{
	chunk_header_t chunk_header;
	int ret;

	if (out->use_crc) {
		chunk_header.chunk_type = CHUNK_TYPE_CRC32;
		chunk_header.reserved1 = 0;
		chunk_header.chunk_sz = 0;
		chunk_header.total_sz = CHUNK_HEADER_LEN + 4;

		ret = out->ops->write(out, &chunk_header, sizeof(chunk_header));
		if (ret < 0) {
			return ret;
		}
		out->ops->write(out, &out->crc32, 4);
		if (ret < 0) {
			return ret;
		}

		out->chunk_cnt++;
	}

	return 0;
}

static struct sparse_file_ops sparse_file_ops = {
		.write_data_chunk = write_sparse_data_chunk,
		.write_fill_chunk = write_sparse_fill_chunk,
		.write_skip_chunk = write_sparse_skip_chunk,
		.write_end_chunk = write_sparse_end_chunk,
};

static int write_normal_data_chunk(struct output_file *out, unsigned int len,
		void *data)
{
	int ret;
	unsigned int rnd_up_len = ALIGN(len, out->block_size);

	ret = out->ops->write(out, data, len);
	if (ret < 0) {
		return ret;
	}

	if (rnd_up_len > len) {
		ret = out->ops->skip(out, rnd_up_len - len);
	}

	return ret;
}

static int write_normal_fill_chunk(struct output_file *out, unsigned int len,
		uint32_t fill_val)
{
	int ret;
	unsigned int i;
	unsigned int write_len;

	/* Initialize fill_buf with the fill_val */
	for (i = 0; i < out->block_size / sizeof(uint32_t); i++) {
		out->fill_buf[i] = fill_val;
	}

	while (len) {
		write_len = min(len, out->block_size);
		ret = out->ops->write(out, out->fill_buf, write_len);
		if (ret < 0) {
			return ret;
		}

		len -= write_len;
	}

	return 0;
}

static int write_normal_skip_chunk(struct output_file *out, int64_t len)
{
	int ret;

	return out->ops->skip(out, len);
}

int write_normal_end_chunk(struct output_file *out)
{
	int ret;

	ret = ftruncate64(out->fd, out->len);
	if (ret < 0) {
		return -errno;
	}

	return 0;
}

static struct sparse_file_ops normal_file_ops = {
		.write_data_chunk = write_normal_data_chunk,
		.write_fill_chunk = write_normal_fill_chunk,
		.write_skip_chunk = write_normal_skip_chunk,
		.write_end_chunk = write_normal_end_chunk,
};

void close_output_file(struct output_file *out)
{
	int ret;

	out->sparse_ops->write_end_chunk(out);
	out->ops->close(out);
	free(out);
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
	out->zero_buf = calloc(block_size, 1);
	if (!out->zero_buf) {
		error_errno("malloc zero_buf");
		goto err_zero_buf;
	}

	out->fill_buf = calloc(block_size, 1);
	if (!out->fill_buf) {
		error_errno("malloc fill_buf");
		goto err_fill_buf;
	}

	if (gz) {
		out->ops = &gz_file_ops;
		out->gz_fd = gzdopen(fd, "wb9");
		if (!out->gz_fd) {
			error_errno("gzopen");
			goto err_gzopen;
		}
	} else {
		out->fd = fd;
		out->ops = &file_ops;
	}

	if (sparse) {
		out->sparse_ops = &sparse_file_ops;
	} else {
		out->sparse_ops = &normal_file_ops;
	}

	out->close_fd = false;
	out->cur_out_ptr = 0ll;
	out->chunk_cnt = 0;

	/* Initialize the crc32 value */
	out->crc32 = 0;
	out->use_crc = crc;

	out->len = len;
	out->block_size = block_size;

	if (sparse) {
		sparse_header_t sparse_header = {
				.magic = SPARSE_HEADER_MAGIC,
				.major_version = SPARSE_HEADER_MAJOR_VER,
				.minor_version = SPARSE_HEADER_MINOR_VER,
				.file_hdr_sz = SPARSE_HEADER_LEN,
				.chunk_hdr_sz = CHUNK_HEADER_LEN,
				.blk_sz = out->block_size,
				.total_blks = out->len / out->block_size,
				.total_chunks = chunks,
				.image_checksum = 0
		};

		if (out->use_crc) {
			sparse_header.total_chunks++;
		}

		ret = out->ops->write(out, &sparse_header, sizeof(sparse_header));
		if (ret < 0) {
			goto err_write;
		}
	}

	return out;

err_write:
	if (gz) {
		gzclose(out->gz_fd);
	}
err_gzopen:
	free(out->fill_buf);
err_fill_buf:
	free(out->zero_buf);
err_zero_buf:
	free(out);
	return NULL;
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

/* Write a contiguous region of data blocks from a memory buffer */
int write_data_chunk(struct output_file *out, unsigned int len, void *data)
{
	return out->sparse_ops->write_data_chunk(out, len, data);
}

/* Write a contiguous region of data blocks with a fill value */
int write_fill_chunk(struct output_file *out, unsigned int len,
		uint32_t fill_val)
{
	return out->sparse_ops->write_fill_chunk(out, len, fill_val);
}

/* Write a contiguous region of data blocks from a file */
int write_file_chunk(struct output_file *out, unsigned int len,
		const char *file, int64_t offset)
{
	int ret;
	int64_t aligned_offset;
	int aligned_diff;
	int buffer_size;

	int file_fd = open(file, O_RDONLY | O_BINARY);
	if (file_fd < 0) {
		return -errno;
	}

	aligned_offset = offset & ~(4096 - 1);
	aligned_diff = offset - aligned_offset;
	buffer_size = len + aligned_diff;

#ifndef USE_MINGW
	char *data = mmap64(NULL, buffer_size, PROT_READ, MAP_SHARED, file_fd,
			aligned_offset);
	if (data == MAP_FAILED) {
		ret = -errno;
		close(file_fd);
		return ret;
	}
#else
	char *data = malloc(buffer_size);
	if (!data) {
		ret = -errno;
		close(file_fd);
		return ret;
	}
	memset(data, 0, buffer_size);
#endif

	ret = out->sparse_ops->write_data_chunk(out, len, data + aligned_diff);

#ifndef USE_MINGW
	munmap(data, buffer_size);
#else
	free(data);
#endif
	close(file_fd);

	return ret;
}

int write_skip_chunk(struct output_file *out, int64_t len)
{
	return out->sparse_ops->write_skip_chunk(out, len);
}
