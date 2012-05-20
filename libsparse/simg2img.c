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
#include <sys/types.h>
#include <unistd.h>

#include "sparse_defs.h"
#include "sparse_format.h"
#include "sparse_crc32.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#define COPY_BUF_SIZE (1024*1024)
u8 *copybuf;

/* This will be malloc'ed with the size of blk_sz from the sparse file header */
u8* zerobuf;

#define SPARSE_HEADER_MAJOR_VER 1
#define SPARSE_HEADER_LEN       (sizeof(sparse_header_t))
#define CHUNK_HEADER_LEN (sizeof(chunk_header_t))

void usage()
{
  fprintf(stderr, "Usage: simg2img <sparse_image_file> <raw_image_file>\n");
}

static int read_all(int fd, void *buf, size_t len)
{
	size_t total = 0;
	int ret;
	char *ptr = buf;

	while (total < len) {
		ret = read(fd, ptr, len - total);

		if (ret < 0)
			return ret;

		if (ret == 0)
			return total;

		ptr += ret;
		total += ret;
	}

	return total;
}

static int write_all(int fd, void *buf, size_t len)
{
	size_t total = 0;
	int ret;
	char *ptr = buf;

	while (total < len) {
		ret = write(fd, ptr, len - total);

		if (ret < 0)
			return ret;

		if (ret == 0)
			return total;

		ptr += ret;
		total += ret;
	}

	return total;
}

int process_raw_chunk(int in, int out, u32 blocks, u32 blk_sz, u32 *crc32)
{
	u64 len = (u64)blocks * blk_sz;
	int ret;
	int chunk;

	while (len) {
		chunk = (len > COPY_BUF_SIZE) ? COPY_BUF_SIZE : len;
		ret = read_all(in, copybuf, chunk);
		if (ret != chunk) {
			fprintf(stderr, "read returned an error copying a raw chunk: %d %d\n",
					ret, chunk);
			exit(-1);
		}
		*crc32 = sparse_crc32(*crc32, copybuf, chunk);
		ret = write_all(out, copybuf, chunk);
		if (ret != chunk) {
			fprintf(stderr, "write returned an error copying a raw chunk\n");
			exit(-1);
		}
		len -= chunk;
	}

	return blocks;
}


int process_fill_chunk(int in, int out, u32 blocks, u32 blk_sz, u32 *crc32)
{
	u64 len = (u64)blocks * blk_sz;
	int ret;
	int chunk;
	u32 fill_val;
	u32 *fillbuf;
	unsigned int i;

	/* Fill copy_buf with the fill value */
	ret = read_all(in, &fill_val, sizeof(fill_val));
	fillbuf = (u32 *)copybuf;
	for (i = 0; i < (COPY_BUF_SIZE / sizeof(fill_val)); i++) {
		fillbuf[i] = fill_val;
	}

	while (len) {
		chunk = (len > COPY_BUF_SIZE) ? COPY_BUF_SIZE : len;
		*crc32 = sparse_crc32(*crc32, copybuf, chunk);
		ret = write_all(out, copybuf, chunk);
		if (ret != chunk) {
			fprintf(stderr, "write returned an error copying a raw chunk\n");
			exit(-1);
		}
		len -= chunk;
	}

	return blocks;
}

int process_skip_chunk(int out, u32 blocks, u32 blk_sz, u32 *crc32)
{
	/* len needs to be 64 bits, as the sparse file specifies the skip amount
	 * as a 32 bit value of blocks.
	 */
	u64 len = (u64)blocks * blk_sz;

	lseek64(out, len, SEEK_CUR);

	return blocks;
}

int process_crc32_chunk(int in, u32 crc32)
{
	u32 file_crc32;
	int ret;

	ret = read_all(in, &file_crc32, 4);
	if (ret != 4) {
		fprintf(stderr, "read returned an error copying a crc32 chunk\n");
		exit(-1);
	}

	if (file_crc32 != crc32) {
		fprintf(stderr, "computed crc32 of 0x%8.8x, expected 0x%8.8x\n",
			 crc32, file_crc32);
		exit(-1);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int in;
	int out;
	unsigned int i;
	sparse_header_t sparse_header;
	chunk_header_t chunk_header;
	u32 crc32 = 0;
	u32 total_blocks = 0;
	int ret;

	if (argc != 3) {
		usage();
		exit(-1);
	}

	if ( (copybuf = malloc(COPY_BUF_SIZE)) == 0) {
		fprintf(stderr, "Cannot malloc copy buf\n");
		exit(-1);
	}

	if (strcmp(argv[1], "-") == 0) {
		in = STDIN_FILENO;
	} else {
		if ((in = open(argv[1], O_RDONLY)) == 0) {
			fprintf(stderr, "Cannot open input file %s\n", argv[1]);
			exit(-1);
		}
	}

	if (strcmp(argv[2], "-") == 0) {
		out = STDOUT_FILENO;
	} else {
		if ((out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666)) == 0) {
			fprintf(stderr, "Cannot open output file %s\n", argv[2]);
			exit(-1);
		}
	}

	ret = read_all(in, &sparse_header, sizeof(sparse_header));
	if (ret != sizeof(sparse_header)) {
		fprintf(stderr, "Error reading sparse file header\n");
		exit(-1);
	}

	if (sparse_header.magic != SPARSE_HEADER_MAGIC) {
		fprintf(stderr, "Bad magic\n");
		exit(-1);
	}

	if (sparse_header.major_version != SPARSE_HEADER_MAJOR_VER) {
		fprintf(stderr, "Unknown major version number\n");
		exit(-1);
	}

	if (sparse_header.file_hdr_sz > SPARSE_HEADER_LEN) {
		/* Skip the remaining bytes in a header that is longer than
		 * we expected.
		 */
		lseek64(in, sparse_header.file_hdr_sz - SPARSE_HEADER_LEN, SEEK_CUR);
	}

	if ( (zerobuf = malloc(sparse_header.blk_sz)) == 0) {
		fprintf(stderr, "Cannot malloc zero buf\n");
		exit(-1);
	}

	for (i=0; i<sparse_header.total_chunks; i++) {
		ret = read_all(in, &chunk_header, sizeof(chunk_header));
		if (ret != sizeof(chunk_header)) {
			fprintf(stderr, "Error reading chunk header\n");
			exit(-1);
		}

		if (sparse_header.chunk_hdr_sz > CHUNK_HEADER_LEN) {
			/* Skip the remaining bytes in a header that is longer than
			 * we expected.
			 */
			lseek64(in, sparse_header.chunk_hdr_sz - CHUNK_HEADER_LEN, SEEK_CUR);
		}

		switch (chunk_header.chunk_type) {
		    case CHUNK_TYPE_RAW:
			if (chunk_header.total_sz != (sparse_header.chunk_hdr_sz +
				 (chunk_header.chunk_sz * sparse_header.blk_sz)) ) {
				fprintf(stderr, "Bogus chunk size for chunk %d, type Raw\n", i);
				exit(-1);
			}
			total_blocks += process_raw_chunk(in, out,
					 chunk_header.chunk_sz, sparse_header.blk_sz, &crc32);
			break;
		    case CHUNK_TYPE_FILL:
			if (chunk_header.total_sz != (sparse_header.chunk_hdr_sz + sizeof(u32)) ) {
				fprintf(stderr, "Bogus chunk size for chunk %d, type Fill\n", i);
				exit(-1);
			}
			total_blocks += process_fill_chunk(in, out,
					 chunk_header.chunk_sz, sparse_header.blk_sz, &crc32);
			break;
		    case CHUNK_TYPE_DONT_CARE:
			if (chunk_header.total_sz != sparse_header.chunk_hdr_sz) {
				fprintf(stderr, "Bogus chunk size for chunk %d, type Dont Care\n", i);
				exit(-1);
			}
			total_blocks += process_skip_chunk(out,
					 chunk_header.chunk_sz, sparse_header.blk_sz, &crc32);
			break;
		    case CHUNK_TYPE_CRC32:
			process_crc32_chunk(in, crc32);
			break;
		    default:
			fprintf(stderr, "Unknown chunk type 0x%4.4x\n", chunk_header.chunk_type);
		}

	}

	/* If the last chunk was a skip, then the code just did a seek, but
	 * no write, and the file won't actually be the correct size.  This
	 * will make the file the correct size.  Make sure the offset is
	 * computed in 64 bits, and the function called can handle 64 bits.
	 */
	if (ftruncate64(out, (u64)total_blocks * sparse_header.blk_sz)) {
		fprintf(stderr, "Error calling ftruncate() to set the image size\n");
		exit(-1);
	}

	close(in);
	close(out);

	if (sparse_header.total_blks != total_blocks) {
		fprintf(stderr, "Wrote %d blocks, expected to write %d blocks\n",
			 total_blocks, sparse_header.total_blks);
		exit(-1);
	}

	exit(0);
}

