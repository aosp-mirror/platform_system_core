/*
 * Copyright (C) 2010-2012 The Android Open Source Project
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

#define DEFAULT_BLOCK_SIZE	"4K"
#define DEFAULT_CHUNK_SIZE	"64M"
#define DEFAULT_SUFFIX		"%03d"

#include "sparse_format.h"
#if 0 /* endian.h is not on all platforms */
# include <endian.h>
#else
  /* For now, just assume we're going to run on little-endian. */
# define my_htole32(h) (h)
# define my_htole16(h) (h)
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define COPY_BUF_SIZE (1024*1024)
static char *copy_buf;

static const char *progname(const char *argv0)
{
    const char *prog_name;
    if ((prog_name = strrchr(argv0, '/')))
	return(prog_name + 1);	/* Advance beyond '/'. */
    return(argv0);		/* No '/' in argv0, use it as is. */
}

static void error_exit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);

    exit(EXIT_FAILURE);
}

static void usage(const char *argv0, const char *error_fmt, ...)
{
    fprintf(stderr,
	    "Usage: %s [OPTIONS] <raw_image_file>\n",
	    progname(argv0));
    fprintf(stderr, "The <raw_image_file> will be split into as many sparse\n");
    fprintf(stderr, "files as needed.  Each sparse file will contain a single\n");
    fprintf(stderr, "DONT CARE chunk to offset to the correct block and then\n");
    fprintf(stderr, "a single RAW chunk containing a portion of the data from\n");
    fprintf(stderr, "the raw image file.  The sparse files will be named by\n");
    fprintf(stderr, "appending a number to the name of the raw image file.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "OPTIONS (Defaults are enclosed by square brackets):\n");
    fprintf(stderr, "  -s SUFFIX      Format appended number with SUFFIX [%s]\n",
	    DEFAULT_SUFFIX);
    fprintf(stderr, "  -B SIZE        Use a block size of SIZE [%s]\n",
	    DEFAULT_BLOCK_SIZE);
    fprintf(stderr, "  -C SIZE        Use a chunk size of SIZE [%s]\n",
	    DEFAULT_CHUNK_SIZE);
    fprintf(stderr, "SIZE is a decimal integer that may optionally be\n");
    fprintf(stderr, "followed by a suffix that specifies a multiplier for\n");
    fprintf(stderr, "the integer:\n");
    fprintf(stderr, "       c         1 byte (the default when omitted)\n");
    fprintf(stderr, "       w         2 bytes\n");
    fprintf(stderr, "       b         512 bytes\n");
    fprintf(stderr, "       kB        1000 bytes\n");
    fprintf(stderr, "       K         1024 bytes\n");
    fprintf(stderr, "       MB        1000*1000 bytes\n");
    fprintf(stderr, "       M         1024*1024 bytes\n");
    fprintf(stderr, "       GB        1000*1000*1000 bytes\n");
    fprintf(stderr, "       G         1024*1024*1024 bytes\n");

    if (error_fmt && *error_fmt)
    {
	fprintf(stderr, "\n");
	va_list ap;
	va_start(ap, error_fmt);
	vfprintf(stderr, error_fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
    }

    exit(EXIT_FAILURE);
}

static void cpy_file(int out_fd, char *out_path, int in_fd, char *in_path,
		     size_t len)
{
    ssize_t s, cpy_len = COPY_BUF_SIZE;

    while (len) {
	if (len < COPY_BUF_SIZE)
	    cpy_len = len;

	s = read(in_fd, copy_buf, cpy_len);
	if (s < 0)
	    error_exit("\"%s\": %s", in_path, strerror(errno));
	if (!s)
	    error_exit("\"%s\": Unexpected EOF", in_path);

	cpy_len = s;

	s = write(out_fd, copy_buf, cpy_len);
	if (s < 0)
	    error_exit("\"%s\": %s", out_path, strerror(errno));
	if (s != cpy_len)
	    error_exit("\"%s\": Short data write (%lu)", out_path,
		       (unsigned long)s);

	len -= cpy_len;
    }
}

static int parse_size(const char *size_str, size_t *size)
{
    static const size_t MAX_SIZE_T = ~(size_t)0;
    size_t mult;
    unsigned long long int value;
    const char *end;
    errno = 0;
    value = strtoull(size_str, (char **)&end, 10);
    if (errno != 0 || end == size_str || value > MAX_SIZE_T)
	return -1;
    if (*end == '\0') {
	*size = value;
	return 0;
    }
    if (!strcmp(end, "c"))
	mult = 1;
    else if (!strcmp(end, "w"))
	mult = 2;
    else if (!strcmp(end, "b"))
	mult = 512;
    else if (!strcmp(end, "kB"))
	mult = 1000;
    else if (!strcmp(end, "K"))
	mult = 1024;
    else if (!strcmp(end, "MB"))
	mult = (size_t)1000*1000;
    else if (!strcmp(end, "M"))
	mult = (size_t)1024*1024;
    else if (!strcmp(end, "GB"))
	mult = (size_t)1000*1000*1000;
    else if (!strcmp(end, "G"))
	mult = (size_t)1024*1024*1024;
    else
	return -1;

    if (value > MAX_SIZE_T / mult)
	return -1;
    *size = value * mult;
    return 0;
}

int main(int argc, char *argv[])
{
    char *suffix = DEFAULT_SUFFIX;
    char *block_size_str = DEFAULT_BLOCK_SIZE;
    char *chunk_size_str = DEFAULT_CHUNK_SIZE;
    size_t block_size, chunk_size, blocks_per_chunk, to_write;
    char *in_path, *out_path, *out_fmt;
    int in_fd, out_fd;
    struct stat in_st;
    off_t left_to_write;
    struct {
	sparse_header_t sparse_hdr;
	chunk_header_t dont_care_hdr;
	chunk_header_t raw_hdr;
    } file_hdr;
    unsigned int file_count;
    ssize_t s;
    int i;

    /* Parse the command line. */
    while ((i = getopt(argc, argv, "s:B:C:")) != -1)
    {
	switch (i) {
	case 's':
	    suffix = optarg;
	    break;
	case 'B':
	    block_size_str = optarg;
	    break;
	case 'C':
	    chunk_size_str = optarg;
	    break;
	default:
	    usage(argv[0], NULL);
	    break;
	}
    }

    if (parse_size(block_size_str, &block_size))
	usage(argv[0], "Can not parse \"%s\" as a block size.",
	      block_size_str);
    if (block_size % 4096)
	usage(argv[0], "Block size is not a multiple of 4096.");

    if (parse_size(chunk_size_str, &chunk_size))
	usage(argv[0], "Can not parse \"%s\" as a chunk size.",
	      chunk_size_str);
    if (chunk_size % block_size)
	usage(argv[0], "Chunk size is not a multiple of the block size.");
    blocks_per_chunk = chunk_size / block_size;

    if ((argc - optind) != 1)
	usage(argv[0], "Missing or extra arguments.");
    in_path = argv[optind];

    /* Open the input file and validate it. */
    if ((in_fd = open(in_path, O_RDONLY)) < 0)
	error_exit("open \"%s\": %s", in_path, strerror(errno));
    if (fstat(in_fd, &in_st))
	error_exit("fstat \"%s\": %s", in_path, strerror(errno));
    left_to_write = in_st.st_size;
    if (left_to_write % block_size)
	error_exit(
	    "\"%s\" size (%llu) is not a multiple of the block size (%llu).\n",
	    in_path,
	    (unsigned long long)left_to_write, (unsigned long long)block_size);

    /* Get a buffer for copying the chunks. */
    if ((copy_buf = malloc(COPY_BUF_SIZE)) == 0)
	error_exit("malloc copy buffer: %s", strerror(errno));

    /* Get a buffer for a sprintf format to form output paths. */
    if ((out_fmt = malloc(sizeof("%s") + strlen(suffix))) == 0)
	error_exit("malloc format buffer: %s", strerror(errno));
    out_fmt[0] = '%';
    out_fmt[1] = 's';
    strcpy(out_fmt + 2, suffix);

    /* Get a buffer for an output path. */
    i = snprintf(copy_buf, COPY_BUF_SIZE, out_fmt, in_path, UINT_MAX);
    if (i >= COPY_BUF_SIZE)
	error_exit("Ridulously long suffix: %s", suffix);
    if ((out_path = malloc(i + 1)) == 0)
	error_exit("malloc output path buffer: %s", strerror(errno));

    /*
     * Each file gets a sparse_header, a Don't Care chunk to offset to
     * where the data belongs and then a Raw chunk with the actual data.
     */
    memset((void *)&file_hdr.sparse_hdr, 0, sizeof(file_hdr.sparse_hdr));
    file_hdr.sparse_hdr.magic = my_htole32(SPARSE_HEADER_MAGIC);
    file_hdr.sparse_hdr.major_version = my_htole16(1);
    file_hdr.sparse_hdr.minor_version = my_htole16(0);
    file_hdr.sparse_hdr.file_hdr_sz = my_htole16(sizeof(sparse_header_t));
    file_hdr.sparse_hdr.chunk_hdr_sz = my_htole16(sizeof(chunk_header_t));
    file_hdr.sparse_hdr.blk_sz = my_htole32(block_size);
    /* The total_blks will be set in the file loop below. */
    file_hdr.sparse_hdr.total_chunks = my_htole32(2);
    file_hdr.sparse_hdr.image_checksum = my_htole32(0); /* Typically unused. */

    memset((void *)&file_hdr.dont_care_hdr, 0, sizeof(file_hdr.dont_care_hdr));
    file_hdr.dont_care_hdr.chunk_type = my_htole16(CHUNK_TYPE_DONT_CARE);
    /* The Don't Care's chunk_sz will be set in the file loop below. */
    file_hdr.dont_care_hdr.total_sz = my_htole32(sizeof(chunk_header_t));

    memset((void *)&file_hdr.raw_hdr, 0, sizeof(file_hdr.raw_hdr));
    file_hdr.raw_hdr.chunk_type = my_htole16(CHUNK_TYPE_RAW);
    file_hdr.raw_hdr.chunk_sz = my_htole32(blocks_per_chunk);
    file_hdr.raw_hdr.total_sz = my_htole32(chunk_size + sizeof(chunk_header_t));

    /* Loop through writing chunk_size to each of the output files. */
    to_write = chunk_size;
    for (file_count = 1; left_to_write ; file_count++) {
	/* Fix up the headers on the last block. */
	if (left_to_write < (off_t)chunk_size) {
	    to_write = left_to_write;
	    file_hdr.raw_hdr.chunk_sz = my_htole32(left_to_write / block_size);
	    file_hdr.raw_hdr.total_sz = my_htole32(left_to_write
						+ sizeof(chunk_header_t));
	}

	/* Form the pathname for this output file and open it. */
	sprintf(out_path, out_fmt, in_path, file_count);
	if ((out_fd = creat(out_path, 0666)) < 0)
	    error_exit("\"%s\": %s", out_path, strerror(errno));

	/* Update and write the headers to this output file. */
	s = (file_count-1) * blocks_per_chunk;
	file_hdr.dont_care_hdr.chunk_sz = my_htole32(s);
	file_hdr.sparse_hdr.total_blks = my_htole32(s
						+ (to_write / block_size));
	s = write(out_fd, (void *)&file_hdr, sizeof(file_hdr));
	if (s < 0)
	    error_exit("\"%s\": %s", out_path, strerror(errno));
	if (s != sizeof(file_hdr))
	    error_exit("\"%s\": Short write (%lu)", out_path, (unsigned long)s);

	/* Copy this chunk from the input file to the output file. */
	cpy_file(out_fd, out_path, in_fd, in_path, to_write);

	/* Close this output file and update the amount left to write. */
	if (close(out_fd))
	    error_exit("close \"%s\": %s", out_path, strerror(errno));
	left_to_write -= to_write;
    }

    if (close(in_fd))
	error_exit("close \"%s\": %s", in_path, strerror(errno));

    exit(EXIT_SUCCESS);
}
