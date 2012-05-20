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

#ifndef _OUTPUT_FILE_H_
#define _OUTPUT_FILE_H_

#include <sparse/sparse.h>

struct output_file;

struct output_file *open_output_file(const char *filename,
		unsigned int block_size, int64_t len,
		int gz, int sparse, int chunks, int crc);
struct output_file *open_output_fd(int fd, unsigned int block_size, int64_t len,
		int gz, int sparse, int chunks, int crc);
void write_data_block(struct output_file *out, int64_t off, void *data, int len);
void write_fill_block(struct output_file *out, int64_t off, unsigned int fill_val, int len);
void write_data_file(struct output_file *out, int64_t off, const char *file,
		int64_t offset, int len);
void pad_output_file(struct output_file *out, int64_t len);
void close_output_file(struct output_file *out);

#endif
