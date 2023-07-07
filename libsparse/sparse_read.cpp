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

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1

#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>
#include <string>

#include <sparse/sparse.h>

#include "android-base/stringprintf.h"
#include "defs.h"
#include "output_file.h"
#include "sparse_crc32.h"
#include "sparse_file.h"
#include "sparse_format.h"

#if defined(__APPLE__) && defined(__MACH__)
#define lseek64 lseek
#define off64_t off_t
#endif

#define SPARSE_HEADER_MAJOR_VER 1
#define SPARSE_HEADER_LEN (sizeof(sparse_header_t))
#define CHUNK_HEADER_LEN (sizeof(chunk_header_t))

static constexpr int64_t COPY_BUF_SIZE = 1024 * 1024;
static char* copybuf;

static std::string ErrorString(int err) {
  if (err == -EOVERFLOW) return "EOF while reading file";
  if (err == -EINVAL) return "Invalid sparse file format";
  if (err == -ENOMEM) return "Failed allocation while reading file";
  return android::base::StringPrintf("Unknown error %d", err);
}

class SparseFileSource {
 public:
  /* Seeks the source ahead by the given offset.
   * Return 0 if successful. */
  virtual int Seek(int64_t offset) = 0;

  /* Return the current offset. */
  virtual int64_t GetOffset() = 0;

  /* Rewind to beginning. Return 0 if successful. */
  virtual int Rewind() = 0;

  /* Adds the given length from the current offset of the source to the file at the given block.
   * Return 0 if successful. */
  virtual int AddToSparseFile(struct sparse_file* s, int64_t len, unsigned int block) = 0;

  /* Get data of fixed size from the current offset and seek len bytes. Return 0 if successful. */
  virtual int ReadValue(void* ptr, int len) = 0;

  /* Find the crc32 of the next len bytes and seek ahead len bytes. Return 0 if successful. */
  virtual int GetCrc32(uint32_t* crc32, int64_t len) = 0;

  virtual ~SparseFileSource(){};
};

class SparseFileFdSource : public SparseFileSource {
 private:
  int fd;

 public:
  SparseFileFdSource(int fd) : fd(fd) {}
  ~SparseFileFdSource() override {}

  int Seek(int64_t off) override {
    return lseek64(fd, off, SEEK_CUR) != -1 ? 0 : -errno;
  }

  int64_t GetOffset() override { return lseek64(fd, 0, SEEK_CUR); }

  int Rewind() override {
    return lseek64(fd, 0, SEEK_SET) == 0 ? 0 : -errno;
  }

  int AddToSparseFile(struct sparse_file* s, int64_t len, unsigned int block) override {
    return sparse_file_add_fd(s, fd, GetOffset(), len, block);
  }

  int ReadValue(void* ptr, int len) override { return read_all(fd, ptr, len); }

  int GetCrc32(uint32_t* crc32, int64_t len) override {
    int chunk;
    int ret;
    while (len) {
      chunk = std::min(len, COPY_BUF_SIZE);
      ret = read_all(fd, copybuf, chunk);
      if (ret < 0) {
        return ret;
      }
      *crc32 = sparse_crc32(*crc32, copybuf, chunk);
      len -= chunk;
    }
    return 0;
  }
};

class SparseFileBufSource : public SparseFileSource {
 private:
  char* buf_start;
  char* buf_end;
  char* buf;
  int64_t offset;

  int AccessOkay(int64_t len) {
    if (len <= 0) return -EINVAL;
    if (buf < buf_start) return -EOVERFLOW;
    if (buf >= buf_end) return -EOVERFLOW;
    if (len > buf_end - buf) return -EOVERFLOW;

    return 0;
  }

 public:
  SparseFileBufSource(char* buf, uint64_t len) {
    this->buf = buf;
    this->offset = 0;
    this->buf_start = buf;
    this->buf_end = buf + len;
  }
  ~SparseFileBufSource() override {}

  int Seek(int64_t off) override {
    int ret = AccessOkay(off);
    if (ret < 0) {
      return ret;
    }
    buf += off;
    offset += off;
    return 0;
  }

  int64_t GetOffset() override { return offset; }

  int Rewind() override {
    buf = buf_start;
    offset = 0;
    return 0;
  }

  int AddToSparseFile(struct sparse_file* s, int64_t len, unsigned int block) override {
    int ret = AccessOkay(len);
    if (ret < 0) {
      return ret;
    }
    return sparse_file_add_data(s, buf, len, block);
  }

  int ReadValue(void* ptr, int len) override {
    int ret = AccessOkay(len);
    if (ret < 0) {
      return ret;
    }
    memcpy(ptr, buf, len);
    buf += len;
    offset += len;
    return 0;
  }

  int GetCrc32(uint32_t* crc32, int64_t len) override {
    int ret = AccessOkay(len);
    if (ret < 0) {
      return ret;
    }
    *crc32 = sparse_crc32(*crc32, buf, len);
    buf += len;
    offset += len;
    return 0;
  }
};

static void verbose_error(bool verbose, int err, const char* fmt, ...) {
  if (!verbose) return;

  std::string msg = ErrorString(err);
  if (fmt) {
    msg += " at ";
    va_list argp;
    va_start(argp, fmt);
    android::base::StringAppendV(&msg, fmt, argp);
    va_end(argp);
  }
  sparse_print_verbose("%s\n", msg.c_str());
}

static int process_raw_chunk(struct sparse_file* s, unsigned int chunk_size,
                             SparseFileSource* source, unsigned int blocks, unsigned int block,
                             uint32_t* crc32) {
  int ret;
  int64_t len = (int64_t)blocks * s->block_size;

  if (chunk_size % s->block_size != 0) {
    return -EINVAL;
  }

  if (chunk_size / s->block_size != blocks) {
    return -EINVAL;
  }

  ret = source->AddToSparseFile(s, len, block);
  if (ret < 0) {
    return ret;
  }

  if (crc32) {
    ret = source->GetCrc32(crc32, len);
    if (ret < 0) {
      return ret;
    }
  } else {
    ret = source->Seek(len);
    if (ret < 0) {
      return ret;
    }
  }

  return 0;
}

static int process_fill_chunk(struct sparse_file* s, unsigned int chunk_size,
                              SparseFileSource* source, unsigned int blocks, unsigned int block,
                              uint32_t* crc32) {
  int ret;
  int chunk;
  int64_t len = (int64_t)blocks * s->block_size;
  uint32_t fill_val;
  uint32_t* fillbuf;
  unsigned int i;

  if (chunk_size != sizeof(fill_val)) {
    return -EINVAL;
  }

  ret = source->ReadValue(&fill_val, sizeof(fill_val));
  if (ret < 0) {
    return ret;
  }

  ret = sparse_file_add_fill(s, fill_val, len, block);
  if (ret < 0) {
    return ret;
  }

  if (crc32) {
    /* Fill copy_buf with the fill value */
    fillbuf = (uint32_t*)copybuf;
    for (i = 0; i < (COPY_BUF_SIZE / sizeof(fill_val)); i++) {
      fillbuf[i] = fill_val;
    }

    while (len) {
      chunk = std::min(len, COPY_BUF_SIZE);
      *crc32 = sparse_crc32(*crc32, copybuf, chunk);
      len -= chunk;
    }
  }

  return 0;
}

static int process_skip_chunk(struct sparse_file* s, unsigned int chunk_size,
                              SparseFileSource* source __unused, unsigned int blocks,
                              unsigned int block __unused, uint32_t* crc32) {
  if (chunk_size != 0) {
    return -EINVAL;
  }

  if (crc32) {
    int64_t len = (int64_t)blocks * s->block_size;
    memset(copybuf, 0, COPY_BUF_SIZE);

    while (len) {
      int chunk = std::min(len, COPY_BUF_SIZE);
      *crc32 = sparse_crc32(*crc32, copybuf, chunk);
      len -= chunk;
    }
  }

  return 0;
}

static int process_crc32_chunk(SparseFileSource* source, unsigned int chunk_size, uint32_t* crc32) {
  uint32_t file_crc32;

  if (chunk_size != sizeof(file_crc32)) {
    return -EINVAL;
  }

  int ret = source->ReadValue(&file_crc32, sizeof(file_crc32));
  if (ret < 0) {
    return ret;
  }

  if (crc32 != nullptr && file_crc32 != *crc32) {
    return -EINVAL;
  }

  return 0;
}

static int process_chunk(struct sparse_file* s, SparseFileSource* source, unsigned int chunk_hdr_sz,
                         chunk_header_t* chunk_header, unsigned int cur_block, uint32_t* crc_ptr) {
  int ret;
  unsigned int chunk_data_size;
  int64_t offset = source->GetOffset();

  chunk_data_size = chunk_header->total_sz - chunk_hdr_sz;

  switch (chunk_header->chunk_type) {
    case CHUNK_TYPE_RAW:
      ret =
          process_raw_chunk(s, chunk_data_size, source, chunk_header->chunk_sz, cur_block, crc_ptr);
      if (ret < 0) {
        verbose_error(s->verbose, ret, "data block at %" PRId64, offset);
        return ret;
      }
      return chunk_header->chunk_sz;
    case CHUNK_TYPE_FILL:
      ret = process_fill_chunk(s, chunk_data_size, source, chunk_header->chunk_sz, cur_block,
                               crc_ptr);
      if (ret < 0) {
        verbose_error(s->verbose, ret, "fill block at %" PRId64, offset);
        return ret;
      }
      return chunk_header->chunk_sz;
    case CHUNK_TYPE_DONT_CARE:
      ret = process_skip_chunk(s, chunk_data_size, source, chunk_header->chunk_sz, cur_block,
                               crc_ptr);
      if (chunk_data_size != 0) {
        if (ret < 0) {
          verbose_error(s->verbose, ret, "skip block at %" PRId64, offset);
          return ret;
        }
      }
      return chunk_header->chunk_sz;
    case CHUNK_TYPE_CRC32:
      ret = process_crc32_chunk(source, chunk_data_size, crc_ptr);
      if (ret < 0) {
        verbose_error(s->verbose, -EINVAL, "crc block at %" PRId64, offset);
        return ret;
      }
      return 0;
    default:
      verbose_error(s->verbose, -EINVAL, "unknown block %04X at %" PRId64, chunk_header->chunk_type,
                    offset);
  }

  return 0;
}

static int sparse_file_read_sparse(struct sparse_file* s, SparseFileSource* source, bool crc) {
  int ret;
  unsigned int i;
  sparse_header_t sparse_header;
  chunk_header_t chunk_header;
  uint32_t crc32 = 0;
  uint32_t* crc_ptr = nullptr;
  unsigned int cur_block = 0;

  if (!copybuf) {
    copybuf = (char*)malloc(COPY_BUF_SIZE);
  }

  if (!copybuf) {
    return -ENOMEM;
  }

  if (crc) {
    crc_ptr = &crc32;
  }

  ret = source->ReadValue(&sparse_header, sizeof(sparse_header));
  if (ret < 0) {
    return ret;
  }

  if (sparse_header.magic != SPARSE_HEADER_MAGIC) {
    return -EINVAL;
  }

  if (sparse_header.major_version != SPARSE_HEADER_MAJOR_VER) {
    return -EINVAL;
  }

  if (sparse_header.file_hdr_sz < SPARSE_HEADER_LEN) {
    return -EINVAL;
  }

  if (sparse_header.chunk_hdr_sz < sizeof(chunk_header)) {
    return -EINVAL;
  }

  if (sparse_header.file_hdr_sz > SPARSE_HEADER_LEN) {
    /* Skip the remaining bytes in a header that is longer than
     * we expected.
     */
    ret = source->Seek(sparse_header.file_hdr_sz - SPARSE_HEADER_LEN);
    if (ret < 0) {
      return ret;
    }
  }

  for (i = 0; i < sparse_header.total_chunks; i++) {
    ret = source->ReadValue(&chunk_header, sizeof(chunk_header));
    if (ret < 0) {
      return ret;
    }

    if (sparse_header.chunk_hdr_sz > CHUNK_HEADER_LEN) {
      /* Skip the remaining bytes in a header that is longer than
       * we expected.
       */
      ret = source->Seek(sparse_header.chunk_hdr_sz - CHUNK_HEADER_LEN);
      if (ret < 0) {
        return ret;
      }
    }

    ret = process_chunk(s, source, sparse_header.chunk_hdr_sz, &chunk_header, cur_block, crc_ptr);
    if (ret < 0) {
      return ret;
    }

    cur_block += ret;
  }

  if (sparse_header.total_blks != cur_block) {
    return -EINVAL;
  }

  return 0;
}

static int do_sparse_file_read_normal(struct sparse_file* s, int fd, uint32_t* buf, int64_t offset,
                                      int64_t remain) {
  int ret;
  unsigned int block = offset / s->block_size;
  unsigned int to_read;
  unsigned int i;
  bool sparse_block;

  if (!buf) {
    return -ENOMEM;
  }

  while (remain > 0) {
    to_read = std::min(remain, (int64_t)(s->block_size));
    ret = read_all(fd, buf, to_read);
    if (ret < 0) {
      error("failed to read sparse file");
      return ret;
    }

    if (to_read == s->block_size) {
      sparse_block = true;
      for (i = 1; i < s->block_size / sizeof(uint32_t); i++) {
        if (buf[0] != buf[i]) {
          sparse_block = false;
          break;
        }
      }
    } else {
      sparse_block = false;
    }

    if (sparse_block) {
      /* TODO: add flag to use skip instead of fill for buf[0] == 0 */
      sparse_file_add_fill(s, buf[0], to_read, block);
    } else {
      sparse_file_add_fd(s, fd, offset, to_read, block);
    }

    remain -= to_read;
    offset += to_read;
    block++;
  }

  return 0;
}

static int sparse_file_read_normal(struct sparse_file* s, int fd) {
  int ret;
  uint32_t* buf = (uint32_t*)malloc(s->block_size);

  if (!buf)
    return -ENOMEM;

  ret = do_sparse_file_read_normal(s, fd, buf, 0, s->len);
  free(buf);
  return ret;
}

#ifdef __linux__
static int sparse_file_read_hole(struct sparse_file* s, int fd) {
  int ret;
  uint32_t* buf = (uint32_t*)malloc(s->block_size);
  int64_t end = 0;
  int64_t start = 0;

  if (!buf) {
    return -ENOMEM;
  }

  do {
    start = lseek(fd, end, SEEK_DATA);
    if (start < 0) {
      if (errno == ENXIO)
        /* The rest of the file is a hole */
        break;

      error("could not seek to data");
      free(buf);
      return -errno;
    } else if (start > s->len) {
      break;
    }

    end = lseek(fd, start, SEEK_HOLE);
    if (end < 0) {
      error("could not seek to end");
      free(buf);
      return -errno;
    }
    end = std::min(end, s->len);

    start = ALIGN_DOWN(start, s->block_size);
    end = ALIGN(end, s->block_size);
    if (lseek(fd, start, SEEK_SET) < 0) {
      free(buf);
      return -errno;
    }

    ret = do_sparse_file_read_normal(s, fd, buf, start, end - start);
    if (ret) {
      free(buf);
      return ret;
    }
  } while (end < s->len);

  free(buf);
  return 0;
}
#else
static int sparse_file_read_hole(struct sparse_file* s __unused, int fd __unused) {
  return -ENOTSUP;
}
#endif

int sparse_file_read(struct sparse_file* s, int fd, enum sparse_read_mode mode, bool crc) {
  if (crc && mode != SPARSE_READ_MODE_SPARSE) {
    return -EINVAL;
  }

  switch (mode) {
    case SPARSE_READ_MODE_SPARSE: {
      SparseFileFdSource source(fd);
      return sparse_file_read_sparse(s, &source, crc);
    }
    case SPARSE_READ_MODE_NORMAL:
      return sparse_file_read_normal(s, fd);
    case SPARSE_READ_MODE_HOLE:
      return sparse_file_read_hole(s, fd);
    default:
      return -EINVAL;
  }
}

static struct sparse_file* sparse_file_import_source(SparseFileSource* source, bool verbose,
                                                     bool crc) {
  int ret;
  sparse_header_t sparse_header;
  int64_t len;
  struct sparse_file* s;

  ret = source->ReadValue(&sparse_header, sizeof(sparse_header));
  if (ret < 0) {
    verbose_error(verbose, ret, "header");
    return nullptr;
  }

  if (sparse_header.magic != SPARSE_HEADER_MAGIC) {
    verbose_error(verbose, -EINVAL, "header magic");
    return nullptr;
  }

  if (sparse_header.major_version != SPARSE_HEADER_MAJOR_VER) {
    verbose_error(verbose, -EINVAL, "header major version");
    return nullptr;
  }

  if (sparse_header.file_hdr_sz < SPARSE_HEADER_LEN) {
    return nullptr;
  }

  if (sparse_header.chunk_hdr_sz < sizeof(chunk_header_t)) {
    return nullptr;
  }

  if (!sparse_header.blk_sz || (sparse_header.blk_sz % 4)) {
    return nullptr;
  }

  if (!sparse_header.total_blks) {
    return nullptr;
  }

  len = (int64_t)sparse_header.total_blks * sparse_header.blk_sz;
  s = sparse_file_new(sparse_header.blk_sz, len);
  if (!s) {
    verbose_error(verbose, -EINVAL, nullptr);
    return nullptr;
  }

  ret = source->Rewind();
  if (ret < 0) {
    verbose_error(verbose, ret, "seeking");
    sparse_file_destroy(s);
    return nullptr;
  }

  s->verbose = verbose;

  ret = sparse_file_read_sparse(s, source, crc);
  if (ret < 0) {
    sparse_file_destroy(s);
    return nullptr;
  }

  return s;
}

struct sparse_file* sparse_file_import(int fd, bool verbose, bool crc) {
  SparseFileFdSource source(fd);
  return sparse_file_import_source(&source, verbose, crc);
}

struct sparse_file* sparse_file_import_buf(char* buf, size_t len, bool verbose, bool crc) {
  SparseFileBufSource source(buf, len);
  return sparse_file_import_source(&source, verbose, crc);
}

struct sparse_file* sparse_file_import_auto(int fd, bool crc, bool verbose) {
  struct sparse_file* s;
  int64_t len;
  int ret;

  s = sparse_file_import(fd, false, crc);
  if (s) {
    return s;
  }

  len = lseek64(fd, 0, SEEK_END);
  if (len < 0) {
    return nullptr;
  }

  lseek64(fd, 0, SEEK_SET);

  s = sparse_file_new(4096, len);
  if (!s) {
    return nullptr;
  }
  if (verbose) {
    sparse_file_verbose(s);
  }

  ret = sparse_file_read_normal(s, fd);
  if (ret < 0) {
    sparse_file_destroy(s);
    return nullptr;
  }

  return s;
}
