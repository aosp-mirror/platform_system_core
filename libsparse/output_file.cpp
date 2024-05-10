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

#include <algorithm>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include "defs.h"
#include "output_file.h"
#include "sparse_crc32.h"
#include "sparse_format.h"

#include <android-base/mapped_file.h>

#ifndef _WIN32
#define O_BINARY 0
#else
#define ftruncate64 ftruncate
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define lseek64 lseek
#define ftruncate64 ftruncate
#define off64_t off_t
#endif

#define SPARSE_HEADER_MAJOR_VER 1
#define SPARSE_HEADER_MINOR_VER 0
#define SPARSE_HEADER_LEN (sizeof(sparse_header_t))
#define CHUNK_HEADER_LEN (sizeof(chunk_header_t))

#define FILL_ZERO_BUFSIZE (2 * 1024 * 1024)

#define container_of(inner, outer_t, elem) ((outer_t*)((char*)(inner)-offsetof(outer_t, elem)))

static constexpr size_t kMaxMmapSize = 256 * 1024 * 1024;

struct output_file_ops {
  int (*open)(struct output_file*, int fd);
  int (*skip)(struct output_file*, int64_t);
  int (*pad)(struct output_file*, int64_t);
  int (*write)(struct output_file*, void*, size_t);
  void (*close)(struct output_file*);
};

struct sparse_file_ops {
  int (*write_data_chunk)(struct output_file* out, uint64_t len, void* data);
  int (*write_fill_chunk)(struct output_file* out, uint64_t len, uint32_t fill_val);
  int (*write_skip_chunk)(struct output_file* out, uint64_t len);
  int (*write_end_chunk)(struct output_file* out);
  int (*write_fd_chunk)(struct output_file* out, uint64_t len, int fd, int64_t offset);
};

struct output_file {
  int64_t cur_out_ptr;
  unsigned int chunk_cnt;
  uint32_t crc32;
  struct output_file_ops* ops;
  struct sparse_file_ops* sparse_ops;
  int use_crc;
  unsigned int block_size;
  int64_t len;
  char* zero_buf;
  uint32_t* fill_buf;
  char* buf;
};

struct output_file_gz {
  struct output_file out;
  gzFile gz_fd;
};

#define to_output_file_gz(_o) container_of((_o), struct output_file_gz, out)

struct output_file_normal {
  struct output_file out;
  int fd;
};

#define to_output_file_normal(_o) container_of((_o), struct output_file_normal, out)

struct output_file_callback {
  struct output_file out;
  void* priv;
  int (*write)(void* priv, const void* buf, size_t len);
};

#define to_output_file_callback(_o) container_of((_o), struct output_file_callback, out)

static int file_open(struct output_file* out, int fd) {
  struct output_file_normal* outn = to_output_file_normal(out);

  outn->fd = fd;
  return 0;
}

static int file_skip(struct output_file* out, int64_t cnt) {
  off64_t ret;
  struct output_file_normal* outn = to_output_file_normal(out);

  ret = lseek64(outn->fd, cnt, SEEK_CUR);
  if (ret < 0) {
    error_errno("lseek64");
    return -1;
  }
  return 0;
}

static int file_pad(struct output_file* out, int64_t len) {
  int ret;
  struct output_file_normal* outn = to_output_file_normal(out);

  ret = ftruncate64(outn->fd, len);
  if (ret < 0) {
    return -errno;
  }

  return 0;
}

static int file_write(struct output_file* out, void* data, size_t len) {
  ssize_t ret;
  struct output_file_normal* outn = to_output_file_normal(out);

  while (len > 0) {
    ret = write(outn->fd, data, len);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      error_errno("write");
      return -1;
    }

    data = (char*)data + ret;
    len -= ret;
  }

  return 0;
}

static void file_close(struct output_file* out) {
  struct output_file_normal* outn = to_output_file_normal(out);

  free(outn);
}

static struct output_file_ops file_ops = {
    .open = file_open,
    .skip = file_skip,
    .pad = file_pad,
    .write = file_write,
    .close = file_close,
};

static int gz_file_open(struct output_file* out, int fd) {
  struct output_file_gz* outgz = to_output_file_gz(out);

  outgz->gz_fd = gzdopen(fd, "wb9");
  if (!outgz->gz_fd) {
    error_errno("gzopen");
    return -errno;
  }

  return 0;
}

static int gz_file_skip(struct output_file* out, int64_t cnt) {
  off64_t ret;
  struct output_file_gz* outgz = to_output_file_gz(out);

  ret = gzseek(outgz->gz_fd, cnt, SEEK_CUR);
  if (ret < 0) {
    error_errno("gzseek");
    return -1;
  }
  return 0;
}

static int gz_file_pad(struct output_file* out, int64_t len) {
  off64_t ret;
  struct output_file_gz* outgz = to_output_file_gz(out);

  ret = gztell(outgz->gz_fd);
  if (ret < 0) {
    return -1;
  }

  if (ret >= len) {
    return 0;
  }

  ret = gzseek(outgz->gz_fd, len - 1, SEEK_SET);
  if (ret < 0) {
    return -1;
  }

  gzwrite(outgz->gz_fd, "", 1);

  return 0;
}

static int gz_file_write(struct output_file* out, void* data, size_t len) {
  int ret;
  struct output_file_gz* outgz = to_output_file_gz(out);

  while (len > 0) {
    ret = gzwrite(outgz->gz_fd, data, std::min<unsigned int>(len, (unsigned int)INT_MAX));
    if (ret == 0) {
      error("gzwrite %s", gzerror(outgz->gz_fd, nullptr));
      return -1;
    }
    len -= ret;
    data = (char*)data + ret;
  }

  return 0;
}

static void gz_file_close(struct output_file* out) {
  struct output_file_gz* outgz = to_output_file_gz(out);

  gzclose(outgz->gz_fd);
  free(outgz);
}

static struct output_file_ops gz_file_ops = {
    .open = gz_file_open,
    .skip = gz_file_skip,
    .pad = gz_file_pad,
    .write = gz_file_write,
    .close = gz_file_close,
};

static int callback_file_open(struct output_file* out __unused, int fd __unused) {
  return 0;
}

static int callback_file_skip(struct output_file* out, int64_t off) {
  struct output_file_callback* outc = to_output_file_callback(out);
  int to_write;
  int ret;

  while (off > 0) {
    to_write = std::min(off, (int64_t)INT_MAX);
    ret = outc->write(outc->priv, nullptr, to_write);
    if (ret < 0) {
      return ret;
    }
    off -= to_write;
  }

  return 0;
}

static int callback_file_pad(struct output_file* out __unused, int64_t len __unused) {
  return -1;
}

static int callback_file_write(struct output_file* out, void* data, size_t len) {
  struct output_file_callback* outc = to_output_file_callback(out);

  return outc->write(outc->priv, data, len);
}

static void callback_file_close(struct output_file* out) {
  struct output_file_callback* outc = to_output_file_callback(out);

  free(outc);
}

static struct output_file_ops callback_file_ops = {
    .open = callback_file_open,
    .skip = callback_file_skip,
    .pad = callback_file_pad,
    .write = callback_file_write,
    .close = callback_file_close,
};

int read_all(int fd, void* buf, size_t len) {
  size_t total = 0;
  int ret;
  char* ptr = reinterpret_cast<char*>(buf);

  while (total < len) {
    ret = read(fd, ptr, len - total);

    if (ret < 0) return -errno;

    if (ret == 0) return -EINVAL;

    ptr += ret;
    total += ret;
  }

  return 0;
}

template <typename T>
static bool write_fd_chunk_range(int fd, int64_t offset, uint64_t len, T callback) {
  uint64_t bytes_written = 0;
  int64_t current_offset = offset;
  while (bytes_written < len) {
    size_t mmap_size = std::min(static_cast<uint64_t>(kMaxMmapSize), len - bytes_written);
    auto m = android::base::MappedFile::FromFd(fd, current_offset, mmap_size, PROT_READ);
    if (!m) {
      error("failed to mmap region of length %zu", mmap_size);
      return false;
    }
    if (!callback(m->data(), mmap_size)) {
      return false;
    }
    bytes_written += mmap_size;
    current_offset += mmap_size;
  }
  return true;
}

static int write_sparse_skip_chunk(struct output_file* out, uint64_t skip_len) {
  chunk_header_t chunk_header;
  int ret;

  if (skip_len % out->block_size) {
    error("don't care size %" PRIi64 " is not a multiple of the block size %u", skip_len,
          out->block_size);
    return -1;
  }

  /* We are skipping data, so emit a don't care chunk. */
  chunk_header.chunk_type = CHUNK_TYPE_DONT_CARE;
  chunk_header.reserved1 = 0;
  chunk_header.chunk_sz = skip_len / out->block_size;
  chunk_header.total_sz = CHUNK_HEADER_LEN;
  ret = out->ops->write(out, &chunk_header, sizeof(chunk_header));
  if (ret < 0) return -1;

  out->cur_out_ptr += skip_len;
  out->chunk_cnt++;

  return 0;
}

static int write_sparse_fill_chunk(struct output_file* out, uint64_t len, uint32_t fill_val) {
  chunk_header_t chunk_header;
  uint64_t rnd_up_len;
  int count;
  int ret;

  /* Round up the fill length to a multiple of the block size */
  rnd_up_len = ALIGN(len, out->block_size);

  /* Finally we can safely emit a chunk of data */
  chunk_header.chunk_type = CHUNK_TYPE_FILL;
  chunk_header.reserved1 = 0;
  chunk_header.chunk_sz = rnd_up_len / out->block_size;
  chunk_header.total_sz = CHUNK_HEADER_LEN + sizeof(fill_val);
  ret = out->ops->write(out, &chunk_header, sizeof(chunk_header));

  if (ret < 0) return -1;
  ret = out->ops->write(out, &fill_val, sizeof(fill_val));
  if (ret < 0) return -1;

  if (out->use_crc) {
    count = out->block_size / sizeof(uint32_t);
    while (count--) out->crc32 = sparse_crc32(out->crc32, &fill_val, sizeof(uint32_t));
  }

  out->cur_out_ptr += rnd_up_len;
  out->chunk_cnt++;

  return 0;
}

static int write_sparse_data_chunk(struct output_file* out, uint64_t len, void* data) {
  chunk_header_t chunk_header;
  uint64_t rnd_up_len, zero_len;
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

  if (ret < 0) return -1;
  ret = out->ops->write(out, data, len);
  if (ret < 0) return -1;
  if (zero_len) {
    uint64_t len = zero_len;
    uint64_t write_len;
    while (len) {
      write_len = std::min(len, (uint64_t)FILL_ZERO_BUFSIZE);
      ret = out->ops->write(out, out->zero_buf, write_len);
      if (ret < 0) {
        return ret;
      }
      len -= write_len;
    }
  }

  if (out->use_crc) {
    out->crc32 = sparse_crc32(out->crc32, data, len);
    if (zero_len) {
      uint64_t len = zero_len;
      uint64_t write_len;
      while (len) {
        write_len = std::min(len, (uint64_t)FILL_ZERO_BUFSIZE);
        out->crc32 = sparse_crc32(out->crc32, out->zero_buf, write_len);
        len -= write_len;
      }
    }
  }

  out->cur_out_ptr += rnd_up_len;
  out->chunk_cnt++;

  return 0;
}

static int write_sparse_fd_chunk(struct output_file* out, uint64_t len, int fd, int64_t offset) {
  chunk_header_t chunk_header;
  uint64_t rnd_up_len, zero_len;
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

  if (ret < 0) return -1;
  bool ok = write_fd_chunk_range(fd, offset, len, [&ret, out](char* data, size_t size) -> bool {
    ret = out->ops->write(out, data, size);
    if (ret < 0) return false;
    if (out->use_crc) {
      out->crc32 = sparse_crc32(out->crc32, data, size);
    }
    return true;
  });
  if (!ok) return -1;
  if (zero_len) {
    uint64_t len = zero_len;
    uint64_t write_len;
    while (len) {
      write_len = std::min(len, (uint64_t)FILL_ZERO_BUFSIZE);
      ret = out->ops->write(out, out->zero_buf, write_len);
      if (ret < 0) {
        return ret;
      }
      len -= write_len;
    }

    if (out->use_crc) {
      uint64_t len = zero_len;
      uint64_t write_len;
      while (len) {
        write_len = std::min(len, (uint64_t)FILL_ZERO_BUFSIZE);
        out->crc32 = sparse_crc32(out->crc32, out->zero_buf, write_len);
        len -= write_len;
      }
    }
  }

  out->cur_out_ptr += rnd_up_len;
  out->chunk_cnt++;

  return 0;
}

int write_sparse_end_chunk(struct output_file* out) {
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
    .write_fd_chunk = write_sparse_fd_chunk,
};

static int write_normal_data_chunk(struct output_file* out, uint64_t len, void* data) {
  int ret;
  uint64_t rnd_up_len = ALIGN(len, out->block_size);

  ret = out->ops->write(out, data, len);
  if (ret < 0) {
    return ret;
  }

  if (rnd_up_len > len) {
    ret = out->ops->skip(out, rnd_up_len - len);
  }

  return ret;
}

static int write_normal_fill_chunk(struct output_file* out, uint64_t len, uint32_t fill_val) {
  int ret;
  unsigned int i;
  uint64_t write_len;

  /* Initialize fill_buf with the fill_val */
  for (i = 0; i < FILL_ZERO_BUFSIZE / sizeof(uint32_t); i++) {
    out->fill_buf[i] = fill_val;
  }

  while (len) {
    write_len = std::min(len, (uint64_t)FILL_ZERO_BUFSIZE);
    ret = out->ops->write(out, out->fill_buf, write_len);
    if (ret < 0) {
      return ret;
    }

    len -= write_len;
  }

  return 0;
}

static int write_normal_fd_chunk(struct output_file* out, uint64_t len, int fd, int64_t offset) {
  int ret;
  uint64_t rnd_up_len = ALIGN(len, out->block_size);

  bool ok = write_fd_chunk_range(fd, offset, len, [&ret, out](char* data, size_t size) -> bool {
    ret = out->ops->write(out, data, size);
    return ret >= 0;
  });
  if (!ok) return ret;

  if (rnd_up_len > len) {
    ret = out->ops->skip(out, rnd_up_len - len);
  }

  return ret;
}

static int write_normal_skip_chunk(struct output_file* out, uint64_t len) {
  return out->ops->skip(out, len);
}

int write_normal_end_chunk(struct output_file* out) {
  return out->ops->pad(out, out->len);
}

static struct sparse_file_ops normal_file_ops = {
    .write_data_chunk = write_normal_data_chunk,
    .write_fill_chunk = write_normal_fill_chunk,
    .write_skip_chunk = write_normal_skip_chunk,
    .write_end_chunk = write_normal_end_chunk,
    .write_fd_chunk = write_normal_fd_chunk,
};

void output_file_close(struct output_file* out) {
  out->sparse_ops->write_end_chunk(out);
  free(out->zero_buf);
  free(out->fill_buf);
  out->zero_buf = nullptr;
  out->fill_buf = nullptr;
  out->ops->close(out);
}

static int output_file_init(struct output_file* out, int block_size, int64_t len, bool sparse,
                            int chunks, bool crc) {
  int ret;

  out->len = len;
  out->block_size = block_size;
  out->cur_out_ptr = 0LL;
  out->chunk_cnt = 0;
  out->crc32 = 0;
  out->use_crc = crc;

  // don't use sparse format block size as it can takes up to 32GB
  out->zero_buf = reinterpret_cast<char*>(calloc(FILL_ZERO_BUFSIZE, 1));
  if (!out->zero_buf) {
    error_errno("malloc zero_buf");
    return -ENOMEM;
  }

  // don't use sparse format block size as it can takes up to 32GB
  out->fill_buf = reinterpret_cast<uint32_t*>(calloc(FILL_ZERO_BUFSIZE, 1));
  if (!out->fill_buf) {
    error_errno("malloc fill_buf");
    ret = -ENOMEM;
    goto err_fill_buf;
  }

  if (sparse) {
    out->sparse_ops = &sparse_file_ops;
  } else {
    out->sparse_ops = &normal_file_ops;
  }

  if (sparse) {
    sparse_header_t sparse_header = {
        .magic = SPARSE_HEADER_MAGIC,
        .major_version = SPARSE_HEADER_MAJOR_VER,
        .minor_version = SPARSE_HEADER_MINOR_VER,
        .file_hdr_sz = SPARSE_HEADER_LEN,
        .chunk_hdr_sz = CHUNK_HEADER_LEN,
        .blk_sz = out->block_size,
        .total_blks = static_cast<unsigned>(DIV_ROUND_UP(out->len, out->block_size)),
        .total_chunks = static_cast<unsigned>(chunks),
        .image_checksum = 0};

    if (out->use_crc) {
      sparse_header.total_chunks++;
    }

    ret = out->ops->write(out, &sparse_header, sizeof(sparse_header));
    if (ret < 0) {
      goto err_write;
    }
  }

  return 0;

err_write:
  free(out->fill_buf);
err_fill_buf:
  free(out->zero_buf);
  return ret;
}

static struct output_file* output_file_new_gz(void) {
  struct output_file_gz* outgz =
      reinterpret_cast<struct output_file_gz*>(calloc(1, sizeof(struct output_file_gz)));
  if (!outgz) {
    error_errno("malloc struct outgz");
    return nullptr;
  }

  outgz->out.ops = &gz_file_ops;

  return &outgz->out;
}

static struct output_file* output_file_new_normal(void) {
  struct output_file_normal* outn =
      reinterpret_cast<struct output_file_normal*>(calloc(1, sizeof(struct output_file_normal)));
  if (!outn) {
    error_errno("malloc struct outn");
    return nullptr;
  }

  outn->out.ops = &file_ops;

  return &outn->out;
}

struct output_file* output_file_open_callback(int (*write)(void*, const void*, size_t), void* priv,
                                              unsigned int block_size, int64_t len, int gz __unused,
                                              int sparse, int chunks, int crc) {
  int ret;
  struct output_file_callback* outc;

  outc =
      reinterpret_cast<struct output_file_callback*>(calloc(1, sizeof(struct output_file_callback)));
  if (!outc) {
    error_errno("malloc struct outc");
    return nullptr;
  }

  outc->out.ops = &callback_file_ops;
  outc->priv = priv;
  outc->write = write;

  ret = output_file_init(&outc->out, block_size, len, sparse, chunks, crc);
  if (ret < 0) {
    free(outc);
    return nullptr;
  }

  return &outc->out;
}

struct output_file* output_file_open_fd(int fd, unsigned int block_size, int64_t len, int gz,
                                        int sparse, int chunks, int crc) {
  int ret;
  struct output_file* out;

  if (gz) {
    out = output_file_new_gz();
  } else {
    out = output_file_new_normal();
  }
  if (!out) {
    return nullptr;
  }

  out->ops->open(out, fd);

  ret = output_file_init(out, block_size, len, sparse, chunks, crc);
  if (ret < 0) {
    free(out);
    return nullptr;
  }

  return out;
}

/* Write a contiguous region of data blocks from a memory buffer */
int write_data_chunk(struct output_file* out, uint64_t len, void* data) {
  return out->sparse_ops->write_data_chunk(out, len, data);
}

/* Write a contiguous region of data blocks with a fill value */
int write_fill_chunk(struct output_file* out, uint64_t len, uint32_t fill_val) {
  return out->sparse_ops->write_fill_chunk(out, len, fill_val);
}

int write_fd_chunk(struct output_file* out, uint64_t len, int fd, int64_t offset) {
  return out->sparse_ops->write_fd_chunk(out, len, fd, offset);
}

/* Write a contiguous region of data blocks from a file */
int write_file_chunk(struct output_file* out, uint64_t len, const char* file, int64_t offset) {
  int ret;

  int file_fd = open(file, O_RDONLY | O_BINARY);
  if (file_fd < 0) {
    return -errno;
  }

  ret = write_fd_chunk(out, len, file_fd, offset);

  close(file_fd);

  return ret;
}

int write_skip_chunk(struct output_file* out, uint64_t len) {
  return out->sparse_ops->write_skip_chunk(out, len);
}
