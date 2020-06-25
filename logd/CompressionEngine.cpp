/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "CompressionEngine.h"

#include <limits>

#include <android-base/logging.h>
#include <zlib.h>
#include <zstd.h>

CompressionEngine& CompressionEngine::GetInstance() {
    static CompressionEngine* engine = new ZstdCompressionEngine();
    return *engine;
}

bool ZlibCompressionEngine::Compress(SerializedData& in, size_t data_length, SerializedData& out) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        LOG(FATAL) << "deflateInit() failed";
    }

    CHECK_LE(data_length, in.size());
    CHECK_LE(in.size(), std::numeric_limits<uint32_t>::max());
    uint32_t deflate_bound = deflateBound(&strm, in.size());

    out.Resize(deflate_bound);

    strm.avail_in = data_length;
    strm.next_in = in.data();
    strm.avail_out = out.size();
    strm.next_out = out.data();
    ret = deflate(&strm, Z_FINISH);
    CHECK_EQ(ret, Z_STREAM_END);

    uint32_t compressed_size = strm.total_out;
    deflateEnd(&strm);

    out.Resize(compressed_size);

    return true;
}

bool ZlibCompressionEngine::Decompress(SerializedData& in, SerializedData& out) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = in.size();
    strm.next_in = in.data();
    strm.avail_out = out.size();
    strm.next_out = out.data();

    inflateInit(&strm);
    int ret = inflate(&strm, Z_NO_FLUSH);

    CHECK_EQ(strm.avail_in, 0U);
    CHECK_EQ(strm.avail_out, 0U);
    CHECK_EQ(ret, Z_STREAM_END);
    inflateEnd(&strm);

    return true;
}

bool ZstdCompressionEngine::Compress(SerializedData& in, size_t data_length, SerializedData& out) {
    CHECK_LE(data_length, in.size());

    size_t compress_bound = ZSTD_compressBound(data_length);
    out.Resize(compress_bound);

    size_t out_size = ZSTD_compress(out.data(), out.size(), in.data(), data_length, 1);
    if (ZSTD_isError(out_size)) {
        LOG(FATAL) << "ZSTD_compress failed: " << ZSTD_getErrorName(out_size);
    }
    out.Resize(out_size);

    return true;
}

bool ZstdCompressionEngine::Decompress(SerializedData& in, SerializedData& out) {
    size_t result = ZSTD_decompress(out.data(), out.size(), in.data(), in.size());
    if (ZSTD_isError(result)) {
        LOG(FATAL) << "ZSTD_decompress failed: " << ZSTD_getErrorName(result);
    }
    CHECK_EQ(result, out.size());
    return true;
}
