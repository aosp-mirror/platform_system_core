//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include <memory>

#include <array>
#include <iostream>
#include <random>

#include <libsnapshot/cow_compress.h>
#include <libsnapshot/cow_format.h>

static const uint32_t BLOCK_SZ = 4096;
static const uint32_t SEED_NUMBER = 10;

namespace android {
namespace snapshot {

static std::string CompressionToString(CowCompression& compression) {
    std::string output;
    switch (compression.algorithm) {
        case kCowCompressBrotli:
            output.append("brotli");
            break;
        case kCowCompressGz:
            output.append("gz");
            break;
        case kCowCompressLz4:
            output.append("lz4");
            break;
        case kCowCompressZstd:
            output.append("zstd");
            break;
        case kCowCompressNone:
            return "No Compression";
    }
    output.append(" " + std::to_string(compression.compression_level));
    return output;
}

void OneShotCompressionTest() {
    std::cout << "\n-------One Shot Compressor Perf Analysis-------\n";

    std::vector<CowCompression> compression_list = {
            {kCowCompressLz4, 0},     {kCowCompressBrotli, 1}, {kCowCompressBrotli, 3},
            {kCowCompressBrotli, 11}, {kCowCompressZstd, 3},   {kCowCompressZstd, 6},
            {kCowCompressZstd, 9},    {kCowCompressZstd, 22},  {kCowCompressGz, 1},
            {kCowCompressGz, 3},      {kCowCompressGz, 6},     {kCowCompressGz, 9}};
    std::vector<std::unique_ptr<ICompressor>> compressors;
    for (auto i : compression_list) {
        compressors.emplace_back(ICompressor::Create(i, BLOCK_SZ));
    }

    // Allocate a buffer of size 8 blocks.
    std::array<char, 32768> buffer;

    // Generate a random 4k buffer of characters
    std::default_random_engine gen(SEED_NUMBER);
    std::uniform_int_distribution<int> distribution(0, 10);
    for (int i = 0; i < buffer.size(); i++) {
        buffer[i] = static_cast<char>(distribution(gen));
    }

    std::vector<std::pair<double, std::string>> latencies;
    std::vector<std::pair<double, std::string>> ratios;

    for (size_t i = 0; i < compressors.size(); i++) {
        const auto start = std::chrono::steady_clock::now();
        std::vector<uint8_t> compressed_data =
                compressors[i]->Compress(buffer.data(), buffer.size());
        const auto end = std::chrono::steady_clock::now();
        const auto latency =
                std::chrono::duration_cast<std::chrono::nanoseconds>(end - start) / 1000.0;
        const double compression_ratio =
                static_cast<uint16_t>(compressed_data.size()) * 1.00 / buffer.size();

        std::cout << "Metrics for " << CompressionToString(compression_list[i]) << ": latency -> "
                  << latency.count() << "ms "
                  << " compression ratio ->" << compression_ratio << " \n";

        latencies.emplace_back(
                std::make_pair(latency.count(), CompressionToString(compression_list[i])));
        ratios.emplace_back(
                std::make_pair(compression_ratio, CompressionToString(compression_list[i])));
    }

    int best_speed = 0;
    int best_ratio = 0;

    for (size_t i = 1; i < latencies.size(); i++) {
        if (latencies[i].first < latencies[best_speed].first) {
            best_speed = i;
        }
        if (ratios[i].first < ratios[best_ratio].first) {
            best_ratio = i;
        }
    }

    std::cout << "BEST SPEED: " << latencies[best_speed].first << "ms "
              << latencies[best_speed].second << "\n";
    std::cout << "BEST RATIO: " << ratios[best_ratio].first << " " << ratios[best_ratio].second
              << "\n";
}

void IncrementalCompressionTest() {
    std::cout << "\n-------Incremental Compressor Perf Analysis-------\n";

    std::vector<CowCompression> compression_list = {
            {kCowCompressLz4, 0},     {kCowCompressBrotli, 1}, {kCowCompressBrotli, 3},
            {kCowCompressBrotli, 11}, {kCowCompressZstd, 3},   {kCowCompressZstd, 6},
            {kCowCompressZstd, 9},    {kCowCompressZstd, 22},  {kCowCompressGz, 1},
            {kCowCompressGz, 3},      {kCowCompressGz, 6},     {kCowCompressGz, 9}};
    std::vector<std::unique_ptr<ICompressor>> compressors;
    for (auto i : compression_list) {
        compressors.emplace_back(ICompressor::Create(i, BLOCK_SZ));
    }

    // Allocate a buffer of size 8 blocks.
    std::array<char, 32768> buffer;

    // Generate a random 4k buffer of characters
    std::default_random_engine gen(SEED_NUMBER);
    std::uniform_int_distribution<int> distribution(0, 10);
    for (int i = 0; i < buffer.size(); i++) {
        buffer[i] = static_cast<char>(distribution(gen));
    }

    std::vector<std::pair<double, std::string>> latencies;
    std::vector<std::pair<double, std::string>> ratios;

    for (size_t i = 0; i < compressors.size(); i++) {
        std::vector<std::vector<uint8_t>> compressed_data_vec;
        int num_blocks = buffer.size() / BLOCK_SZ;
        const uint8_t* iter = reinterpret_cast<const uint8_t*>(buffer.data());

        const auto start = std::chrono::steady_clock::now();
        while (num_blocks > 0) {
            std::vector<uint8_t> compressed_data = compressors[i]->Compress(iter, BLOCK_SZ);
            compressed_data_vec.emplace_back(compressed_data);
            num_blocks--;
            iter += BLOCK_SZ;
        }

        const auto end = std::chrono::steady_clock::now();
        const auto latency =
                std::chrono::duration_cast<std::chrono::nanoseconds>(end - start) / 1000.0;

        size_t size = 0;
        for (auto& i : compressed_data_vec) {
            size += i.size();
        }
        const double compression_ratio = size * 1.00 / buffer.size();

        std::cout << "Metrics for " << CompressionToString(compression_list[i]) << ": latency -> "
                  << latency.count() << "ms "
                  << " compression ratio ->" << compression_ratio << " \n";

        latencies.emplace_back(
                std::make_pair(latency.count(), CompressionToString(compression_list[i])));
        ratios.emplace_back(
                std::make_pair(compression_ratio, CompressionToString(compression_list[i])));
    }

    int best_speed = 0;
    int best_ratio = 0;

    for (size_t i = 1; i < latencies.size(); i++) {
        if (latencies[i].first < latencies[best_speed].first) {
            best_speed = i;
        }
        if (ratios[i].first < ratios[best_ratio].first) {
            best_ratio = i;
        }
    }

    std::cout << "BEST SPEED: " << latencies[best_speed].first << "ms "
              << latencies[best_speed].second << "\n";
    std::cout << "BEST RATIO: " << ratios[best_ratio].first << " " << ratios[best_ratio].second
              << "\n";
}

}  // namespace snapshot
}  // namespace android

int main() {
    android::snapshot::OneShotCompressionTest();
    android::snapshot::IncrementalCompressionTest();

    return 0;
}