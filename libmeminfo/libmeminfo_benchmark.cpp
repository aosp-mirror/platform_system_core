/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <meminfo/sysmeminfo.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>

#include <benchmark/benchmark.h>

enum {
    MEMINFO_TOTAL,
    MEMINFO_FREE,
    MEMINFO_BUFFERS,
    MEMINFO_CACHED,
    MEMINFO_SHMEM,
    MEMINFO_SLAB,
    MEMINFO_SLAB_RECLAIMABLE,
    MEMINFO_SLAB_UNRECLAIMABLE,
    MEMINFO_SWAP_TOTAL,
    MEMINFO_SWAP_FREE,
    MEMINFO_ZRAM_TOTAL,
    MEMINFO_MAPPED,
    MEMINFO_VMALLOC_USED,
    MEMINFO_PAGE_TABLES,
    MEMINFO_KERNEL_STACK,
    MEMINFO_COUNT
};

static void get_mem_info(uint64_t mem[], const char* file) {
    char buffer[4096];
    unsigned int numFound = 0;

    int fd = open(file, O_RDONLY);

    if (fd < 0) {
        printf("Unable to open %s: %s\n", file, strerror(errno));
        return;
    }

    const int len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (len < 0) {
        printf("Empty %s\n", file);
        return;
    }
    buffer[len] = 0;

    static const char* const tags[] = {
            "MemTotal:",     "MemFree:",    "Buffers:",     "Cached:",   "Shmem:", "Slab:",
            "SReclaimable:", "SUnreclaim:", "SwapTotal:",   "SwapFree:", "ZRam:",  "Mapped:",
            "VmallocUsed:",  "PageTables:", "KernelStack:", NULL
    };

    static const int tagsLen[] = {9, 8, 8, 7, 6, 5, 13, 11, 10, 9, 5, 7, 12, 11, 12, 0};

    memset(mem, 0, sizeof(uint64_t) * 15);
    char* p = buffer;
    while (*p && (numFound < (sizeof(tagsLen) / sizeof(tagsLen[0])))) {
        int i = 0;
        while (tags[i]) {
            // std::cout << "tag =" << tags[i] << " p = " << std::string(p, tagsLen[i]) <<
            // std::endl;
            if (strncmp(p, tags[i], tagsLen[i]) == 0) {
                p += tagsLen[i];
                while (*p == ' ') p++;
                char* num = p;
                while (*p >= '0' && *p <= '9') p++;
                if (*p != 0) {
                    *p = 0;
                    p++;
                }
                mem[i] = atoll(num);
                numFound++;
                break;
            }
            i++;
        }
        while (*p && *p != '\n') {
            p++;
        }
        if (*p) p++;
    }
}

static void BM_ParseSysMemInfo(benchmark::State& state) {
    std::string meminfo = R"meminfo(MemTotal:        3019740 kB
MemFree:         1809728 kB
MemAvailable:    2546560 kB
Buffers:           54736 kB
Cached:           776052 kB
SwapCached:            0 kB
Active:           445856 kB
Inactive:         459092 kB
Active(anon):      78492 kB
Inactive(anon):     2240 kB
Active(file):     367364 kB
Inactive(file):   456852 kB
Unevictable:        3096 kB
Mlocked:            3096 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                32 kB
Writeback:             0 kB
AnonPages:         74988 kB
Mapped:            62624 kB
Shmem:              4020 kB
Slab:              86464 kB
SReclaimable:      44432 kB
SUnreclaim:        42032 kB
KernelStack:        4880 kB
PageTables:         2900 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     1509868 kB
Committed_AS:      80296 kB
VmallocTotal:   263061440 kB
VmallocUsed:           0 kB
VmallocChunk:          0 kB
AnonHugePages:      6144 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:         131072 kB
CmaFree:          130380 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB)meminfo";

    TemporaryFile tf;
    ::android::base::WriteStringToFd(meminfo, tf.fd);

    uint64_t mem[MEMINFO_COUNT];
    for (auto _ : state) {
        get_mem_info(mem, tf.path);
    }
}
BENCHMARK(BM_ParseSysMemInfo);

static void BM_ReadMemInfo(benchmark::State& state) {
    std::string meminfo = R"meminfo(MemTotal:        3019740 kB
MemFree:         1809728 kB
MemAvailable:    2546560 kB
Buffers:           54736 kB
Cached:           776052 kB
SwapCached:            0 kB
Active:           445856 kB
Inactive:         459092 kB
Active(anon):      78492 kB
Inactive(anon):     2240 kB
Active(file):     367364 kB
Inactive(file):   456852 kB
Unevictable:        3096 kB
Mlocked:            3096 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                32 kB
Writeback:             0 kB
AnonPages:         74988 kB
Mapped:            62624 kB
Shmem:              4020 kB
Slab:              86464 kB
SReclaimable:      44432 kB
SUnreclaim:        42032 kB
KernelStack:        4880 kB
PageTables:         2900 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     1509868 kB
Committed_AS:      80296 kB
VmallocTotal:   263061440 kB
VmallocUsed:           0 kB
VmallocChunk:          0 kB
AnonHugePages:      6144 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:         131072 kB
CmaFree:          130380 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB)meminfo";

    TemporaryFile tf;
    android::base::WriteStringToFd(meminfo, tf.fd);

    std::string file = std::string(tf.path);
    ::android::meminfo::SysMemInfo mi;
    for (auto _ : state) {
        mi.ReadMemInfo(file);
    }
}
BENCHMARK(BM_ReadMemInfo);

static uint64_t get_zram_mem_used(const std::string& zram_dir) {
    FILE* f = fopen((zram_dir + "mm_stat").c_str(), "r");
    if (f) {
        uint64_t mem_used_total = 0;

        int matched = fscanf(f, "%*d %*d %" SCNu64 " %*d %*d %*d %*d", &mem_used_total);
        if (matched != 1)
            fprintf(stderr, "warning: failed to parse %s\n", (zram_dir + "mm_stat").c_str());

        fclose(f);
        return mem_used_total;
    }

    f = fopen((zram_dir + "mem_used_total").c_str(), "r");
    if (f) {
        uint64_t mem_used_total = 0;

        int matched = fscanf(f, "%" SCNu64, &mem_used_total);
        if (matched != 1)
            fprintf(stderr, "warning: failed to parse %s\n", (zram_dir + "mem_used_total").c_str());

        fclose(f);
        return mem_used_total;
    }

    return 0;
}

static void BM_OldReadZramTotal(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string zram_mmstat_dir = exec_dir + "/testdata1/";
    for (auto _ : state) {
        uint64_t zram_total __attribute__((unused)) = get_zram_mem_used(zram_mmstat_dir) / 1024;
    }
}
BENCHMARK(BM_OldReadZramTotal);

static void BM_NewReadZramTotal(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string zram_mmstat_dir = exec_dir + "/testdata1/";
    ::android::meminfo::SysMemInfo mi;
    for (auto _ : state) {
        uint64_t zram_total __attribute__((unused)) = mi.mem_zram_kb(zram_mmstat_dir);
    }
}
BENCHMARK(BM_NewReadZramTotal);

BENCHMARK_MAIN();
