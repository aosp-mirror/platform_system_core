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

#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include <benchmark/benchmark.h>

using ::android::meminfo::MemUsage;
using ::android::meminfo::ProcMemInfo;
using ::android::meminfo::SmapsOrRollupFromFile;
using ::android::meminfo::SysMemInfo;

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
            "VmallocUsed:",  "PageTables:", "KernelStack:", NULL};

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

static void BM_ReadMemInfo_old(benchmark::State& state) {
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
BENCHMARK(BM_ReadMemInfo_old);

static void BM_ReadMemInfo_new(benchmark::State& state) {
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
    std::vector<uint64_t> mem(MEMINFO_COUNT);
    const std::vector<std::string> tags = {
            SysMemInfo::kMemTotal,      SysMemInfo::kMemFree,        SysMemInfo::kMemBuffers,
            SysMemInfo::kMemCached,     SysMemInfo::kMemShmem,       SysMemInfo::kMemSlab,
            SysMemInfo::kMemSReclaim,   SysMemInfo::kMemSUnreclaim,  SysMemInfo::kMemSwapTotal,
            SysMemInfo::kMemSwapFree,   SysMemInfo::kMemMapped,      SysMemInfo::kMemVmallocUsed,
            SysMemInfo::kMemPageTables, SysMemInfo::kMemKernelStack,
    };

    SysMemInfo smi;
    for (auto _ : state) {
        smi.ReadMemInfo(tags, &mem, file);
    }
}
BENCHMARK(BM_ReadMemInfo_new);

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

static void BM_ZramTotal_old(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string zram_mmstat_dir = exec_dir + "/testdata1/";
    for (auto _ : state) {
        uint64_t zram_total __attribute__((unused)) = get_zram_mem_used(zram_mmstat_dir) / 1024;
    }
}
BENCHMARK(BM_ZramTotal_old);

static void BM_ZramTotal_new(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string zram_mmstat_dir = exec_dir + "/testdata1/";
    SysMemInfo smi;
    for (auto _ : state) {
        uint64_t zram_total __attribute__((unused)) = smi.mem_zram_kb(zram_mmstat_dir);
    }
}
BENCHMARK(BM_ZramTotal_new);

static void BM_MemInfoWithZram_old(benchmark::State& state) {
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
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string zram_mmstat_dir = exec_dir + "/testdata1/";
    uint64_t mem[MEMINFO_COUNT];
    for (auto _ : state) {
        get_mem_info(mem, tf.path);
        mem[MEMINFO_ZRAM_TOTAL] = get_zram_mem_used("/sys/block/zram0/") / 1024;
        CHECK_EQ(mem[MEMINFO_KERNEL_STACK], 4880u);
    }
}
BENCHMARK(BM_MemInfoWithZram_old);

static void BM_MemInfoWithZram_new(benchmark::State& state) {
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
    std::vector<uint64_t> mem(MEMINFO_COUNT);
    std::vector<std::string> tags(SysMemInfo::kDefaultSysMemInfoTags);
    auto it = tags.begin();
    tags.insert(it + MEMINFO_ZRAM_TOTAL, "Zram:");
    SysMemInfo smi;

    for (auto _ : state) {
        smi.ReadMemInfo(tags, &mem, file);
        CHECK_EQ(mem[MEMINFO_KERNEL_STACK], 4880u);
    }
}
BENCHMARK(BM_MemInfoWithZram_new);

// Current implementation is in frameworks/base/core/jni/android_os_Debug.cpp.
// That implementation is still buggy and it skips over vmalloc allocated memory by kernel modules.
// This is the *fixed* version of the same implementation intended for benchmarking against the new
// one.
static uint64_t get_allocated_vmalloc_memory(const std::string& vm_file) {
    char line[1024];

    uint64_t vmalloc_allocated_size = 0;
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(vm_file.c_str(), "re"), fclose};
    if (fp == nullptr) {
        return 0;
    }

    while (true) {
        if (fgets(line, 1024, fp.get()) == NULL) {
            break;
        }

        // check to see if there are pages mapped in vmalloc area
        if (!strstr(line, "pages=")) {
            continue;
        }

        long nr_pages;
        if (sscanf(line, "%*x-%*x %*ld %*s pages=%ld", &nr_pages) == 1) {
            vmalloc_allocated_size += (nr_pages * getpagesize());
        } else if (sscanf(line, "%*x-%*x %*ld %*s %*s pages=%ld", &nr_pages) == 1) {
            // The second case is for kernel modules. If allocation comes from the module,
            // kernel puts an extra string containing the module name before "pages=" in
            // the line.
            //    See: https://elixir.bootlin.com/linux/latest/source/kernel/kallsyms.c#L373
            vmalloc_allocated_size += (nr_pages * getpagesize());
        }
    }
    return vmalloc_allocated_size;
}

static void BM_VmallocInfo_old_fixed(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string vmallocinfo =
            ::android::base::StringPrintf("%s/testdata1/vmallocinfo", exec_dir.c_str());
    for (auto _ : state) {
        CHECK_EQ(get_allocated_vmalloc_memory(vmallocinfo), 29884416);
    }
}
BENCHMARK(BM_VmallocInfo_old_fixed);

static void BM_VmallocInfo_new(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string vmallocinfo =
            ::android::base::StringPrintf("%s/testdata1/vmallocinfo", exec_dir.c_str());
    for (auto _ : state) {
        SysMemInfo smi;
        CHECK_EQ(smi.ReadVmallocInfo(vmallocinfo), 29884416);
    }
}
BENCHMARK(BM_VmallocInfo_new);

// This implementation is picked up as-is from frameworks/base/core/jni/android_os_Debug.cpp
// and only slightly modified to use std:unique_ptr.
static bool get_smaps_rollup(const std::string path, MemUsage* rollup) {
    char lineBuffer[1024];
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (fp != nullptr) {
        char* line;
        while (true) {
            if (fgets(lineBuffer, sizeof(lineBuffer), fp.get()) == NULL) {
                break;
            }
            line = lineBuffer;

            switch (line[0]) {
                case 'P':
                    if (strncmp(line, "Pss:", 4) == 0) {
                        char* c = line + 4;
                        while (*c != 0 && (*c < '0' || *c > '9')) {
                            c++;
                        }
                        rollup->pss += atoi(c);
                    } else if (strncmp(line, "Private_Clean:", 14) == 0 ||
                               strncmp(line, "Private_Dirty:", 14) == 0) {
                        char* c = line + 14;
                        while (*c != 0 && (*c < '0' || *c > '9')) {
                            c++;
                        }
                        rollup->uss += atoi(c);
                    }
                    break;
                case 'R':
                    if (strncmp(line, "Rss:", 4) == 0) {
                        char* c = line + 4;
                        while (*c != 0 && (*c < '0' || *c > '9')) {
                            c++;
                        }
                        rollup->rss += atoi(c);
                    }
                    break;
                case 'S':
                    if (strncmp(line, "SwapPss:", 8) == 0) {
                        char* c = line + 8;
                        long lSwapPss;
                        while (*c != 0 && (*c < '0' || *c > '9')) {
                            c++;
                        }
                        lSwapPss = atoi(c);
                        rollup->swap_pss += lSwapPss;
                    }
                    break;
            }
        }
    } else {
        return false;
    }

    return true;
}

static void BM_SmapsRollup_old(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string path = ::android::base::StringPrintf("%s/testdata1/smaps", exec_dir.c_str());
    for (auto _ : state) {
        MemUsage stats;
        CHECK_EQ(get_smaps_rollup(path, &stats), true);
        CHECK_EQ(stats.pss, 108384);
    }
}
BENCHMARK(BM_SmapsRollup_old);

static void BM_SmapsRollup_new(benchmark::State& state) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string path = ::android::base::StringPrintf("%s/testdata1/smaps", exec_dir.c_str());
    for (auto _ : state) {
        MemUsage stats;
        CHECK_EQ(SmapsOrRollupFromFile(path, &stats), true);
        CHECK_EQ(stats.pss, 108384);
    }
}
BENCHMARK(BM_SmapsRollup_new);

BENCHMARK_MAIN();
