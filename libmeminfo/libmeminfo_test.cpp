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

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <meminfo/pageacct.h>
#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

using namespace std;
using namespace android::meminfo;

pid_t pid = -1;

TEST(ProcMemInfo, TestWorkingTestReset) {
    // Expect reset to succeed
    EXPECT_TRUE(ProcMemInfo::ResetWorkingSet(pid));
}

TEST(ProcMemInfo, UsageEmpty) {
    // If we created the object for getting working set,
    // the usage must be empty
    ProcMemInfo proc_mem(pid, true);
    const MemUsage& usage = proc_mem.Usage();
    EXPECT_EQ(usage.rss, 0);
    EXPECT_EQ(usage.vss, 0);
    EXPECT_EQ(usage.pss, 0);
    EXPECT_EQ(usage.uss, 0);
    EXPECT_EQ(usage.swap, 0);
}

TEST(ProcMemInfo, MapsNotEmpty) {
    // Make sure the process maps are never empty
    ProcMemInfo proc_mem(pid);
    const std::vector<Vma>& maps = proc_mem.Maps();
    EXPECT_FALSE(maps.empty());
}

TEST(ProcMemInfo, WssEmpty) {
    // If we created the object for getting usage,
    // the working set must be empty
    ProcMemInfo proc_mem(pid, false);
    const MemUsage& wss = proc_mem.Wss();
    EXPECT_EQ(wss.rss, 0);
    EXPECT_EQ(wss.vss, 0);
    EXPECT_EQ(wss.pss, 0);
    EXPECT_EQ(wss.uss, 0);
    EXPECT_EQ(wss.swap, 0);
}

TEST(ProcMemInfo, SwapOffsetsEmpty) {
    // If we created the object for getting working set,
    // the swap offsets must be empty
    ProcMemInfo proc_mem(pid, true);
    const std::vector<uint16_t>& swap_offsets = proc_mem.SwapOffsets();
    EXPECT_EQ(swap_offsets.size(), 0);
}

TEST(ProcMemInfo, IsSmapsSupportedTest) {
    // Get any pid and check if /proc/<pid>/smaps_rollup exists using the API.
    // The API must return the appropriate value regardless of the after it succeeds
    // once.
    std::string path = ::android::base::StringPrintf("/proc/%d/smaps_rollup", pid);
    bool supported = IsSmapsRollupSupported(pid);
    EXPECT_EQ(!access(path.c_str(), F_OK | R_OK), supported);
    // Second call must return what the first one returned regardless of the pid parameter.
    // So, deliberately pass invalid pid.
    EXPECT_EQ(supported, IsSmapsRollupSupported(-1));
}

TEST(ProcMemInfo, SmapsOrRollupTest) {
    // Make sure we can parse 'smaps_rollup' correctly
    std::string rollup =
            R"rollup(12c00000-7fe859e000 ---p 00000000 00:00 0                                [rollup]
Rss:              331908 kB
Pss:              202052 kB
Shared_Clean:     158492 kB
Shared_Dirty:      18928 kB
Private_Clean:     90472 kB
Private_Dirty:     64016 kB
Referenced:       318700 kB
Anonymous:         81984 kB
AnonHugePages:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:               5344 kB
SwapPss:             442 kB
Locked:          1523537 kB)rollup";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(rollup, tf.fd));

    MemUsage stats;
    ASSERT_EQ(SmapsOrRollupFromFile(tf.path, &stats), true);
    EXPECT_EQ(stats.rss, 331908);
    EXPECT_EQ(stats.pss, 202052);
    EXPECT_EQ(stats.uss, 154488);
    EXPECT_EQ(stats.private_clean, 90472);
    EXPECT_EQ(stats.private_dirty, 64016);
    EXPECT_EQ(stats.swap_pss, 442);
}

TEST(ProcMemInfo, SmapsOrRollupSmapsTest) {
    // Make sure /proc/<pid>/smaps is parsed correctly
    std::string smaps =
            R"smaps(12c00000-13440000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space (region space)]
Name:           [anon:dalvik-main space (region space)]
Size:               8448 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                2652 kB
Pss:                2652 kB
Shared_Clean:        840 kB
Shared_Dirty:         40 kB
Private_Clean:        84 kB
Private_Dirty:      2652 kB
Referenced:         2652 kB
Anonymous:          2652 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                102 kB
SwapPss:              70 kB
Locked:             2652 kB
VmFlags: rd wr mr mw me ac 
)smaps";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(smaps, tf.fd));

    MemUsage stats;
    ASSERT_EQ(SmapsOrRollupFromFile(tf.path, &stats), true);
    EXPECT_EQ(stats.rss, 2652);
    EXPECT_EQ(stats.pss, 2652);
    EXPECT_EQ(stats.uss, 2736);
    EXPECT_EQ(stats.private_clean, 84);
    EXPECT_EQ(stats.private_dirty, 2652);
    EXPECT_EQ(stats.swap_pss, 70);
}

TEST(ProcMemInfo, SmapsOrRollupPssRollupTest) {
    // Make sure /proc/<pid>/smaps is parsed correctly
    // to get the PSS
    std::string smaps =
            R"smaps(12c00000-13440000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space (region space)]
Name:           [anon:dalvik-main space (region space)]
Size:               8448 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                2652 kB
Pss:                2652 kB
Shared_Clean:        840 kB
Shared_Dirty:         40 kB
Private_Clean:        84 kB
Private_Dirty:      2652 kB
Referenced:         2652 kB
Anonymous:          2652 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                102 kB
SwapPss:              70 kB
Locked:             2652 kB
VmFlags: rd wr mr mw me ac 
)smaps";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(smaps, tf.fd));

    uint64_t pss;
    ASSERT_EQ(SmapsOrRollupPssFromFile(tf.path, &pss), true);
    EXPECT_EQ(pss, 2652);
}

TEST(ProcMemInfo, SmapsOrRollupPssSmapsTest) {
    // Correctly parse smaps file to gather pss
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string path = ::android::base::StringPrintf("%s/testdata1/smaps_short", exec_dir.c_str());

    uint64_t pss;
    ASSERT_EQ(SmapsOrRollupPssFromFile(path, &pss), true);
    EXPECT_EQ(pss, 19119);
}

TEST(ProcMemInfo, ForEachVmaFromFileTest) {
    // Parse smaps file correctly to make callbacks for each virtual memory area (vma)
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string path = ::android::base::StringPrintf("%s/testdata1/smaps_short", exec_dir.c_str());
    ProcMemInfo proc_mem(pid);

    std::vector<Vma> vmas;
    auto collect_vmas = [&](const Vma& v) { vmas.push_back(v); };
    ASSERT_TRUE(ForEachVmaFromFile(path, collect_vmas));

    // We should get a total of 6 vmas
    ASSERT_EQ(vmas.size(), 6);

    // Expect values to be equal to what we have in testdata1/smaps_short
    // Check for sizes first
    ASSERT_EQ(vmas[0].usage.vss, 32768);
    EXPECT_EQ(vmas[1].usage.vss, 11204);
    EXPECT_EQ(vmas[2].usage.vss, 16896);
    EXPECT_EQ(vmas[3].usage.vss, 260);
    EXPECT_EQ(vmas[4].usage.vss, 6060);
    EXPECT_EQ(vmas[5].usage.vss, 4);

    // Check for names
    EXPECT_EQ(vmas[0].name, "[anon:dalvik-zygote-jit-code-cache]");
    EXPECT_EQ(vmas[1].name, "/system/framework/x86_64/boot-framework.art");
    EXPECT_EQ(vmas[2].name, "[anon:libc_malloc]");
    EXPECT_EQ(vmas[3].name, "/system/priv-app/SettingsProvider/oat/x86_64/SettingsProvider.odex");
    EXPECT_EQ(vmas[4].name, "/system/lib64/libhwui.so");
    EXPECT_EQ(vmas[5].name, "[vsyscall]");

    EXPECT_EQ(vmas[0].usage.rss, 2048);
    EXPECT_EQ(vmas[1].usage.rss, 11188);
    EXPECT_EQ(vmas[2].usage.rss, 15272);
    EXPECT_EQ(vmas[3].usage.rss, 260);
    EXPECT_EQ(vmas[4].usage.rss, 4132);
    EXPECT_EQ(vmas[5].usage.rss, 0);

    EXPECT_EQ(vmas[0].usage.pss, 113);
    EXPECT_EQ(vmas[1].usage.pss, 2200);
    EXPECT_EQ(vmas[2].usage.pss, 15272);
    EXPECT_EQ(vmas[3].usage.pss, 260);
    EXPECT_EQ(vmas[4].usage.pss, 1274);
    EXPECT_EQ(vmas[5].usage.pss, 0);

    EXPECT_EQ(vmas[0].usage.uss, 0);
    EXPECT_EQ(vmas[1].usage.uss, 1660);
    EXPECT_EQ(vmas[2].usage.uss, 15272);
    EXPECT_EQ(vmas[3].usage.uss, 260);
    EXPECT_EQ(vmas[4].usage.uss, 0);
    EXPECT_EQ(vmas[5].usage.uss, 0);

    EXPECT_EQ(vmas[0].usage.private_clean, 0);
    EXPECT_EQ(vmas[1].usage.private_clean, 0);
    EXPECT_EQ(vmas[2].usage.private_clean, 0);
    EXPECT_EQ(vmas[3].usage.private_clean, 260);
    EXPECT_EQ(vmas[4].usage.private_clean, 0);
    EXPECT_EQ(vmas[5].usage.private_clean, 0);

    EXPECT_EQ(vmas[0].usage.private_dirty, 0);
    EXPECT_EQ(vmas[1].usage.private_dirty, 1660);
    EXPECT_EQ(vmas[2].usage.private_dirty, 15272);
    EXPECT_EQ(vmas[3].usage.private_dirty, 0);
    EXPECT_EQ(vmas[4].usage.private_dirty, 0);
    EXPECT_EQ(vmas[5].usage.private_dirty, 0);

    EXPECT_EQ(vmas[0].usage.shared_clean, 0);
    EXPECT_EQ(vmas[1].usage.shared_clean, 80);
    EXPECT_EQ(vmas[2].usage.shared_clean, 0);
    EXPECT_EQ(vmas[3].usage.shared_clean, 0);
    EXPECT_EQ(vmas[4].usage.shared_clean, 4132);
    EXPECT_EQ(vmas[5].usage.shared_clean, 0);

    EXPECT_EQ(vmas[0].usage.shared_dirty, 2048);
    EXPECT_EQ(vmas[1].usage.shared_dirty, 9448);
    EXPECT_EQ(vmas[2].usage.shared_dirty, 0);
    EXPECT_EQ(vmas[3].usage.shared_dirty, 0);
    EXPECT_EQ(vmas[4].usage.shared_dirty, 0);
    EXPECT_EQ(vmas[5].usage.shared_dirty, 0);

    EXPECT_EQ(vmas[0].usage.swap, 0);
    EXPECT_EQ(vmas[1].usage.swap, 0);
    EXPECT_EQ(vmas[2].usage.swap, 0);
    EXPECT_EQ(vmas[3].usage.swap, 0);
    EXPECT_EQ(vmas[4].usage.swap, 0);
    EXPECT_EQ(vmas[5].usage.swap, 0);

    EXPECT_EQ(vmas[0].usage.swap_pss, 0);
    EXPECT_EQ(vmas[1].usage.swap_pss, 0);
    EXPECT_EQ(vmas[2].usage.swap_pss, 0);
    EXPECT_EQ(vmas[3].usage.swap_pss, 0);
    EXPECT_EQ(vmas[4].usage.swap_pss, 0);
    EXPECT_EQ(vmas[5].usage.swap_pss, 0);
}

TEST(ProcMemInfo, SmapsReturnTest) {
    // Make sure Smaps() is never empty for any process
    ProcMemInfo proc_mem(pid);
    auto vmas = proc_mem.Smaps();
    EXPECT_FALSE(vmas.empty());
}

TEST(ProcMemInfo, SmapsTest) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();
    std::string path = ::android::base::StringPrintf("%s/testdata1/smaps_short", exec_dir.c_str());
    ProcMemInfo proc_mem(pid);
    auto vmas = proc_mem.Smaps(path);

    ASSERT_FALSE(vmas.empty());
    // We should get a total of 6 vmas
    ASSERT_EQ(vmas.size(), 6);

    // Expect values to be equal to what we have in testdata1/smaps_short
    // Check for sizes first
    ASSERT_EQ(vmas[0].usage.vss, 32768);
    EXPECT_EQ(vmas[1].usage.vss, 11204);
    EXPECT_EQ(vmas[2].usage.vss, 16896);
    EXPECT_EQ(vmas[3].usage.vss, 260);
    EXPECT_EQ(vmas[4].usage.vss, 6060);
    EXPECT_EQ(vmas[5].usage.vss, 4);

    // Check for names
    EXPECT_EQ(vmas[0].name, "[anon:dalvik-zygote-jit-code-cache]");
    EXPECT_EQ(vmas[1].name, "/system/framework/x86_64/boot-framework.art");
    EXPECT_EQ(vmas[2].name, "[anon:libc_malloc]");
    EXPECT_EQ(vmas[3].name, "/system/priv-app/SettingsProvider/oat/x86_64/SettingsProvider.odex");
    EXPECT_EQ(vmas[4].name, "/system/lib64/libhwui.so");
    EXPECT_EQ(vmas[5].name, "[vsyscall]");

    EXPECT_EQ(vmas[0].usage.rss, 2048);
    EXPECT_EQ(vmas[1].usage.rss, 11188);
    EXPECT_EQ(vmas[2].usage.rss, 15272);
    EXPECT_EQ(vmas[3].usage.rss, 260);
    EXPECT_EQ(vmas[4].usage.rss, 4132);
    EXPECT_EQ(vmas[5].usage.rss, 0);

    EXPECT_EQ(vmas[0].usage.pss, 113);
    EXPECT_EQ(vmas[1].usage.pss, 2200);
    EXPECT_EQ(vmas[2].usage.pss, 15272);
    EXPECT_EQ(vmas[3].usage.pss, 260);
    EXPECT_EQ(vmas[4].usage.pss, 1274);
    EXPECT_EQ(vmas[5].usage.pss, 0);

    EXPECT_EQ(vmas[0].usage.uss, 0);
    EXPECT_EQ(vmas[1].usage.uss, 1660);
    EXPECT_EQ(vmas[2].usage.uss, 15272);
    EXPECT_EQ(vmas[3].usage.uss, 260);
    EXPECT_EQ(vmas[4].usage.uss, 0);
    EXPECT_EQ(vmas[5].usage.uss, 0);

    EXPECT_EQ(vmas[0].usage.private_clean, 0);
    EXPECT_EQ(vmas[1].usage.private_clean, 0);
    EXPECT_EQ(vmas[2].usage.private_clean, 0);
    EXPECT_EQ(vmas[3].usage.private_clean, 260);
    EXPECT_EQ(vmas[4].usage.private_clean, 0);
    EXPECT_EQ(vmas[5].usage.private_clean, 0);

    EXPECT_EQ(vmas[0].usage.private_dirty, 0);
    EXPECT_EQ(vmas[1].usage.private_dirty, 1660);
    EXPECT_EQ(vmas[2].usage.private_dirty, 15272);
    EXPECT_EQ(vmas[3].usage.private_dirty, 0);
    EXPECT_EQ(vmas[4].usage.private_dirty, 0);
    EXPECT_EQ(vmas[5].usage.private_dirty, 0);

    EXPECT_EQ(vmas[0].usage.shared_clean, 0);
    EXPECT_EQ(vmas[1].usage.shared_clean, 80);
    EXPECT_EQ(vmas[2].usage.shared_clean, 0);
    EXPECT_EQ(vmas[3].usage.shared_clean, 0);
    EXPECT_EQ(vmas[4].usage.shared_clean, 4132);
    EXPECT_EQ(vmas[5].usage.shared_clean, 0);

    EXPECT_EQ(vmas[0].usage.shared_dirty, 2048);
    EXPECT_EQ(vmas[1].usage.shared_dirty, 9448);
    EXPECT_EQ(vmas[2].usage.shared_dirty, 0);
    EXPECT_EQ(vmas[3].usage.shared_dirty, 0);
    EXPECT_EQ(vmas[4].usage.shared_dirty, 0);
    EXPECT_EQ(vmas[5].usage.shared_dirty, 0);

    EXPECT_EQ(vmas[0].usage.swap, 0);
    EXPECT_EQ(vmas[1].usage.swap, 0);
    EXPECT_EQ(vmas[2].usage.swap, 0);
    EXPECT_EQ(vmas[3].usage.swap, 0);
    EXPECT_EQ(vmas[4].usage.swap, 0);
    EXPECT_EQ(vmas[5].usage.swap, 0);

    EXPECT_EQ(vmas[0].usage.swap_pss, 0);
    EXPECT_EQ(vmas[1].usage.swap_pss, 0);
    EXPECT_EQ(vmas[2].usage.swap_pss, 0);
    EXPECT_EQ(vmas[3].usage.swap_pss, 0);
    EXPECT_EQ(vmas[4].usage.swap_pss, 0);
    EXPECT_EQ(vmas[5].usage.swap_pss, 0);
}

TEST(SysMemInfo, TestSysMemInfoFile) {
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
SwapTotal:         32768 kB
SwapFree:           4096 kB
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
VmallocUsed:       65536 kB
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
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(meminfo, tf.fd));

    SysMemInfo mi;
    ASSERT_TRUE(mi.ReadMemInfo(tf.path));
    EXPECT_EQ(mi.mem_total_kb(), 3019740);
    EXPECT_EQ(mi.mem_free_kb(), 1809728);
    EXPECT_EQ(mi.mem_buffers_kb(), 54736);
    EXPECT_EQ(mi.mem_cached_kb(), 776052);
    EXPECT_EQ(mi.mem_shmem_kb(), 4020);
    EXPECT_EQ(mi.mem_slab_kb(), 86464);
    EXPECT_EQ(mi.mem_slab_reclaimable_kb(), 44432);
    EXPECT_EQ(mi.mem_slab_unreclaimable_kb(), 42032);
    EXPECT_EQ(mi.mem_swap_kb(), 32768);
    EXPECT_EQ(mi.mem_swap_free_kb(), 4096);
    EXPECT_EQ(mi.mem_mapped_kb(), 62624);
    EXPECT_EQ(mi.mem_vmalloc_used_kb(), 65536);
    EXPECT_EQ(mi.mem_page_tables_kb(), 2900);
    EXPECT_EQ(mi.mem_kernel_stack_kb(), 4880);
}

TEST(SysMemInfo, TestEmptyFile) {
    TemporaryFile tf;
    std::string empty_string = "";
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(empty_string, tf.fd));

    SysMemInfo mi;
    EXPECT_TRUE(mi.ReadMemInfo(tf.path));
    EXPECT_EQ(mi.mem_total_kb(), 0);
}

TEST(SysMemInfo, TestZramTotal) {
    std::string exec_dir = ::android::base::GetExecutableDirectory();

    SysMemInfo mi;
    std::string zram_mmstat_dir = exec_dir + "/testdata1/";
    EXPECT_EQ(mi.mem_zram_kb(zram_mmstat_dir), 30504);

    std::string zram_memused_dir = exec_dir + "/testdata2/";
    EXPECT_EQ(mi.mem_zram_kb(zram_memused_dir), 30504);
}

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

TEST(SysMemInfo, TestZramWithTags) {
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
SwapTotal:         32768 kB
SwapFree:           4096 kB
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
VmallocUsed:       65536 kB
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
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(meminfo, tf.fd));
    std::string file = std::string(tf.path);
    std::vector<uint64_t> mem(MEMINFO_COUNT);
    std::vector<std::string> tags(SysMemInfo::kDefaultSysMemInfoTags);
    auto it = tags.begin();
    tags.insert(it + MEMINFO_ZRAM_TOTAL, "Zram:");
    SysMemInfo mi;

    // Read system memory info
    EXPECT_TRUE(mi.ReadMemInfo(tags, &mem, file));

    EXPECT_EQ(mem[MEMINFO_TOTAL], 3019740);
    EXPECT_EQ(mem[MEMINFO_FREE], 1809728);
    EXPECT_EQ(mem[MEMINFO_BUFFERS], 54736);
    EXPECT_EQ(mem[MEMINFO_CACHED], 776052);
    EXPECT_EQ(mem[MEMINFO_SHMEM], 4020);
    EXPECT_EQ(mem[MEMINFO_SLAB], 86464);
    EXPECT_EQ(mem[MEMINFO_SLAB_RECLAIMABLE], 44432);
    EXPECT_EQ(mem[MEMINFO_SLAB_UNRECLAIMABLE], 42032);
    EXPECT_EQ(mem[MEMINFO_SWAP_TOTAL], 32768);
    EXPECT_EQ(mem[MEMINFO_SWAP_FREE], 4096);
    EXPECT_EQ(mem[MEMINFO_MAPPED], 62624);
    EXPECT_EQ(mem[MEMINFO_VMALLOC_USED], 65536);
    EXPECT_EQ(mem[MEMINFO_PAGE_TABLES], 2900);
    EXPECT_EQ(mem[MEMINFO_KERNEL_STACK], 4880);
}

TEST(SysMemInfo, TestVmallocInfoNoMemory) {
    std::string vmallocinfo =
            R"vmallocinfo(0x0000000000000000-0x0000000000000000   69632 of_iomap+0x78/0xb0 phys=17a00000 ioremap
0x0000000000000000-0x0000000000000000    8192 of_iomap+0x78/0xb0 phys=b220000 ioremap
0x0000000000000000-0x0000000000000000    8192 of_iomap+0x78/0xb0 phys=17c90000 ioremap
0x0000000000000000-0x0000000000000000    8192 of_iomap+0x78/0xb0 phys=17ca0000 ioremap)vmallocinfo";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(vmallocinfo, tf.fd));
    std::string file = std::string(tf.path);

    EXPECT_EQ(ReadVmallocInfo(file), 0);
}

TEST(SysMemInfo, TestVmallocInfoKernel) {
    std::string vmallocinfo =
            R"vmallocinfo(0x0000000000000000-0x0000000000000000    8192 drm_property_create_blob+0x44/0xec pages=1 vmalloc)vmallocinfo";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(vmallocinfo, tf.fd));
    std::string file = std::string(tf.path);

    EXPECT_EQ(ReadVmallocInfo(file), getpagesize());
}

TEST(SysMemInfo, TestVmallocInfoModule) {
    std::string vmallocinfo =
            R"vmallocinfo(0x0000000000000000-0x0000000000000000   28672 pktlog_alloc_buf+0xc4/0x15c [wlan] pages=6 vmalloc)vmallocinfo";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(vmallocinfo, tf.fd));
    std::string file = std::string(tf.path);

    EXPECT_EQ(ReadVmallocInfo(file), 6 * getpagesize());
}

TEST(SysMemInfo, TestVmallocInfoAll) {
    std::string vmallocinfo =
            R"vmallocinfo(0x0000000000000000-0x0000000000000000   69632 of_iomap+0x78/0xb0 phys=17a00000 ioremap
0x0000000000000000-0x0000000000000000    8192 of_iomap+0x78/0xb0 phys=b220000 ioremap
0x0000000000000000-0x0000000000000000    8192 of_iomap+0x78/0xb0 phys=17c90000 ioremap
0x0000000000000000-0x0000000000000000    8192 of_iomap+0x78/0xb0 phys=17ca0000 ioremap
0x0000000000000000-0x0000000000000000    8192 drm_property_create_blob+0x44/0xec pages=1 vmalloc
0x0000000000000000-0x0000000000000000   28672 pktlog_alloc_buf+0xc4/0x15c [wlan] pages=6 vmalloc)vmallocinfo";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(vmallocinfo, tf.fd));
    std::string file = std::string(tf.path);

    EXPECT_EQ(ReadVmallocInfo(file), 7 * getpagesize());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::android::base::InitLogging(argv, android::base::StderrLogger);
    pid = getpid();
    return RUN_ALL_TESTS();
}
