/* Copyright (C) 2019 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <linux/dma-buf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <ion/ion.h>

#include <dmabufinfo/dmabufinfo.h>

using namespace ::android::dmabufinfo;
using namespace ::android::base;

#define MAX_HEAP_NAME 32
#define ION_HEAP_ANY_MASK (0x7fffffff)

struct ion_heap_data {
    char name[MAX_HEAP_NAME];
    __u32 type;
    __u32 heap_id;
    __u32 reserved0;
    __u32 reserved1;
    __u32 reserved2;
};

#ifndef DMA_BUF_SET_NAME
#define DMA_BUF_SET_NAME _IOW(DMA_BUF_BASE, 5, const char*)
#endif

#define EXPECT_ONE_BUF_EQ(_bufptr, _name, _fdrefs, _maprefs, _expname, _count, _size) \
    do {                                                                              \
        EXPECT_EQ(_bufptr->name(), _name);                                            \
        EXPECT_EQ(_bufptr->fdrefs().size(), _fdrefs);                                 \
        EXPECT_EQ(_bufptr->maprefs().size(), _maprefs);                               \
        EXPECT_EQ(_bufptr->exporter(), _expname);                                     \
        EXPECT_EQ(_bufptr->count(), _count);                                          \
        EXPECT_EQ(_bufptr->size(), _size);                                            \
    } while (0)

#define EXPECT_PID_IN_FDREFS(_bufptr, _pid, _expect)                         \
    do {                                                                     \
        const std::unordered_map<pid_t, int>& _fdrefs = _bufptr->fdrefs();   \
        auto _ref = _fdrefs.find(_pid);                                      \
        EXPECT_EQ((_ref != _fdrefs.end()), _expect);                         \
    } while (0)

#define EXPECT_PID_IN_MAPREFS(_bufptr, _pid, _expect)                        \
    do {                                                                     \
        const std::unordered_map<pid_t, int>& _maprefs = _bufptr->maprefs(); \
        auto _ref = _maprefs.find(_pid);                                     \
        EXPECT_EQ((_ref != _maprefs.end()), _expect);                        \
    } while (0)

TEST(DmaBufInfoParser, TestReadDmaBufInfo) {
    std::string bufinfo = R"bufinfo(00045056    00000002    00000007    00000002    ion 00022069    
	Attached Devices:
Total 0 devices attached
01048576    00000002    00000007    00000001    ion 00019834    CAMERA
	Attached Devices:
	soc:qcom,cam_smmu:msm_cam_smmu_icp
Total 1 devices attached)bufinfo";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(::android::base::WriteStringToFd(bufinfo, tf.fd));
    std::string path = std::string(tf.path);

    std::vector<DmaBuffer> dmabufs;
    EXPECT_TRUE(ReadDmaBufInfo(&dmabufs, path));

    EXPECT_EQ(dmabufs.size(), 2UL);

    EXPECT_EQ(dmabufs[0].size(), 45056UL);
    EXPECT_EQ(dmabufs[0].inode(), 22069UL);
    EXPECT_EQ(dmabufs[0].count(), 2UL);
    EXPECT_EQ(dmabufs[0].exporter(), "ion");
    EXPECT_TRUE(dmabufs[0].name().empty());
    EXPECT_EQ(dmabufs[0].total_refs(), 0ULL);
    EXPECT_TRUE(dmabufs[0].fdrefs().empty());
    EXPECT_TRUE(dmabufs[0].maprefs().empty());

    EXPECT_EQ(dmabufs[1].size(), 1048576UL);
    EXPECT_EQ(dmabufs[1].inode(), 19834UL);
    EXPECT_EQ(dmabufs[1].count(), 1UL);
    EXPECT_EQ(dmabufs[1].exporter(), "ion");
    EXPECT_FALSE(dmabufs[1].name().empty());
    EXPECT_EQ(dmabufs[1].name(), "CAMERA");
    EXPECT_EQ(dmabufs[1].total_refs(), 0ULL);
    EXPECT_TRUE(dmabufs[1].fdrefs().empty());
    EXPECT_TRUE(dmabufs[1].maprefs().empty());
}

class DmaBufTester : public ::testing::Test {
  public:
    DmaBufTester() : ion_fd(ion_open()), ion_heap_mask(get_ion_heap_mask()) {}

    ~DmaBufTester() {
        if (is_valid()) {
            ion_close(ion_fd);
        }
    }

    bool is_valid() { return (ion_fd >= 0 && ion_heap_mask > 0); }

    unique_fd allocate(uint64_t size, const std::string& name) {
        int fd;
        int err = ion_alloc_fd(ion_fd, size, 0, ion_heap_mask, 0, &fd);
        if (err < 0) {
            return unique_fd{err};
        }

        if (!name.empty()) {
            err = ioctl(fd, DMA_BUF_SET_NAME, name.c_str());
            if (err < 0) return unique_fd{-errno};
        }

        return unique_fd{fd};
    }

  private:
    int get_ion_heap_mask() {
        if (ion_fd < 0) {
            return 0;
        }

        if (ion_is_legacy(ion_fd)) {
            // Since ION is still in staging, we've seen that the heap mask ids are also
            // changed across kernels for some reason. So, here we basically ask for a buffer
            // from _any_ heap.
            return ION_HEAP_ANY_MASK;
        }

        int cnt;
        int err = ion_query_heap_cnt(ion_fd, &cnt);
        if (err < 0) {
            return err;
        }

        std::vector<ion_heap_data> heaps;
        heaps.resize(cnt);
        err = ion_query_get_heaps(ion_fd, cnt, &heaps[0]);
        if (err < 0) {
            return err;
        }

        unsigned int ret = 0;
        for (auto& it : heaps) {
            if (!strcmp(it.name, "ion_system_heap")) {
                ret |= (1 << it.heap_id);
            }
        }

        return ret;
    }

    unique_fd ion_fd;
    const int ion_heap_mask;
};

TEST_F(DmaBufTester, TestFdRef) {
    // Test if a dma buffer is found while the corresponding file descriptor
    // is open
    ASSERT_TRUE(is_valid());
    pid_t pid = getpid();
    std::vector<DmaBuffer> dmabufs;
    {
        // Allocate one buffer and make sure the library can see it
        unique_fd buf = allocate(4096, "dmabuftester-4k");
        ASSERT_GT(buf, 0) << "Allocated buffer is invalid";
        ASSERT_TRUE(ReadDmaBufInfo(pid, &dmabufs));

        EXPECT_EQ(dmabufs.size(), 1UL);
        EXPECT_ONE_BUF_EQ(dmabufs.begin(), "dmabuftester-4k", 1UL, 0UL, "ion", 1UL, 4096ULL);

        // Make sure the buffer has the right pid too.
        EXPECT_PID_IN_FDREFS(dmabufs.begin(), pid, false);
    }

    // Now make sure the buffer has disappeared
    ASSERT_TRUE(ReadDmaBufInfo(pid, &dmabufs));
    EXPECT_TRUE(dmabufs.empty());
}

TEST_F(DmaBufTester, TestMapRef) {
    // Test to make sure we can find a buffer if the fd is closed but the buffer
    // is mapped
    ASSERT_TRUE(is_valid());
    pid_t pid = getpid();
    std::vector<DmaBuffer> dmabufs;
    {
        // Allocate one buffer and make sure the library can see it
        unique_fd buf = allocate(4096, "dmabuftester-4k");
        ASSERT_GT(buf, 0) << "Allocated buffer is invalid";
        auto ptr = mmap(0, 4096, PROT_READ, MAP_SHARED, buf, 0);
        ASSERT_NE(ptr, MAP_FAILED);
        ASSERT_TRUE(ReadDmaBufInfo(pid, &dmabufs));

        EXPECT_EQ(dmabufs.size(), 1UL);
        EXPECT_ONE_BUF_EQ(dmabufs.begin(), "dmabuftester-4k", 1UL, 1UL, "ion", 2UL, 4096ULL);

        // Make sure the buffer has the right pid too.
        EXPECT_PID_IN_FDREFS(dmabufs.begin(), pid, false);
        EXPECT_PID_IN_MAPREFS(dmabufs.begin(), pid, false);

        // close the file descriptor and re-read the stats
        buf.reset(-1);
        ASSERT_TRUE(ReadDmaBufInfo(pid, &dmabufs));

        EXPECT_EQ(dmabufs.size(), 1UL);
        EXPECT_ONE_BUF_EQ(dmabufs.begin(), "<unknown>", 0UL, 1UL, "<unknown>", 0UL, 4096ULL);

        EXPECT_PID_IN_FDREFS(dmabufs.begin(), pid, true);
        EXPECT_PID_IN_MAPREFS(dmabufs.begin(), pid, false);

        // unmap the bufer and lose all references
        munmap(ptr, 4096);
    }

    // Now make sure the buffer has disappeared
    ASSERT_TRUE(ReadDmaBufInfo(pid, &dmabufs));
    EXPECT_TRUE(dmabufs.empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::android::base::InitLogging(argv, android::base::StderrLogger);
    return RUN_ALL_TESTS();
}
