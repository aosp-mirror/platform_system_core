/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <linux/fs.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>
#include <cutils/ashmem.h>
#include <gtest/gtest.h>

#include "ashmem-internal.h"

using android::base::unique_fd;

static void TestCreateRegion(size_t size, unique_fd &fd, int prot) {
    fd = unique_fd(ashmem_create_region(nullptr, size));
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    ASSERT_EQ(size, static_cast<size_t>(ashmem_get_size_region(fd)));
    ASSERT_EQ(0, ashmem_set_prot_region(fd, prot));

    // We've been inconsistent historically about whether or not these file
    // descriptors were CLOEXEC. Make sure we're consistent going forward.
    // https://issuetracker.google.com/165667331
    ASSERT_EQ(FD_CLOEXEC, (fcntl(fd, F_GETFD) & FD_CLOEXEC));
}

static void TestMmap(const unique_fd& fd, size_t size, int prot, void** region, off_t off = 0) {
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    *region = mmap(nullptr, size, prot, MAP_SHARED, fd, off);
    ASSERT_NE(MAP_FAILED, *region);
}

static void TestProtDenied(const unique_fd &fd, size_t size, int prot) {
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    EXPECT_EQ(MAP_FAILED, mmap(nullptr, size, prot, MAP_SHARED, fd, 0));
}

static void TestProtIs(const unique_fd& fd, int prot) {
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    EXPECT_EQ(prot, ioctl(fd, ASHMEM_GET_PROT_MASK));
}

static void FillData(std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = i & 0xFF;
    }
}

static void waitForChildProcessExit(pid_t pid) {
    int exitStatus;
    pid_t childPid = waitpid(pid, &exitStatus, 0);

    ASSERT_GT(childPid, 0);
    ASSERT_TRUE(WIFEXITED(exitStatus));
    ASSERT_EQ(0, WEXITSTATUS(exitStatus));
}

static void ForkTest(const unique_fd &fd, size_t size) {
    void* region1 = nullptr;
    std::vector<uint8_t> data(size);
    FillData(data);

    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region1));

    memcpy(region1, data.data(), size);
    ASSERT_EQ(0, memcmp(region1, data.data(), size));
    EXPECT_EQ(0, munmap(region1, size));


    pid_t pid = fork();
    if (!pid) {
        if (!ashmem_valid(fd)) {
            _exit(3);
        }

        void *region2 = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (region2 == MAP_FAILED) {
            _exit(1);
        } else if (memcmp(region2, data.data(), size) != 0){
            _exit(2);
        }

        // Clear the ashmem buffer here to ensure that updates to the contents
        // of the buffer are visible across processes with a reference to the
        // buffer.
        memset(region2, 0, size);
        munmap(region2, size);
        _exit(0);
    } else {
        ASSERT_GT(pid, 0);
        ASSERT_NO_FATAL_FAILURE(waitForChildProcessExit(pid));
    }

    memset(data.data(), 0, size);
    void *region2;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region2));
    ASSERT_EQ(0, memcmp(region2, data.data(), size));
    EXPECT_EQ(0, munmap(region2, size));
}

static void FileOperationsTest(const unique_fd &fd, size_t size) {
    void* region = nullptr;

    const size_t pageSize = getpagesize();
    const size_t dataSize = pageSize * 2;
    const size_t holeSize = pageSize;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, dataSize, PROT_READ | PROT_WRITE, &region, holeSize));

    std::vector<uint8_t> data(dataSize);
    FillData(data);
    memcpy(region, data.data(), dataSize);

    const off_t dataStart = holeSize;
    const off_t dataEnd = dataStart + dataSize;

    // The sequence of seeks below looks something like this:
    //
    // [    ][data][data][    ]
    // --^                          lseek(99, SEEK_SET)
    //   ------^                    lseek(dataStart, SEEK_CUR)
    // ------^                      lseek(0, SEEK_DATA)
    //       ------------^          lseek(dataStart, SEEK_HOLE)
    //                      ^--     lseek(-99, SEEK_END)
    //                ^------       lseek(-dataStart, SEEK_CUR)
    const struct {
        // lseek() parameters
        off_t offset;
        int whence;
        // Expected lseek() return value
        off_t ret;
    } seeks[] = {
            {99, SEEK_SET, 99},
            {dataStart, SEEK_CUR, dataStart + 99},
            {0, SEEK_DATA, dataStart},
            {dataStart, SEEK_HOLE, dataEnd},
            {-99, SEEK_END, static_cast<off_t>(size) - 99},
            {-dataStart, SEEK_CUR, dataEnd - 99},
    };
    for (const auto& cfg : seeks) {
        errno = 0;
        ASSERT_TRUE(ashmem_valid(fd));
        auto off = lseek(fd, cfg.offset, cfg.whence);
        ASSERT_EQ(cfg.ret, off) << "lseek(" << cfg.offset << ", " << cfg.whence << ") failed"
                                << (errno ? ": " : "") << (errno ? strerror(errno) : "");

        if (off >= dataStart && off < dataEnd) {
            off_t dataOff = off - dataStart;
            ssize_t readSize = dataSize - dataOff;
            uint8_t buf[readSize];

            ASSERT_EQ(readSize, TEMP_FAILURE_RETRY(read(fd, buf, readSize)));
            EXPECT_EQ(0, memcmp(buf, &data[dataOff], readSize));
        }
    }

    EXPECT_EQ(0, munmap(region, dataSize));
}

static void ProtTestROBuffer(const unique_fd &fd, size_t size) {
    void *region;

    TestProtDenied(fd, size, PROT_WRITE);
    TestProtIs(fd, PROT_READ | PROT_EXEC);
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ, &region));
    EXPECT_EQ(0, munmap(region, size));
}

static void ProtTestRWBuffer(const unique_fd &fd, size_t size) {
    TestProtIs(fd, PROT_READ | PROT_WRITE | PROT_EXEC);
    ASSERT_EQ(0, ashmem_set_prot_region(fd, PROT_READ | PROT_EXEC));
    errno = 0;
    ASSERT_EQ(-1, ashmem_set_prot_region(fd, PROT_READ | PROT_WRITE |
                                         PROT_EXEC))
        << "kernel shouldn't allow adding protection bits";
    EXPECT_EQ(EINVAL, errno);
    TestProtIs(fd, PROT_READ | PROT_EXEC);
    TestProtDenied(fd, size, PROT_WRITE);
}

static void ForkProtTest(const unique_fd &fd, size_t size) {
    pid_t pid = fork();
    if (!pid) {
        // Change buffer mapping permissions to read-only to ensure that
        // updates to the buffer's mapping permissions are visible across
        // processes that reference the buffer.
        if (!ashmem_valid(fd)) {
            _exit(3);
        } else if (ashmem_set_prot_region(fd, PROT_READ) == -1) {
            _exit(1);
        }
        _exit(0);
    } else {
        ASSERT_GT(pid, 0);
        ASSERT_NO_FATAL_FAILURE(waitForChildProcessExit(pid));
    }

    ASSERT_NO_FATAL_FAILURE(TestProtDenied(fd, size, PROT_WRITE));
}

static void ForkMultiRegionTest(unique_fd fds[], int nRegions, size_t size) {
    std::vector<uint8_t> data(size);
    FillData(data);

    for (int i = 0; i < nRegions; i++) {
        void* region = nullptr;
        ASSERT_NO_FATAL_FAILURE(TestMmap(fds[i], size, PROT_READ | PROT_WRITE, &region));
        memcpy(region, data.data(), size);
        ASSERT_EQ(0, memcmp(region, data.data(), size));
        EXPECT_EQ(0, munmap(region, size));
    }

    pid_t pid = fork();
    if (!pid) {
        // Clear each ashmem buffer in the context of the child process to
        // ensure that the updates are visible to the parent process later.
        for (int i = 0; i < nRegions; i++) {
            if (!ashmem_valid(fds[i])) {
                _exit(3);
            }
            void *region = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fds[i], 0);
            if (region == MAP_FAILED) {
                _exit(1);
            }
            if (memcmp(region, data.data(), size) != 0) {
                munmap(region, size);
                _exit(2);
            }
            memset(region, 0, size);
            munmap(region, size);
        }
        _exit(0);
    } else {
        ASSERT_GT(pid, 0);
        ASSERT_NO_FATAL_FAILURE(waitForChildProcessExit(pid));
    }

    memset(data.data(), 0, size);
    for (int i = 0; i < nRegions; i++) {
        void *region;
        ASSERT_NO_FATAL_FAILURE(TestMmap(fds[i], size, PROT_READ | PROT_WRITE, &region));
        ASSERT_EQ(0, memcmp(region, data.data(), size));
        EXPECT_EQ(0, munmap(region, size));
    }

}

TEST(AshmemTest, ForkTest) {
    const size_t size = getpagesize();
    unique_fd fd;

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
    ASSERT_NO_FATAL_FAILURE(ForkTest(fd, size));
}

TEST(AshmemTest, FileOperationsTest) {
    const size_t pageSize = getpagesize();
    // Allocate a 4-page buffer, but leave page-sized holes on either side in
    // the test.
    const size_t size = pageSize * 4;
    unique_fd fd;

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
    ASSERT_NO_FATAL_FAILURE(FileOperationsTest(fd, size));
}

TEST(AshmemTest, ProtTest) {
    unique_fd fd;
    const size_t size = getpagesize();

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_EXEC));
    ASSERT_NO_FATAL_FAILURE(ProtTestROBuffer(fd, size));

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE | PROT_EXEC));
    ASSERT_NO_FATAL_FAILURE(ProtTestRWBuffer(fd, size));
}

TEST(AshmemTest, ForkProtTest) {
    unique_fd fd;
    const size_t size = getpagesize();

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
    ASSERT_NO_FATAL_FAILURE(ForkProtTest(fd, size));
}

TEST(AshmemTest, ForkMultiRegionTest) {
    const size_t size = getpagesize();
    constexpr int nRegions = 16;
    unique_fd fds[nRegions];

    for (int i = 0; i < nRegions; i++) {
        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fds[i], PROT_READ | PROT_WRITE));
    }

    ASSERT_NO_FATAL_FAILURE(ForkMultiRegionTest(fds, nRegions, size));
}

class AshmemTestMemfdAshmemCompat : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!has_memfd_support()){
        GTEST_SKIP() << "No memfd support; skipping memfd-ashmem compat tests";
    }
  }
};

TEST_F(AshmemTestMemfdAshmemCompat, SetNameTest) {
    unique_fd fd;

    // ioctl() should fail, since memfd names cannot be changed after the buffer has been created.
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
                                                                PROT_EXEC));
    ASSERT_LT(ioctl(fd, ASHMEM_SET_NAME, "invalid-command"), 0);
}

TEST_F(AshmemTestMemfdAshmemCompat, GetNameTest) {
    unique_fd fd;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
                                                                PROT_EXEC));

    char testBuf[ASHMEM_NAME_LEN];
    ASSERT_EQ(0, ioctl(fd, ASHMEM_GET_NAME, &testBuf));
    // ashmem_create_region(nullptr, ...) creates memfds with the name "none".
    ASSERT_STREQ(testBuf, "none");
}

TEST_F(AshmemTestMemfdAshmemCompat, SetSizeTest) {
    unique_fd fd;

    // ioctl() should fail, since libcutils sets and seals the buffer size after creating it.
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
                                                                PROT_EXEC));
    ASSERT_LT(ioctl(fd, ASHMEM_SET_SIZE, 2 * getpagesize()), 0);
}

TEST_F(AshmemTestMemfdAshmemCompat, GetSizeTest) {
    unique_fd fd;
    size_t bufSize = getpagesize();

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(bufSize, fd, PROT_READ | PROT_WRITE | PROT_EXEC));
    ASSERT_EQ(static_cast<int>(bufSize), ioctl(fd, ASHMEM_GET_SIZE, 0));
}

TEST_F(AshmemTestMemfdAshmemCompat, ProtMaskTest) {
    unique_fd fd;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
                                                                PROT_EXEC));

    // We can only change PROT_WRITE for memfds since memfd implements ashmem's prot_mask through
    // file seals, and only write seals exist.
    //
    // All memfd files start off as being writable (i.e. PROT_WRITE is part of the prot_mask).
    // Test to ensure that the implementation only clears the PROT_WRITE bit when requested.
    ASSERT_EQ(0, ioctl(fd, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_WRITE | PROT_EXEC));
    int prot = ioctl(fd, ASHMEM_GET_PROT_MASK, 0);
    ASSERT_NE(prot, -1);
    ASSERT_TRUE(prot & PROT_WRITE) << prot;

    ASSERT_EQ(0, ioctl(fd, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_EXEC));
    prot = ioctl(fd, ASHMEM_GET_PROT_MASK, 0);
    ASSERT_NE(prot, -1);
    ASSERT_TRUE(!(prot & PROT_WRITE)) << prot;

    // The shim layer should implement clearing PROT_WRITE via file seals, so check the file
    // seals to ensure that F_SEAL_FUTURE_WRITE is set.
    int seals = fcntl(fd, F_GET_SEALS, 0);
    ASSERT_NE(seals, -1);
    ASSERT_TRUE(seals & F_SEAL_FUTURE_WRITE) << seals;

    // Similarly, ensure that file seals affect prot_mask
    unique_fd fd2;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd2, PROT_READ | PROT_WRITE |
                                                                PROT_EXEC));
    ASSERT_EQ(0, fcntl(fd2, F_ADD_SEALS, F_SEAL_FUTURE_WRITE));
    prot = ioctl(fd2, ASHMEM_GET_PROT_MASK, 0);
    ASSERT_NE(prot, -1);
    ASSERT_TRUE(!(prot & PROT_WRITE)) << prot;

    // And finally, ensure that adding back permissions fails
    ASSERT_LT(ioctl(fd2, ASHMEM_SET_PROT_MASK, PROT_READ | PROT_WRITE | PROT_EXEC), 0);
}

TEST_F(AshmemTestMemfdAshmemCompat, FileIDTest) {
    unique_fd fd;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
                                                                PROT_EXEC));

    unsigned long ino;
    ASSERT_EQ(0, ioctl(fd, ASHMEM_GET_FILE_ID, &ino));
    struct stat st;
    ASSERT_EQ(0, fstat(fd, &st));
    ASSERT_EQ(ino, st.st_ino);
}

TEST_F(AshmemTestMemfdAshmemCompat, UnpinningTest) {
    unique_fd fd;
    size_t bufSize = getpagesize();
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(getpagesize(), fd, PROT_READ | PROT_WRITE |
                                                                PROT_EXEC));

    struct ashmem_pin pin = {
        .offset = 0,
        .len = static_cast<uint32_t>(bufSize),
    };
    ASSERT_EQ(0, ioctl(fd, ASHMEM_UNPIN, &pin));
    // ASHMEM_UNPIN should just be a nop
    ASSERT_EQ(ASHMEM_IS_PINNED, ioctl(fd, ASHMEM_GET_PIN_STATUS, 0));

    // This shouldn't do anything; when we pin the page, it shouldn't have been purged.
    ASSERT_EQ(0, ioctl(fd, ASHMEM_PURGE_ALL_CACHES, 0));
    ASSERT_EQ(ASHMEM_NOT_PURGED, ioctl(fd, ASHMEM_PIN, &pin));
}