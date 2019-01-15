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

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libdm/loop_control.h>

#include <libfiemap_writer/fiemap_writer.h>

using namespace std;
using namespace android::fiemap_writer;
using unique_fd = android::base::unique_fd;
using LoopDevice = android::dm::LoopDevice;

std::string testbdev = "";
uint64_t testfile_size = 536870912;  // default of 512MiB

class FiemapWriterTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const ::testing::TestInfo* tinfo = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string exec_dir = ::android::base::GetExecutableDirectory();
        testfile = ::android::base::StringPrintf("%s/testdata/%s", exec_dir.c_str(), tinfo->name());
    }

    // name of the file we use for testing
    std::string testfile;
};

TEST_F(FiemapWriterTest, CreateImpossiblyLargeFile) {
    // Try creating a file of size ~100TB but aligned to
    // 512 byte to make sure block alignment tests don't
    // fail.
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, 1099511627997184);
    EXPECT_EQ(fptr, nullptr);
    EXPECT_EQ(access(testfile.c_str(), F_OK), -1);
    EXPECT_EQ(errno, ENOENT);
}

TEST_F(FiemapWriterTest, CreateUnalignedFile) {
    // Try creating a file of size 4097 bytes which is guaranteed
    // to be unaligned to all known block sizes. The creation must
    // fail.
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, 4097);
    EXPECT_EQ(fptr, nullptr);
    EXPECT_EQ(access(testfile.c_str(), F_OK), -1);
    EXPECT_EQ(errno, ENOENT);
}

TEST_F(FiemapWriterTest, CheckFilePath) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, 4096);
    ASSERT_NE(fptr, nullptr);
    EXPECT_EQ(fptr->size(), 4096);
    EXPECT_EQ(fptr->file_path(), testfile);
    EXPECT_EQ(access(testfile.c_str(), F_OK), 0);
}

TEST_F(FiemapWriterTest, CheckBlockDevicePath) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, 4096);
    EXPECT_EQ(fptr->size(), 4096);
    EXPECT_EQ(fptr->bdev_path(), testbdev);
}

TEST_F(FiemapWriterTest, CheckFileCreated) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, 32768);
    ASSERT_NE(fptr, nullptr);
    unique_fd fd(open(testfile.c_str(), O_RDONLY));
    EXPECT_GT(fd, -1);
}

TEST_F(FiemapWriterTest, CheckFileSizeActual) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, testfile_size);
    ASSERT_NE(fptr, nullptr);

    struct stat sb;
    ASSERT_EQ(stat(testfile.c_str(), &sb), 0);
    EXPECT_EQ(sb.st_size, testfile_size);
}

TEST_F(FiemapWriterTest, CheckFileExtents) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, testfile_size);
    ASSERT_NE(fptr, nullptr);
    EXPECT_GT(fptr->extents().size(), 0);
}

TEST_F(FiemapWriterTest, CheckWriteError) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, testfile_size);
    ASSERT_NE(fptr, nullptr);

    // prepare buffer for writing the pattern - 0xa0
    uint64_t blocksize = fptr->block_size();
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, blocksize), free);
    ASSERT_NE(buffer, nullptr);
    memset(buffer.get(), 0xa0, blocksize);

    uint8_t* p = static_cast<uint8_t*>(buffer.get());
    for (off64_t off = 0; off < testfile_size; off += blocksize) {
        ASSERT_TRUE(fptr->Write(off, p, blocksize));
    }

    EXPECT_TRUE(fptr->Flush());
}

class TestExistingFile : public ::testing::Test {
  protected:
    void SetUp() override {
        std::string exec_dir = ::android::base::GetExecutableDirectory();
        std::string unaligned_file = exec_dir + "/testdata/unaligned_file";
        std::string file_4k = exec_dir + "/testdata/file_4k";
        std::string file_32k = exec_dir + "/testdata/file_32k";
        fptr_unaligned = FiemapWriter::Open(unaligned_file, 4097, false);
        fptr_4k = FiemapWriter::Open(file_4k, 4096, false);
        fptr_32k = FiemapWriter::Open(file_32k, 32768, false);
    }

    FiemapUniquePtr fptr_unaligned;
    FiemapUniquePtr fptr_4k;
    FiemapUniquePtr fptr_32k;
};

TEST_F(TestExistingFile, ErrorChecks) {
    EXPECT_EQ(fptr_unaligned, nullptr);
    EXPECT_NE(fptr_4k, nullptr);
    EXPECT_NE(fptr_32k, nullptr);

    EXPECT_EQ(fptr_4k->size(), 4096);
    EXPECT_EQ(fptr_32k->size(), 32768);
    EXPECT_GT(fptr_4k->extents().size(), 0);
    EXPECT_GT(fptr_32k->extents().size(), 0);
}

TEST_F(TestExistingFile, CheckWriteError) {
    ASSERT_NE(fptr_4k, nullptr);
    // prepare buffer for writing the pattern - 0xa0
    uint64_t blocksize = fptr_4k->block_size();
    auto buff_4k = std::unique_ptr<void, decltype(&free)>(calloc(1, blocksize), free);
    ASSERT_NE(buff_4k, nullptr);
    memset(buff_4k.get(), 0xa0, blocksize);

    uint8_t* p = static_cast<uint8_t*>(buff_4k.get());
    for (off64_t off = 0; off < 4096; off += blocksize) {
        ASSERT_TRUE(fptr_4k->Write(off, p, blocksize));
    }
    EXPECT_TRUE(fptr_4k->Flush());

    ASSERT_NE(fptr_32k, nullptr);
    // prepare buffer for writing the pattern - 0xa0
    blocksize = fptr_32k->block_size();
    auto buff_32k = std::unique_ptr<void, decltype(&free)>(calloc(1, blocksize), free);
    ASSERT_NE(buff_32k, nullptr);
    memset(buff_32k.get(), 0xa0, blocksize);
    p = static_cast<uint8_t*>(buff_32k.get());
    for (off64_t off = 0; off < 4096; off += blocksize) {
        ASSERT_TRUE(fptr_32k->Write(off, p, blocksize));
    }
    EXPECT_TRUE(fptr_32k->Flush());
}

class VerifyBlockWritesExt4 : public ::testing::Test {
    // 2GB Filesystem and 4k block size by default
    static constexpr uint64_t block_size = 4096;
    static constexpr uint64_t fs_size = 2147483648;

  protected:
    void SetUp() override {
        fs_path = std::string(getenv("TMPDIR")) + "/ext4_2G.img";
        uint64_t count = fs_size / block_size;
        std::string dd_cmd =
                ::android::base::StringPrintf("/system/bin/dd if=/dev/zero of=%s bs=%" PRIu64
                                              " count=%" PRIu64 " > /dev/null 2>&1",
                                              fs_path.c_str(), block_size, count);
        std::string mkfs_cmd =
                ::android::base::StringPrintf("/system/bin/mkfs.ext4 -q %s", fs_path.c_str());
        // create mount point
        mntpoint = std::string(getenv("TMPDIR")) + "/fiemap_mnt";
        ASSERT_EQ(mkdir(mntpoint.c_str(), S_IRWXU), 0);
        // create file for the file system
        int ret = system(dd_cmd.c_str());
        ASSERT_EQ(ret, 0);
        // Get and attach a loop device to the filesystem we created
        LoopDevice loop_dev(fs_path);
        ASSERT_TRUE(loop_dev.valid());
        // create file system
        ret = system(mkfs_cmd.c_str());
        ASSERT_EQ(ret, 0);

        // mount the file system
        ASSERT_EQ(mount(loop_dev.device().c_str(), mntpoint.c_str(), "ext4", 0, nullptr), 0);
    }

    void TearDown() override {
        umount(mntpoint.c_str());
        rmdir(mntpoint.c_str());
        unlink(fs_path.c_str());
    }

    std::string mntpoint;
    std::string fs_path;
};

TEST_F(VerifyBlockWritesExt4, CheckWrites) {
    EXPECT_EQ(access(fs_path.c_str(), F_OK), 0);

    std::string file_path = mntpoint + "/testfile";
    uint64_t file_size = 100 * 1024 * 1024;
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, getpagesize()), free);
    ASSERT_NE(buffer, nullptr);
    memset(buffer.get(), 0xa0, getpagesize());
    {
        // scoped fiemap writer
        FiemapUniquePtr fptr = FiemapWriter::Open(file_path, file_size);
        ASSERT_NE(fptr, nullptr);
        uint8_t* p = static_cast<uint8_t*>(buffer.get());
        for (off64_t off = 0; off < file_size / getpagesize(); off += getpagesize()) {
            ASSERT_TRUE(fptr->Write(off, p, getpagesize()));
        }
        EXPECT_TRUE(fptr->Flush());
    }
    // unmount file system here to make sure we invalidated all page cache and
    // remount the filesystem again for verification
    ASSERT_EQ(umount(mntpoint.c_str()), 0);

    LoopDevice loop_dev(fs_path);
    ASSERT_TRUE(loop_dev.valid());
    ASSERT_EQ(mount(loop_dev.device().c_str(), mntpoint.c_str(), "ext4", 0, nullptr), 0)
            << "failed to mount: " << loop_dev.device() << " on " << mntpoint << ": "
            << strerror(errno);

    ::android::base::unique_fd fd(open(file_path.c_str(), O_RDONLY | O_SYNC));
    ASSERT_NE(fd, -1);
    auto filebuf = std::unique_ptr<void, decltype(&free)>(calloc(1, getpagesize()), free);
    ASSERT_NE(filebuf, nullptr);
    for (off64_t off = 0; off < file_size / getpagesize(); off += getpagesize()) {
        memset(filebuf.get(), 0x00, getpagesize());
        ASSERT_EQ(pread64(fd, filebuf.get(), getpagesize(), off), getpagesize());
        ASSERT_EQ(memcmp(filebuf.get(), buffer.get(), getpagesize()), 0)
                << "Invalid pattern at offset: " << off << " size " << getpagesize();
    }
}

class VerifyBlockWritesF2fs : public ::testing::Test {
    // 2GB Filesystem and 4k block size by default
    static constexpr uint64_t block_size = 4096;
    static constexpr uint64_t fs_size = 2147483648;

  protected:
    void SetUp() override {
        fs_path = std::string(getenv("TMPDIR")) + "/f2fs_2G.img";
        uint64_t count = fs_size / block_size;
        std::string dd_cmd =
                ::android::base::StringPrintf("/system/bin/dd if=/dev/zero of=%s bs=%" PRIu64
                                              " count=%" PRIu64 " > /dev/null 2>&1",
                                              fs_path.c_str(), block_size, count);
        std::string mkfs_cmd =
                ::android::base::StringPrintf("/system/bin/make_f2fs -q %s", fs_path.c_str());
        // create mount point
        mntpoint = std::string(getenv("TMPDIR")) + "/fiemap_mnt";
        ASSERT_EQ(mkdir(mntpoint.c_str(), S_IRWXU), 0);
        // create file for the file system
        int ret = system(dd_cmd.c_str());
        ASSERT_EQ(ret, 0);
        // Get and attach a loop device to the filesystem we created
        LoopDevice loop_dev(fs_path);
        ASSERT_TRUE(loop_dev.valid());
        // create file system
        ret = system(mkfs_cmd.c_str());
        ASSERT_EQ(ret, 0);

        // mount the file system
        ASSERT_EQ(mount(loop_dev.device().c_str(), mntpoint.c_str(), "f2fs", 0, nullptr), 0);
    }

    void TearDown() override {
        umount(mntpoint.c_str());
        rmdir(mntpoint.c_str());
        unlink(fs_path.c_str());
    }

    std::string mntpoint;
    std::string fs_path;
};

TEST_F(VerifyBlockWritesF2fs, CheckWrites) {
    EXPECT_EQ(access(fs_path.c_str(), F_OK), 0);

    std::string file_path = mntpoint + "/testfile";
    uint64_t file_size = 100 * 1024 * 1024;
    auto buffer = std::unique_ptr<void, decltype(&free)>(calloc(1, getpagesize()), free);
    ASSERT_NE(buffer, nullptr);
    memset(buffer.get(), 0xa0, getpagesize());
    {
        // scoped fiemap writer
        FiemapUniquePtr fptr = FiemapWriter::Open(file_path, file_size);
        ASSERT_NE(fptr, nullptr);
        uint8_t* p = static_cast<uint8_t*>(buffer.get());
        for (off64_t off = 0; off < file_size / getpagesize(); off += getpagesize()) {
            ASSERT_TRUE(fptr->Write(off, p, getpagesize()));
        }
        EXPECT_TRUE(fptr->Flush());
    }
    // unmount file system here to make sure we invalidated all page cache and
    // remount the filesystem again for verification
    ASSERT_EQ(umount(mntpoint.c_str()), 0);

    LoopDevice loop_dev(fs_path);
    ASSERT_TRUE(loop_dev.valid());
    ASSERT_EQ(mount(loop_dev.device().c_str(), mntpoint.c_str(), "f2fs", 0, nullptr), 0)
            << "failed to mount: " << loop_dev.device() << " on " << mntpoint << ": "
            << strerror(errno);

    ::android::base::unique_fd fd(open(file_path.c_str(), O_RDONLY | O_SYNC));
    ASSERT_NE(fd, -1);
    auto filebuf = std::unique_ptr<void, decltype(&free)>(calloc(1, getpagesize()), free);
    ASSERT_NE(filebuf, nullptr);
    for (off64_t off = 0; off < file_size / getpagesize(); off += getpagesize()) {
        memset(filebuf.get(), 0x00, getpagesize());
        ASSERT_EQ(pread64(fd, filebuf.get(), getpagesize(), off), getpagesize());
        ASSERT_EQ(memcmp(filebuf.get(), buffer.get(), getpagesize()), 0)
                << "Invalid pattern at offset: " << off << " size " << getpagesize();
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (argc <= 1) {
        cerr << "Filepath with its bdev path must be provided as follows:" << endl;
        cerr << "  $ fiemap_writer_test </dev/block/XXXX" << endl;
        cerr << "  where, /dev/block/XXX is the block device where the file resides" << endl;
        exit(EXIT_FAILURE);
    }
    ::android::base::InitLogging(argv, ::android::base::StderrLogger);

    testbdev = argv[1];
    if (argc > 2) {
        testfile_size = strtoull(argv[2], NULL, 0);
        if (testfile_size == ULLONG_MAX) {
            testfile_size = 512 * 1024 * 1024;
        }
    }

    return RUN_ALL_TESTS();
}
