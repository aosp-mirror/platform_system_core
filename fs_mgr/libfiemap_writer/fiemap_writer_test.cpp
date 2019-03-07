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
#include <sys/vfs.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <libdm/loop_control.h>
#include <libfiemap_writer/fiemap_writer.h>
#include <libfiemap_writer/split_fiemap_writer.h>

#include "utility.h"

namespace android {
namespace fiemap_writer {

using namespace std;
using namespace std::string_literals;
using namespace android::fiemap_writer;
using unique_fd = android::base::unique_fd;
using LoopDevice = android::dm::LoopDevice;

std::string gTestDir;
uint64_t testfile_size = 536870912;  // default of 512MiB
size_t gBlockSize = 0;

class FiemapWriterTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const ::testing::TestInfo* tinfo = ::testing::UnitTest::GetInstance()->current_test_info();
        testfile = gTestDir + "/"s + tinfo->name();
    }

    void TearDown() override { unlink(testfile.c_str()); }

    // name of the file we use for testing
    std::string testfile;
};

class SplitFiemapTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const ::testing::TestInfo* tinfo = ::testing::UnitTest::GetInstance()->current_test_info();
        testfile = gTestDir + "/"s + tinfo->name();
    }

    void TearDown() override {
        std::string message;
        if (!SplitFiemap::RemoveSplitFiles(testfile, &message)) {
            cerr << "Could not remove all split files: " << message;
        }
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
    // to be unaligned to all known block sizes.
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, gBlockSize + 1);
    ASSERT_NE(fptr, nullptr);
    ASSERT_EQ(fptr->size(), gBlockSize * 2);
}

TEST_F(FiemapWriterTest, CheckFilePath) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, gBlockSize);
    ASSERT_NE(fptr, nullptr);
    EXPECT_EQ(fptr->size(), gBlockSize);
    EXPECT_EQ(fptr->file_path(), testfile);
    EXPECT_EQ(access(testfile.c_str(), F_OK), 0);
}

TEST_F(FiemapWriterTest, CheckProgress) {
    std::vector<uint64_t> expected;
    size_t invocations = 0;
    auto callback = [&](uint64_t done, uint64_t total) -> bool {
        EXPECT_LT(invocations, expected.size());
        EXPECT_EQ(done, expected[invocations]);
        EXPECT_EQ(total, gBlockSize);
        invocations++;
        return true;
    };

    uint32_t fs_type;
    {
        auto ptr = FiemapWriter::Open(testfile, gBlockSize, true);
        ASSERT_NE(ptr, nullptr);
        fs_type = ptr->fs_type();
    }
    ASSERT_EQ(unlink(testfile.c_str()), 0);

    if (fs_type != MSDOS_SUPER_MAGIC) {
        expected.push_back(0);
    }
    expected.push_back(gBlockSize);

    auto ptr = FiemapWriter::Open(testfile, gBlockSize, true, std::move(callback));
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(invocations, expected.size());
}

TEST_F(FiemapWriterTest, CheckPinning) {
    auto ptr = FiemapWriter::Open(testfile, 4096);
    ASSERT_NE(ptr, nullptr);
    EXPECT_TRUE(FiemapWriter::HasPinnedExtents(testfile));
}

TEST_F(FiemapWriterTest, CheckBlockDevicePath) {
    FiemapUniquePtr fptr = FiemapWriter::Open(testfile, gBlockSize);
    EXPECT_EQ(fptr->size(), gBlockSize);
    EXPECT_EQ(fptr->bdev_path().find("/dev/block/"), size_t(0));
    EXPECT_EQ(fptr->bdev_path().find("/dev/block/dm-"), string::npos);
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

TEST_F(FiemapWriterTest, ExistingFile) {
    // Create the file.
    { ASSERT_NE(FiemapWriter::Open(testfile, gBlockSize), nullptr); }
    // Test that we can still open it.
    {
        auto ptr = FiemapWriter::Open(testfile, 0, false);
        ASSERT_NE(ptr, nullptr);
        EXPECT_GT(ptr->extents().size(), 0);
    }
}

TEST_F(FiemapWriterTest, FileDeletedOnError) {
    auto callback = [](uint64_t, uint64_t) -> bool { return false; };
    auto ptr = FiemapWriter::Open(testfile, gBlockSize, true, std::move(callback));
    EXPECT_EQ(ptr, nullptr);
    EXPECT_EQ(access(testfile.c_str(), F_OK), -1);
    EXPECT_EQ(errno, ENOENT);
}

TEST_F(FiemapWriterTest, MaxBlockSize) {
    ASSERT_GT(DetermineMaximumFileSize(testfile), 0);
}

TEST_F(SplitFiemapTest, Create) {
    auto ptr = SplitFiemap::Create(testfile, 1024 * 768, 1024 * 32);
    ASSERT_NE(ptr, nullptr);

    auto extents = ptr->extents();

    // Destroy the fiemap, closing file handles. This should not delete them.
    ptr = nullptr;

    std::vector<std::string> files;
    ASSERT_TRUE(SplitFiemap::GetSplitFileList(testfile, &files));
    for (const auto& path : files) {
        EXPECT_EQ(access(path.c_str(), F_OK), 0);
    }

    ASSERT_GE(extents.size(), files.size());
}

TEST_F(SplitFiemapTest, Open) {
    {
        auto ptr = SplitFiemap::Create(testfile, 1024 * 768, 1024 * 32);
        ASSERT_NE(ptr, nullptr);
    }

    auto ptr = SplitFiemap::Open(testfile);
    ASSERT_NE(ptr, nullptr);

    auto extents = ptr->extents();
    ASSERT_GE(extents.size(), 24);
}

TEST_F(SplitFiemapTest, DeleteOnFail) {
    auto ptr = SplitFiemap::Create(testfile, 1024 * 1024 * 10, 1);
    ASSERT_EQ(ptr, nullptr);

    std::string first_file = testfile + ".0001";
    ASSERT_NE(access(first_file.c_str(), F_OK), 0);
    ASSERT_EQ(errno, ENOENT);
    ASSERT_NE(access(testfile.c_str(), F_OK), 0);
    ASSERT_EQ(errno, ENOENT);
}

static string ReadSplitFiles(const std::string& base_path, size_t num_files) {
    std::string result;
    for (int i = 0; i < num_files; i++) {
        std::string path = base_path + android::base::StringPrintf(".%04d", i);
        std::string data;
        if (!android::base::ReadFileToString(path, &data)) {
            return {};
        }
        result += data;
    }
    return result;
}

TEST_F(SplitFiemapTest, WriteWholeFile) {
    static constexpr size_t kChunkSize = 32768;
    static constexpr size_t kSize = kChunkSize * 3;
    auto ptr = SplitFiemap::Create(testfile, kSize, kChunkSize);
    ASSERT_NE(ptr, nullptr);

    auto buffer = std::make_unique<int[]>(kSize / sizeof(int));
    for (size_t i = 0; i < kSize / sizeof(int); i++) {
        buffer[i] = i;
    }
    ASSERT_TRUE(ptr->Write(buffer.get(), kSize));

    std::string expected(reinterpret_cast<char*>(buffer.get()), kSize);
    auto actual = ReadSplitFiles(testfile, 3);
    ASSERT_EQ(expected.size(), actual.size());
    EXPECT_EQ(memcmp(expected.data(), actual.data(), actual.size()), 0);
}

TEST_F(SplitFiemapTest, WriteFileInChunks1) {
    static constexpr size_t kChunkSize = 32768;
    static constexpr size_t kSize = kChunkSize * 3;
    auto ptr = SplitFiemap::Create(testfile, kSize, kChunkSize);
    ASSERT_NE(ptr, nullptr);

    auto buffer = std::make_unique<int[]>(kSize / sizeof(int));
    for (size_t i = 0; i < kSize / sizeof(int); i++) {
        buffer[i] = i;
    }

    // Write in chunks of 1000 (so some writes straddle the boundary of two
    // files).
    size_t bytes_written = 0;
    while (bytes_written < kSize) {
        size_t to_write = std::min(kSize - bytes_written, (size_t)1000);
        char* data = reinterpret_cast<char*>(buffer.get()) + bytes_written;
        ASSERT_TRUE(ptr->Write(data, to_write));
        bytes_written += to_write;
    }

    std::string expected(reinterpret_cast<char*>(buffer.get()), kSize);
    auto actual = ReadSplitFiles(testfile, 3);
    ASSERT_EQ(expected.size(), actual.size());
    EXPECT_EQ(memcmp(expected.data(), actual.data(), actual.size()), 0);
}

TEST_F(SplitFiemapTest, WriteFileInChunks2) {
    static constexpr size_t kChunkSize = 32768;
    static constexpr size_t kSize = kChunkSize * 3;
    auto ptr = SplitFiemap::Create(testfile, kSize, kChunkSize);
    ASSERT_NE(ptr, nullptr);

    auto buffer = std::make_unique<int[]>(kSize / sizeof(int));
    for (size_t i = 0; i < kSize / sizeof(int); i++) {
        buffer[i] = i;
    }

    // Write in chunks of 32KiB so every write is exactly at the end of the
    // current file.
    size_t bytes_written = 0;
    while (bytes_written < kSize) {
        size_t to_write = std::min(kSize - bytes_written, kChunkSize);
        char* data = reinterpret_cast<char*>(buffer.get()) + bytes_written;
        ASSERT_TRUE(ptr->Write(data, to_write));
        bytes_written += to_write;
    }

    std::string expected(reinterpret_cast<char*>(buffer.get()), kSize);
    auto actual = ReadSplitFiles(testfile, 3);
    ASSERT_EQ(expected.size(), actual.size());
    EXPECT_EQ(memcmp(expected.data(), actual.data(), actual.size()), 0);
}

TEST_F(SplitFiemapTest, WritePastEnd) {
    static constexpr size_t kChunkSize = 32768;
    static constexpr size_t kSize = kChunkSize * 3;
    auto ptr = SplitFiemap::Create(testfile, kSize, kChunkSize);
    ASSERT_NE(ptr, nullptr);

    auto buffer = std::make_unique<int[]>(kSize / sizeof(int));
    for (size_t i = 0; i < kSize / sizeof(int); i++) {
        buffer[i] = i;
    }
    ASSERT_TRUE(ptr->Write(buffer.get(), kSize));
    ASSERT_FALSE(ptr->Write(buffer.get(), kSize));
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

bool DetermineBlockSize() {
    struct statfs s;
    if (statfs(gTestDir.c_str(), &s)) {
        std::cerr << "Could not call statfs: " << strerror(errno) << "\n";
        return false;
    }
    if (!s.f_bsize) {
        std::cerr << "Invalid block size: " << s.f_bsize << "\n";
        return false;
    }

    gBlockSize = s.f_bsize;
    return true;
}

}  // namespace fiemap_writer
}  // namespace android

using namespace android::fiemap_writer;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (argc <= 1) {
        cerr << "Usage: <test_dir> [file_size]\n";
        cerr << "\n";
        cerr << "Note: test_dir must be a writable directory.\n";
        exit(EXIT_FAILURE);
    }
    ::android::base::InitLogging(argv, ::android::base::StderrLogger);

    std::string tempdir = argv[1] + "/XXXXXX"s;
    if (!mkdtemp(tempdir.data())) {
        cerr << "unable to create tempdir on " << argv[1] << "\n";
        exit(EXIT_FAILURE);
    }
    if (!android::base::Realpath(tempdir, &gTestDir)) {
        cerr << "unable to find realpath for " << tempdir;
        exit(EXIT_FAILURE);
    }

    if (argc > 2) {
        testfile_size = strtoull(argv[2], NULL, 0);
        if (testfile_size == ULLONG_MAX) {
            testfile_size = 512 * 1024 * 1024;
        }
    }

    if (!DetermineBlockSize()) {
        exit(EXIT_FAILURE);
    }

    auto result = RUN_ALL_TESTS();

    std::string cmd = "rm -rf " + gTestDir;
    system(cmd.c_str());

    return result;
}
