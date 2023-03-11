/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <filesystem>
#include <optional>
#include <string_view>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/result.h>
#include <android-base/strings.h>
#include <bootimg.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libavb/libavb.h>

#include "vendor_boot_img_utils.h"

using android::base::borrowed_fd;
using android::base::ErrnoError;
using android::base::GetExecutableDirectory;
using android::base::ReadFdToString;
using android::base::Result;
using testing::AllOf;
using testing::Each;
using testing::Eq;
using testing::HasSubstr;
using testing::Not;
using testing::Property;
using std::string_literals::operator""s;

// Expect that the Result<T> returned by |expr| is successful, and value matches |result_matcher|.
#define EXPECT_RESULT(expr, result_matcher)                          \
    EXPECT_THAT(expr, AllOf(Property(&decltype(expr)::ok, Eq(true)), \
                            Property(&decltype(expr)::value, result_matcher)))

// Expect that the Result<T> returned by |expr| fails, and error message matches |error_matcher|.
#define EXPECT_ERROR(expr, error_matcher)                                                        \
    do {                                                                                         \
        EXPECT_THAT(                                                                             \
                expr,                                                                            \
                AllOf(Property(&decltype(expr)::ok, Eq(false)),                                  \
                      Property(&decltype(expr)::error,                                           \
                               Property(&decltype(expr)::error_type::message, error_matcher)))); \
    } while (0)

namespace {

// Wrapper of fstat.
Result<uint64_t> FileSize(borrowed_fd fd, std::filesystem::path path) {
    struct stat sb;
    if (fstat(fd.get(), &sb) == -1) return ErrnoError() << "fstat(" << path << ")";
    return sb.st_size;
}

// Seek to beginning then read the whole file.
Result<std::string> ReadStartOfFdToString(borrowed_fd fd, std::filesystem::path path) {
    if (lseek(fd.get(), 0, SEEK_SET) != 0)
        return ErrnoError() << "lseek(" << path << ", 0, SEEK_SET)";
    std::string content;
    if (!android::base::ReadFdToString(fd, &content)) return ErrnoError() << "read(" << path << ")";
    return content;
}

// Round |value| up to page boundary.
inline uint32_t round_up(uint32_t value, uint32_t page_size) {
    return (value + page_size - 1) / page_size * page_size;
}

// Match is successful if |arg| is a zero-padded version of |expected|.
MATCHER_P(IsPadded, expected, (negation ? "is" : "isn't") + " zero-padded of expected value"s) {
    if (arg.size() < expected.size()) return false;
    if (0 != memcmp(arg.data(), expected.data(), expected.size())) return false;
    auto remainder = std::string_view(arg).substr(expected.size());
    for (char e : remainder)
        if (e != '\0') return false;
    return true;
}

// Same as Eq, but don't print the content to avoid spam.
MATCHER_P(MemEq, expected, (negation ? "is" : "isn't") + " expected value"s) {
    if (arg.size() != expected.size()) return false;
    return 0 == memcmp(arg.data(), expected.data(), expected.size());
}

// Expect that |arg| and |expected| has the same AVB footer.
MATCHER_P(HasSameAvbFooter, expected,
          (negation ? "has" : "does not have") + "expected AVB footer"s) {
    if (expected.size() < AVB_FOOTER_SIZE || arg.size() < AVB_FOOTER_SIZE) return false;
    return std::string_view(expected).substr(expected.size() - AVB_FOOTER_SIZE) ==
           std::string_view(arg).substr(arg.size() - AVB_FOOTER_SIZE);
}

// A lazy handle of a file.
struct TestFileHandle {
    virtual ~TestFileHandle() = default;
    // Lazily call OpenImpl(), cache result in open_result_.
    android::base::Result<void> Open() {
        if (!open_result_.has_value()) open_result_ = OpenImpl();
        return open_result_.value();
    }
    // The original size at the time when the file is opened. If the file has been modified,
    // this field is NOT updated.
    uint64_t size() {
        CHECK(open_result_.has_value());
        return size_;
    }
    // The current size of the file. If the file has been modified since opened,
    // this is updated.
    Result<uint64_t> fsize() {
        CHECK(open_result_.has_value());
        return FileSize(fd_, abs_path_);
    }
    borrowed_fd fd() {
        CHECK(open_result_.has_value());
        return fd_;
    }
    Result<std::string> Read() {
        CHECK(open_result_.has_value());
        return ReadStartOfFdToString(fd_, abs_path_);
    }

  private:
    std::filesystem::path abs_path_;
    uint64_t size_;
    std::optional<android::base::Result<void>> open_result_;
    borrowed_fd fd_{-1};
    // Opens |rel_path_| as a readonly fd, pass it to Transform, and store result to
    // |borrowed_fd_|.
    android::base::Result<void> OpenImpl() {
        android::base::unique_fd read_fd(TEMP_FAILURE_RETRY(
                open(abs_path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_BINARY)));
        if (!read_fd.ok()) return ErrnoError() << "open(" << abs_path_ << ")";
        auto size = FileSize(read_fd, abs_path_);
        if (!size.ok()) return size.error();
        size_ = *size;

        auto borrowed_fd = Transform(abs_path_, std::move(read_fd));
        if (!borrowed_fd.ok()) return borrowed_fd.error();
        fd_ = borrowed_fd.value();

        return {};
    }

  protected:
    // |rel_path| is the relative path under test data directory.
    TestFileHandle(const std::filesystem::path& rel_path)
        : abs_path_(std::move(std::filesystem::path(GetExecutableDirectory()) / rel_path)) {}
    // Given |read_fd|, the readonly fd on the test file, return an fd that's suitable for client
    // to use. Implementation is responsible for managing the lifetime of the returned fd.
    virtual android::base::Result<borrowed_fd> Transform(const std::filesystem::path& abs_path,
                                                         android::base::unique_fd read_fd) = 0;
};

// A TestFileHandle where the file is readonly.
struct ReadOnlyTestFileHandle : TestFileHandle {
    ReadOnlyTestFileHandle(const std::filesystem::path& rel_path) : TestFileHandle(rel_path) {}

  private:
    android::base::unique_fd owned_fd_;
    android::base::Result<borrowed_fd> Transform(const std::filesystem::path&,
                                                 android::base::unique_fd read_fd) override {
        owned_fd_ = std::move(read_fd);
        return owned_fd_;
    }
};

// A TestFileHandle where the test file is copies, hence read-writable.
struct ReadWriteTestFileHandle : TestFileHandle {
    ReadWriteTestFileHandle(const std::filesystem::path& rel_path) : TestFileHandle(rel_path) {}

  private:
    std::unique_ptr<TemporaryFile> temp_file_;

    android::base::Result<borrowed_fd> Transform(const std::filesystem::path& abs_path,
                                                 android::base::unique_fd read_fd) override {
        // Make a copy to avoid writing to test data. Test files are small, so it is okay
        // to read the whole file.
        auto content = ReadStartOfFdToString(read_fd, abs_path);
        if (!content.ok()) return content.error();
        temp_file_ = std::make_unique<TemporaryFile>();
        if (temp_file_->fd == -1)
            return ErrnoError() << "copy " << abs_path << ": open temp file failed";
        if (!android::base::WriteStringToFd(*content, temp_file_->fd))
            return ErrnoError() << "copy " << abs_path << ": write temp file failed";

        return temp_file_->fd;
    }
};

class RepackVendorBootImgTestEnv : public ::testing::Environment {
  public:
    virtual void SetUp() {
        OpenTestFile("test_dtb.img", &dtb, &dtb_content);
        OpenTestFile("test_bootconfig.img", &bootconfig, &bootconfig_content);
        OpenTestFile("test_vendor_ramdisk_none.img", &none, &none_content);
        OpenTestFile("test_vendor_ramdisk_platform.img", &platform, &platform_content);
        OpenTestFile("test_vendor_ramdisk_replace.img", &replace, &replace_content);
    }

    std::unique_ptr<TestFileHandle> dtb;
    std::string dtb_content;
    std::unique_ptr<TestFileHandle> bootconfig;
    std::string bootconfig_content;
    std::unique_ptr<TestFileHandle> none;
    std::string none_content;
    std::unique_ptr<TestFileHandle> platform;
    std::string platform_content;
    std::unique_ptr<TestFileHandle> replace;
    std::string replace_content;

  private:
    void OpenTestFile(const char* rel_path, std::unique_ptr<TestFileHandle>* handle,
                      std::string* content) {
        *handle = std::make_unique<ReadOnlyTestFileHandle>(rel_path);
        ASSERT_RESULT_OK((*handle)->Open());
        auto content_res = (*handle)->Read();
        ASSERT_RESULT_OK(content_res);
        *content = *content_res;
    }
};
RepackVendorBootImgTestEnv* env = nullptr;

struct RepackVendorBootImgTestParam {
    std::string vendor_boot_file_name;
    uint32_t expected_header_version;
    friend std::ostream& operator<<(std::ostream& os, const RepackVendorBootImgTestParam& param) {
        return os << param.vendor_boot_file_name;
    }
};

class RepackVendorBootImgTest : public ::testing::TestWithParam<RepackVendorBootImgTestParam> {
  public:
    virtual void SetUp() {
        vboot = std::make_unique<ReadWriteTestFileHandle>(GetParam().vendor_boot_file_name);
        ASSERT_RESULT_OK(vboot->Open());
    }
    std::unique_ptr<TestFileHandle> vboot;
};

TEST_P(RepackVendorBootImgTest, InvalidSize) {
    EXPECT_ERROR(replace_vendor_ramdisk(vboot->fd(), vboot->size() + 1, "default",
                                        env->replace->fd(), env->replace->size()),
                 HasSubstr("Size of vendor boot does not match"));
    EXPECT_ERROR(replace_vendor_ramdisk(vboot->fd(), vboot->size(), "default", env->replace->fd(),
                                        env->replace->size() + 1),
                 HasSubstr("Size of new vendor ramdisk does not match"));
}

TEST_P(RepackVendorBootImgTest, ReplaceUnknown) {
    auto res = replace_vendor_ramdisk(vboot->fd(), vboot->size(), "unknown", env->replace->fd(),
                                      env->replace->size());
    if (GetParam().expected_header_version == 3) {
        EXPECT_ERROR(res, Eq("Require vendor boot header V4 but is V3"));
    } else if (GetParam().expected_header_version == 4) {
        EXPECT_ERROR(res, Eq("Vendor ramdisk 'unknown' not found"));
    }
}

TEST_P(RepackVendorBootImgTest, ReplaceDefault) {
    auto old_content = vboot->Read();
    ASSERT_RESULT_OK(old_content);

    ASSERT_RESULT_OK(replace_vendor_ramdisk(vboot->fd(), vboot->size(), "default",
                                            env->replace->fd(), env->replace->size()));
    EXPECT_RESULT(vboot->fsize(), vboot->size()) << "File size should not change after repack";

    auto new_content_res = vboot->Read();
    ASSERT_RESULT_OK(new_content_res);
    std::string_view new_content(*new_content_res);

    auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v3*>(new_content.data());
    ASSERT_EQ(0, memcmp(VENDOR_BOOT_MAGIC, hdr->magic, VENDOR_BOOT_MAGIC_SIZE));
    ASSERT_EQ(GetParam().expected_header_version, hdr->header_version);
    EXPECT_EQ(hdr->vendor_ramdisk_size, env->replace->size());
    EXPECT_EQ(hdr->dtb_size, env->dtb->size());

    auto o = round_up(sizeof(vendor_boot_img_hdr_v3), hdr->page_size);
    auto p = round_up(hdr->vendor_ramdisk_size, hdr->page_size);
    auto q = round_up(hdr->dtb_size, hdr->page_size);

    EXPECT_THAT(new_content.substr(o, p), IsPadded(env->replace_content));
    EXPECT_THAT(new_content.substr(o + p, q), IsPadded(env->dtb_content));

    if (hdr->header_version < 4) return;

    auto hdr_v4 = static_cast<const vendor_boot_img_hdr_v4*>(hdr);
    EXPECT_EQ(hdr_v4->vendor_ramdisk_table_entry_num, 1);
    EXPECT_EQ(hdr_v4->vendor_ramdisk_table_size, 1 * hdr_v4->vendor_ramdisk_table_entry_size);
    EXPECT_GE(hdr_v4->vendor_ramdisk_table_entry_size, sizeof(vendor_ramdisk_table_entry_v4));
    auto entry = reinterpret_cast<const vendor_ramdisk_table_entry_v4*>(&new_content[o + p + q]);
    EXPECT_EQ(entry->ramdisk_offset, 0);
    EXPECT_EQ(entry->ramdisk_size, hdr_v4->vendor_ramdisk_size);
    EXPECT_EQ(entry->ramdisk_type, VENDOR_RAMDISK_TYPE_NONE);

    EXPECT_EQ(hdr_v4->bootconfig_size, env->bootconfig->size());
    auto r = round_up(hdr_v4->vendor_ramdisk_table_size, hdr_v4->page_size);
    auto s = round_up(hdr_v4->bootconfig_size, hdr_v4->page_size);
    EXPECT_THAT(new_content.substr(o + p + q + r, s), IsPadded(env->bootconfig_content));

    EXPECT_THAT(new_content, HasSameAvbFooter(*old_content));
}

INSTANTIATE_TEST_SUITE_P(
        RepackVendorBootImgTest, RepackVendorBootImgTest,
        ::testing::Values(RepackVendorBootImgTestParam{"vendor_boot_v3.img", 3},
                          RepackVendorBootImgTestParam{"vendor_boot_v4_with_frag.img", 4},
                          RepackVendorBootImgTestParam{"vendor_boot_v4_without_frag.img", 4}),
        [](const auto& info) {
            return android::base::StringReplace(info.param.vendor_boot_file_name, ".", "_", false);
        });

std::string_view GetRamdiskName(const vendor_ramdisk_table_entry_v4* entry) {
    auto ramdisk_name = reinterpret_cast<const char*>(entry->ramdisk_name);
    return std::string_view(ramdisk_name, strnlen(ramdisk_name, VENDOR_RAMDISK_NAME_SIZE));
}

class RepackVendorBootImgTestV4 : public ::testing::TestWithParam<uint32_t /* ramdisk type */> {
  public:
    virtual void SetUp() {
        vboot = std::make_unique<ReadWriteTestFileHandle>("vendor_boot_v4_with_frag.img");
        ASSERT_RESULT_OK(vboot->Open());
    }
    std::unique_ptr<TestFileHandle> vboot;
};

TEST_P(RepackVendorBootImgTestV4, Replace) {
    uint32_t replace_ramdisk_type = GetParam();
    std::string replace_ramdisk_name;
    std::string expect_new_ramdisk_content;
    uint32_t expect_none_size = env->none->size();
    uint32_t expect_platform_size = env->platform->size();
    switch (replace_ramdisk_type) {
        case VENDOR_RAMDISK_TYPE_NONE:
            replace_ramdisk_name = "none_ramdisk";
            expect_new_ramdisk_content = env->replace_content + env->platform_content;
            expect_none_size = env->replace->size();
            break;
        case VENDOR_RAMDISK_TYPE_PLATFORM:
            replace_ramdisk_name = "platform_ramdisk";
            expect_new_ramdisk_content = env->none_content + env->replace_content;
            expect_platform_size = env->replace->size();
            break;
        default:
            LOG(FATAL) << "Ramdisk type " << replace_ramdisk_type
                       << " is not supported by this test.";
    }

    auto old_content = vboot->Read();
    ASSERT_RESULT_OK(old_content);

    ASSERT_RESULT_OK(replace_vendor_ramdisk(vboot->fd(), vboot->size(), replace_ramdisk_name,
                                            env->replace->fd(), env->replace->size()));
    EXPECT_RESULT(vboot->fsize(), vboot->size()) << "File size should not change after repack";

    auto new_content_res = vboot->Read();
    ASSERT_RESULT_OK(new_content_res);
    std::string_view new_content(*new_content_res);

    auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v4*>(new_content.data());
    ASSERT_EQ(0, memcmp(VENDOR_BOOT_MAGIC, hdr->magic, VENDOR_BOOT_MAGIC_SIZE));
    ASSERT_EQ(4, hdr->header_version);
    EXPECT_EQ(hdr->vendor_ramdisk_size, expect_none_size + expect_platform_size);
    EXPECT_EQ(hdr->dtb_size, env->dtb->size());
    EXPECT_EQ(hdr->bootconfig_size, env->bootconfig->size());

    auto o = round_up(sizeof(vendor_boot_img_hdr_v3), hdr->page_size);
    auto p = round_up(hdr->vendor_ramdisk_size, hdr->page_size);
    auto q = round_up(hdr->dtb_size, hdr->page_size);
    auto r = round_up(hdr->vendor_ramdisk_table_size, hdr->page_size);
    auto s = round_up(hdr->bootconfig_size, hdr->page_size);

    EXPECT_THAT(new_content.substr(o, p), IsPadded(expect_new_ramdisk_content));
    EXPECT_THAT(new_content.substr(o + p, q), IsPadded(env->dtb_content));

    // Check changes in table.
    EXPECT_EQ(hdr->vendor_ramdisk_table_entry_num, 2);
    EXPECT_EQ(hdr->vendor_ramdisk_table_size, 2 * hdr->vendor_ramdisk_table_entry_size);
    EXPECT_GE(hdr->vendor_ramdisk_table_entry_size, sizeof(vendor_ramdisk_table_entry_v4));
    auto entry_none =
            reinterpret_cast<const vendor_ramdisk_table_entry_v4*>(&new_content[o + p + q]);
    EXPECT_EQ(entry_none->ramdisk_offset, 0);
    EXPECT_EQ(entry_none->ramdisk_size, expect_none_size);
    EXPECT_EQ(entry_none->ramdisk_type, VENDOR_RAMDISK_TYPE_NONE);
    EXPECT_EQ(GetRamdiskName(entry_none), "none_ramdisk");

    auto entry_platform = reinterpret_cast<const vendor_ramdisk_table_entry_v4*>(
            &new_content[o + p + q + hdr->vendor_ramdisk_table_entry_size]);
    EXPECT_EQ(entry_platform->ramdisk_offset, expect_none_size);
    EXPECT_EQ(entry_platform->ramdisk_size, expect_platform_size);
    EXPECT_EQ(entry_platform->ramdisk_type, VENDOR_RAMDISK_TYPE_PLATFORM);
    EXPECT_EQ(GetRamdiskName(entry_platform), "platform_ramdisk");

    EXPECT_THAT(new_content.substr(o + p + q + r, s), IsPadded(env->bootconfig_content));

    EXPECT_THAT(new_content, HasSameAvbFooter(*old_content));
}
INSTANTIATE_TEST_SUITE_P(RepackVendorBootImgTest, RepackVendorBootImgTestV4,
                         ::testing::Values(VENDOR_RAMDISK_TYPE_NONE, VENDOR_RAMDISK_TYPE_PLATFORM),
                         [](const auto& info) {
                             return info.param == VENDOR_RAMDISK_TYPE_NONE ? "none" : "platform";
                         });

}  // namespace

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    env = static_cast<RepackVendorBootImgTestEnv*>(
            testing::AddGlobalTestEnvironment(new RepackVendorBootImgTestEnv));
    return RUN_ALL_TESTS();
}
