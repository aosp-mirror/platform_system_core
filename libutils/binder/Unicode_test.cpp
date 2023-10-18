/*
 * Copyright (C) 2010 The Android Open Source Project
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

#define LOG_TAG "Unicode_test"

#include <sys/mman.h>
#include <unistd.h>

#include <log/log.h>
#include <utils/Unicode.h>

#include <gtest/gtest.h>

namespace android {

class UnicodeTest : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }

    char16_t const * const kSearchString = u"I am a leaf on the wind.";

    constexpr static size_t BUFSIZE = 64;       // large enough for all tests

    void TestUTF8toUTF16(std::initializer_list<uint8_t> input,
                         std::initializer_list<char16_t> expect,
                         const char* err_msg_length = "",
                         ssize_t expected_length = 0) {
        uint8_t empty_str[] = {};
        char16_t output[BUFSIZE];

        const size_t inlen = input.size(), outlen = expect.size();
        ASSERT_LT(outlen, BUFSIZE);

        const uint8_t *input_data = inlen ? std::data(input) : empty_str;
        ssize_t measured = utf8_to_utf16_length(input_data, inlen);
        EXPECT_EQ(expected_length ? : (ssize_t)outlen, measured) << err_msg_length;

        utf8_to_utf16(input_data, inlen, output, outlen + 1);
        for (size_t i = 0; i < outlen; i++) {
            EXPECT_EQ(std::data(expect)[i], output[i]);
        }
        EXPECT_EQ(0, output[outlen]) << "should be null terminated";
    }

    void TestUTF16toUTF8(std::initializer_list<char16_t> input,
                         std::initializer_list<char> expect,
                         const char* err_msg_length = "",
                         ssize_t expected_length = 0) {
        char16_t empty_str[] = {};
        char output[BUFSIZE];

        const size_t inlen = input.size(), outlen = expect.size();
        ASSERT_LT(outlen, BUFSIZE);

        const char16_t *input_data = inlen ? std::data(input) : empty_str;
        ssize_t measured = utf16_to_utf8_length(input_data, inlen);
        EXPECT_EQ(expected_length ? : (ssize_t)outlen, measured) << err_msg_length;

        utf16_to_utf8(input_data, inlen, output, outlen + 1);
        for (size_t i = 0; i < outlen; i++) {
            EXPECT_EQ(std::data(expect)[i], output[i]);
        }
        EXPECT_EQ(0, output[outlen]) << "should be null terminated";
    }
};

TEST_F(UnicodeTest, UTF8toUTF16ZeroLength) {
    TestUTF8toUTF16({}, {},
        "Zero length input should return zero length output.");
}

TEST_F(UnicodeTest, UTF8toUTF16ASCII) {
    TestUTF8toUTF16(
        { 0x30 },               // U+0030 or ASCII '0'
        { 0x0030 },
        "ASCII codepoints should have a length of 1 char16_t");
}

TEST_F(UnicodeTest, UTF8toUTF16Plane1) {
    TestUTF8toUTF16(
        { 0xE2, 0x8C, 0xA3 },   // U+2323 SMILE
        { 0x2323 },
        "Plane 1 codepoints should have a length of 1 char16_t");
}

TEST_F(UnicodeTest, UTF8toUTF16Surrogate) {
    TestUTF8toUTF16(
        { 0xF0, 0x90, 0x80, 0x80 },   // U+10000
        { 0xD800, 0xDC00 },
        "Surrogate pairs should have a length of 2 char16_t");
}

TEST_F(UnicodeTest, UTF8toUTF16TruncatedUTF8) {
    TestUTF8toUTF16(
        { 0xE2, 0x8C },       // Truncated U+2323 SMILE
        { },                  // Conversion should still work but produce nothing
        "Truncated UTF-8 should return -1 to indicate invalid",
        -1);
}

TEST_F(UnicodeTest, UTF8toUTF16Normal) {
    TestUTF8toUTF16({
        0x30,                   // U+0030, 1 UTF-16 character
        0xC4, 0x80,             // U+0100, 1 UTF-16 character
        0xE2, 0x8C, 0xA3,       // U+2323, 1 UTF-16 character
        0xF0, 0x90, 0x80, 0x80, // U+10000, 2 UTF-16 character
    }, {
        0x0030,
        0x0100,
        0x2323,
        0xD800, 0xDC00
    });
}

TEST_F(UnicodeTest, UTF8toUTF16Invalid) {
    // TODO: The current behavior of utf8_to_utf16 is to treat invalid
    // leading byte (>= 0xf8) as a 4-byte UTF8 sequence, and to treat
    // invalid trailing byte(s) (i.e. bytes not having MSB set) as if
    // they are valid and do the normal conversion. However, a better
    // handling would be to treat invalid sequences as errors, such
    // cases need to be reported and invalid characters (e.g. U+FFFD)
    // could be produced at the place of error.  Until a fix is ready
    // and compatibility is not an issue, we will keep testing the
    // current behavior
    TestUTF8toUTF16({
        0xf8,                   // invalid leading byte
        0xc4, 0x00,             // U+0100 with invalid trailing byte
        0xe2, 0x0c, 0xa3,       // U+2323 with invalid trailing bytes
        0xf0, 0x10, 0x00, 0x00, // U+10000 with invalid trailing bytes
    }, {
        0x4022,                 // invalid leading byte (>=0xfc) is treated
                                // as valid for 4-byte UTF8 sequence
	0x000C,
	0x00A3,                 // invalid leadnig byte (b'10xxxxxx) is
                                // treated as valid single UTF-8 byte
        0xD800,                 // invalid trailing bytes are treated
        0xDC00,                 // as valid bytes and follow normal
    });
}

TEST_F(UnicodeTest, UTF16toUTF8ZeroLength) {
    // TODO: The current behavior of utf16_to_utf8_length() is that
    // it returns -1 if the input is a zero length UTF16 string.
    // This is inconsistent with utf8_to_utf16_length() where a zero
    // length string returns 0.  However, to fix the current behavior,
    // we could have compatibility issue.  Until then, we will keep
    // testing the current behavior
    TestUTF16toUTF8({}, {},
        "Zero length UTF16 input should return length of -1.", -1);
}

TEST_F(UnicodeTest, UTF16toUTF8ASCII) {
    TestUTF16toUTF8(
        { 0x0030 },  // U+0030 or ASCII '0'
        { '\x30' },
        "ASCII codepoints in UTF16 should give a length of 1 in UTF8");
}

TEST_F(UnicodeTest, UTF16toUTF8Plane1) {
    TestUTF16toUTF8(
        { 0x2323 },  // U+2323 SMILE
        { '\xE2', '\x8C', '\xA3' },
        "Plane 1 codepoints should have a length of 3 char in UTF-8");
}

TEST_F(UnicodeTest, UTF16toUTF8Surrogate) {
    TestUTF16toUTF8(
        { 0xD800, 0xDC00 },  // U+10000
        { '\xF0', '\x90', '\x80', '\x80' },
        "Surrogate pairs should have a length of 4 chars");
}

TEST_F(UnicodeTest, UTF16toUTF8UnpairedSurrogate) {
    TestUTF16toUTF8(
        { 0xD800 },     // U+10000 with high surrogate pair only
        { },            // Unpaired surrogate should be ignored
        "A single unpaired high surrogate should have a length of 0 chars");

    TestUTF16toUTF8(
        { 0xDC00 },     // U+10000 with low surrogate pair only
        { },            // Unpaired surrogate should be ignored
        "A single unpaired low surrogate should have a length of 0 chars");

    TestUTF16toUTF8(
        // U+0030, U+0100, U+10000 with high surrogate pair only, U+2323
        { 0x0030, 0x0100, 0xDC00, 0x2323 },
        { '\x30', '\xC4', '\x80', '\xE2', '\x8C', '\xA3' },
        "Unpaired high surrogate should be skipped in the middle");

    TestUTF16toUTF8(
        // U+0030, U+0100, U+10000 with high surrogate pair only, U+2323
        { 0x0030, 0x0100, 0xDC00, 0x2323 },
        { '\x30', '\xC4', '\x80', '\xE2', '\x8C', '\xA3' },
        "Unpaired low surrogate should be skipped in the middle");
}

TEST_F(UnicodeTest, UTF16toUTF8CorrectInvalidSurrogate) {
    // http://b/29250543
    // d841d8 is an invalid start for a surrogate pair. Make sure this is handled by ignoring the
    // first character in the pair and handling the rest correctly.
    TestUTF16toUTF8(
        { 0xD841, 0xD841, 0xDC41 },     // U+20441
        { '\xF0', '\xA0', '\x91', '\x81' },
        "Invalid start for a surrogate pair should be ignored");
}

TEST_F(UnicodeTest, UTF16toUTF8Normal) {
    TestUTF16toUTF8({
        0x0024, // U+0024 ($) --> 0x24,           1 UTF-8 byte
        0x00A3, // U+00A3 (£) --> 0xC2 0xA3,      2 UTF-8 bytes
        0x0939, // U+0939 (ह) --> 0xE0 0xA4 0xB9, 3 UTF-8 bytes
        0x20AC, // U+20AC (€) --> 0xE2 0x82 0xAC, 3 UTF-8 bytes
        0xD55C, // U+D55C (한)--> 0xED 0x95 0x9C, 3 UTF-8 bytes
        0xD801, 0xDC37, // U+10437 (𐐷) --> 0xF0 0x90 0x90 0xB7, 4 UTF-8 bytes
    }, {
        '\x24',
        '\xC2', '\xA3',
        '\xE0', '\xA4', '\xB9',
        '\xE2', '\x82', '\xAC',
        '\xED', '\x95', '\x9C',
        '\xF0', '\x90', '\x90', '\xB7',
    });
}

TEST_F(UnicodeTest, strstr16EmptyTarget) {
    EXPECT_EQ(strstr16(kSearchString, u""), kSearchString)
            << "should return the original pointer";
}

TEST_F(UnicodeTest, strstr16EmptyTarget_bug) {
    // In the original code when target is an empty string strlen16() would
    // start reading the memory until a "terminating null" (that is, zero)
    // character is found.   This happens because "*target++" in the original
    // code would increment the pointer beyond the actual string.
    void* memptr;
    const size_t alignment = sysconf(_SC_PAGESIZE);
    const size_t size = 2 * alignment;
    ASSERT_EQ(posix_memalign(&memptr, alignment, size), 0);
    // Fill allocated memory.
    memset(memptr, 'A', size);
    // Create a pointer to an "empty" string on the first page.
    char16_t* const emptyString = (char16_t* const)((char*)memptr + alignment - 4);
    *emptyString = (char16_t)0;
    // Protect the second page to show that strstr16() violates that.
    ASSERT_EQ(mprotect((char*)memptr + alignment, alignment, PROT_NONE), 0);
    // Test strstr16(): when bug is present a segmentation fault is raised.
    ASSERT_EQ(strstr16((char16_t*)memptr, emptyString), (char16_t*)memptr)
        << "should not read beyond the first char16_t.";
    // Reset protection of the second page
    ASSERT_EQ(mprotect((char*)memptr + alignment, alignment, PROT_READ | PROT_WRITE), 0);
    // Free allocated memory.
    free(memptr);
}

TEST_F(UnicodeTest, strstr16SameString) {
    const char16_t* result = strstr16(kSearchString, kSearchString);
    EXPECT_EQ(kSearchString, result)
            << "should return the original pointer";
}

TEST_F(UnicodeTest, strstr16TargetStartOfString) {
    const char16_t* result = strstr16(kSearchString, u"I am");
    EXPECT_EQ(kSearchString, result)
            << "should return the original pointer";
}


TEST_F(UnicodeTest, strstr16TargetEndOfString) {
    const char16_t* result = strstr16(kSearchString, u"wind.");
    EXPECT_EQ(kSearchString+19, result);
}

TEST_F(UnicodeTest, strstr16TargetWithinString) {
    const char16_t* result = strstr16(kSearchString, u"leaf");
    EXPECT_EQ(kSearchString+7, result);
}

TEST_F(UnicodeTest, strstr16TargetNotPresent) {
    const char16_t* result = strstr16(kSearchString, u"soar");
    EXPECT_EQ(nullptr, result);
}

// http://b/29267949
// Test that overreading in utf8_to_utf16_length is detected
TEST_F(UnicodeTest, InvalidUtf8OverreadDetected) {
    // An utf8 char starting with \xc4 is two bytes long.
    // Add extra zeros so no extra memory is read in case the code doesn't
    // work as expected.
    static char utf8[] = "\xc4\x00\x00\x00";
    ASSERT_DEATH(utf8_to_utf16_length((uint8_t *) utf8, strlen(utf8),
            true /* overreadIsFatal */), "" /* regex for ASSERT_DEATH */);
}

}
