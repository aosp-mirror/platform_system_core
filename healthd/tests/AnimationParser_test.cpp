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

#include "AnimationParser.h"

#include <gtest/gtest.h>

using namespace android;

TEST(AnimationParserTest, Test_can_ignore_line) {
    EXPECT_TRUE(can_ignore_line(""));
    EXPECT_TRUE(can_ignore_line("     "));
    EXPECT_TRUE(can_ignore_line("#"));
    EXPECT_TRUE(can_ignore_line("   # comment"));

    EXPECT_FALSE(can_ignore_line("text"));
    EXPECT_FALSE(can_ignore_line("text # comment"));
    EXPECT_FALSE(can_ignore_line("     text"));
    EXPECT_FALSE(can_ignore_line("     text # comment"));
}

TEST(AnimationParserTest, Test_remove_prefix) {
    static const char TEST_STRING[] = "abcdef";
    const char* rest = nullptr;
    EXPECT_FALSE(remove_prefix(TEST_STRING, "def", &rest));
    // Ignore strings that only consist of the prefix
    EXPECT_FALSE(remove_prefix(TEST_STRING, TEST_STRING, &rest));

    EXPECT_TRUE(remove_prefix(TEST_STRING, "abc", &rest));
    EXPECT_STREQ("def", rest);

    EXPECT_TRUE(remove_prefix("  abcdef", "abc", &rest));
    EXPECT_STREQ("def", rest);
}

TEST(AnimationParserTest, Test_parse_text_field) {
    static const char TEST_FILE_NAME[] = "font_file";
    static const int TEST_X = 3;
    static const int TEST_Y = 6;
    static const int TEST_R = 1;
    static const int TEST_G = 2;
    static const int TEST_B = 4;
    static const int TEST_A = 8;

    static const char TEST_XCENT_YCENT[] = "c c 1 2 4 8  font_file ";
    static const char TEST_XCENT_YVAL[]  = "c 6 1 2 4 8  font_file ";
    static const char TEST_XVAL_YCENT[]  = "3 c 1 2 4 8  font_file ";
    static const char TEST_XVAL_YVAL[]   = "3 6 1 2 4 8  font_file ";
    static const char TEST_BAD_MISSING[] = "c c 1 2 4 font_file";
    static const char TEST_BAD_NO_FILE[] = "c c 1 2 4 8";

    animation::text_field out;

    EXPECT_TRUE(parse_text_field(TEST_XCENT_YCENT, &out));
    EXPECT_EQ(CENTER_VAL, out.pos_x);
    EXPECT_EQ(CENTER_VAL, out.pos_y);
    EXPECT_EQ(TEST_R, out.color_r);
    EXPECT_EQ(TEST_G, out.color_g);
    EXPECT_EQ(TEST_B, out.color_b);
    EXPECT_EQ(TEST_A, out.color_a);
    EXPECT_STREQ(TEST_FILE_NAME, out.font_file.c_str());

    EXPECT_TRUE(parse_text_field(TEST_XCENT_YVAL, &out));
    EXPECT_EQ(CENTER_VAL, out.pos_x);
    EXPECT_EQ(TEST_Y, out.pos_y);
    EXPECT_EQ(TEST_R, out.color_r);
    EXPECT_EQ(TEST_G, out.color_g);
    EXPECT_EQ(TEST_B, out.color_b);
    EXPECT_EQ(TEST_A, out.color_a);
    EXPECT_STREQ(TEST_FILE_NAME, out.font_file.c_str());

    EXPECT_TRUE(parse_text_field(TEST_XVAL_YCENT, &out));
    EXPECT_EQ(TEST_X, out.pos_x);
    EXPECT_EQ(CENTER_VAL, out.pos_y);
    EXPECT_EQ(TEST_R, out.color_r);
    EXPECT_EQ(TEST_G, out.color_g);
    EXPECT_EQ(TEST_B, out.color_b);
    EXPECT_EQ(TEST_A, out.color_a);
    EXPECT_STREQ(TEST_FILE_NAME, out.font_file.c_str());

    EXPECT_TRUE(parse_text_field(TEST_XVAL_YVAL, &out));
    EXPECT_EQ(TEST_X, out.pos_x);
    EXPECT_EQ(TEST_Y, out.pos_y);
    EXPECT_EQ(TEST_R, out.color_r);
    EXPECT_EQ(TEST_G, out.color_g);
    EXPECT_EQ(TEST_B, out.color_b);
    EXPECT_EQ(TEST_A, out.color_a);
    EXPECT_STREQ(TEST_FILE_NAME, out.font_file.c_str());

    EXPECT_FALSE(parse_text_field(TEST_BAD_MISSING, &out));
    EXPECT_FALSE(parse_text_field(TEST_BAD_NO_FILE, &out));
}

TEST(AnimationParserTest, Test_parse_animation_desc_basic) {
    static const char TEST_ANIMATION[] = R"desc(
        # Basic animation
        animation: 5 1 test/animation_file
        frame: 1000 0 100
    )desc";
    animation anim;

    EXPECT_TRUE(parse_animation_desc(TEST_ANIMATION, &anim));
}

TEST(AnimationParserTest, Test_parse_animation_desc_bad_no_animation_line) {
    static const char TEST_ANIMATION[] = R"desc(
        # Bad animation
        frame: 1000 90  10
    )desc";
    animation anim;

    EXPECT_FALSE(parse_animation_desc(TEST_ANIMATION, &anim));
}

TEST(AnimationParserTest, Test_parse_animation_desc_bad_no_frame) {
    static const char TEST_ANIMATION[] = R"desc(
        # Bad animation
        animation: 5 1 test/animation_file
    )desc";
    animation anim;

    EXPECT_FALSE(parse_animation_desc(TEST_ANIMATION, &anim));
}

TEST(AnimationParserTest, Test_parse_animation_desc_bad_animation_line_format) {
    static const char TEST_ANIMATION[] = R"desc(
        # Bad animation
        animation: 5 1
        frame: 1000 90  10
    )desc";
    animation anim;

    EXPECT_FALSE(parse_animation_desc(TEST_ANIMATION, &anim));
}

TEST(AnimationParserTest, Test_parse_animation_desc_full) {
    static const char TEST_ANIMATION[] = R"desc(
        # Full animation
        animation: 5 1 test/animation_file
        clock_display:    11 12 13 14 15 16 test/time_font
        percent_display:  21 22 23 24 25 26 test/percent_font

        frame: 10 20 30
        frame: 40 50 60
    )desc";
    animation anim;

    EXPECT_TRUE(parse_animation_desc(TEST_ANIMATION, &anim));

    EXPECT_EQ(5, anim.num_cycles);
    EXPECT_EQ(1, anim.first_frame_repeats);
    EXPECT_STREQ("test/animation_file", anim.animation_file.c_str());

    EXPECT_EQ(11, anim.text_clock.pos_x);
    EXPECT_EQ(12, anim.text_clock.pos_y);
    EXPECT_EQ(13, anim.text_clock.color_r);
    EXPECT_EQ(14, anim.text_clock.color_g);
    EXPECT_EQ(15, anim.text_clock.color_b);
    EXPECT_EQ(16, anim.text_clock.color_a);
    EXPECT_STREQ("test/time_font", anim.text_clock.font_file.c_str());

    EXPECT_EQ(21, anim.text_percent.pos_x);
    EXPECT_EQ(22, anim.text_percent.pos_y);
    EXPECT_EQ(23, anim.text_percent.color_r);
    EXPECT_EQ(24, anim.text_percent.color_g);
    EXPECT_EQ(25, anim.text_percent.color_b);
    EXPECT_EQ(26, anim.text_percent.color_a);
    EXPECT_STREQ("test/percent_font", anim.text_percent.font_file.c_str());

    EXPECT_EQ(2, anim.num_frames);

    EXPECT_EQ(10, anim.frames[0].disp_time);
    EXPECT_EQ(20, anim.frames[0].min_level);
    EXPECT_EQ(30, anim.frames[0].max_level);

    EXPECT_EQ(40, anim.frames[1].disp_time);
    EXPECT_EQ(50, anim.frames[1].min_level);
    EXPECT_EQ(60, anim.frames[1].max_level);
}
