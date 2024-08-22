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

#include <gtest/gtest.h>
#include <sys/prctl.h>

#include <string>

#include <android-base/test_utils.h>

#include "libdebuggerd/tombstone.h"
#include "tombstone.pb.h"

using CallbackType = std::function<void(const std::string& line, bool should_log)>;

class TombstoneProtoToTextTest : public ::testing::Test {
 public:
  void SetUp() {
    tombstone_.reset(new Tombstone);

    tombstone_->set_arch(Architecture::ARM64);
    tombstone_->set_build_fingerprint("Test fingerprint");
    tombstone_->set_timestamp("1970-01-01 00:00:00");
    tombstone_->set_pid(100);
    tombstone_->set_tid(100);
    tombstone_->set_uid(0);
    tombstone_->set_selinux_label("none");

    Signal signal;
    signal.set_number(SIGSEGV);
    signal.set_name("SIGSEGV");
    signal.set_code(0);
    signal.set_code_name("none");

    *tombstone_->mutable_signal_info() = signal;

    Thread thread;
    thread.set_id(100);
    thread.set_name("main");
    thread.set_tagged_addr_ctrl(0);
    thread.set_pac_enabled_keys(0);

    auto& threads = *tombstone_->mutable_threads();
    threads[100] = thread;
    main_thread_ = &threads[100];
  }

  void ProtoToString() {
    text_ = "";
    EXPECT_TRUE(
        tombstone_proto_to_text(*tombstone_, [this](const std::string& line, bool should_log) {
          if (should_log) {
            text_ += "LOG ";
          }
          text_ += line + '\n';
        }));
  }

  Thread* main_thread_;
  std::string text_;
  std::unique_ptr<Tombstone> tombstone_;
};

TEST_F(TombstoneProtoToTextTest, tagged_addr_ctrl) {
  main_thread_->set_tagged_addr_ctrl(0);
  ProtoToString();
  EXPECT_MATCH(text_, "LOG tagged_addr_ctrl: 0000000000000000\\n");

  main_thread_->set_tagged_addr_ctrl(PR_TAGGED_ADDR_ENABLE);
  ProtoToString();
  EXPECT_MATCH(text_, "LOG tagged_addr_ctrl: 0000000000000001 \\(PR_TAGGED_ADDR_ENABLE\\)\\n");

  main_thread_->set_tagged_addr_ctrl(PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
                                     (0xfffe << PR_MTE_TAG_SHIFT));
  ProtoToString();
  EXPECT_MATCH(text_,
               "LOG tagged_addr_ctrl: 000000000007fff3 \\(PR_TAGGED_ADDR_ENABLE, PR_MTE_TCF_SYNC, "
               "mask 0xfffe\\)\\n");

  main_thread_->set_tagged_addr_ctrl(0xf0000000 | PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
                                     PR_MTE_TCF_ASYNC | (0xfffe << PR_MTE_TAG_SHIFT));
  ProtoToString();
  EXPECT_MATCH(text_,
               "LOG tagged_addr_ctrl: 00000000f007fff7 \\(PR_TAGGED_ADDR_ENABLE, PR_MTE_TCF_SYNC, "
               "PR_MTE_TCF_ASYNC, mask 0xfffe, unknown 0xf0000000\\)\\n");
}

TEST_F(TombstoneProtoToTextTest, pac_enabled_keys) {
  main_thread_->set_pac_enabled_keys(0);
  ProtoToString();
  EXPECT_MATCH(text_, "LOG pac_enabled_keys: 0000000000000000\\n");

  main_thread_->set_pac_enabled_keys(PR_PAC_APIAKEY);
  ProtoToString();
  EXPECT_MATCH(text_, "LOG pac_enabled_keys: 0000000000000001 \\(PR_PAC_APIAKEY\\)\\n");

  main_thread_->set_pac_enabled_keys(PR_PAC_APIAKEY | PR_PAC_APDBKEY);
  ProtoToString();
  EXPECT_MATCH(text_,
               "LOG pac_enabled_keys: 0000000000000009 \\(PR_PAC_APIAKEY, PR_PAC_APDBKEY\\)\\n");

  main_thread_->set_pac_enabled_keys(PR_PAC_APIAKEY | PR_PAC_APDBKEY | 0x1000);
  ProtoToString();
  EXPECT_MATCH(text_,
               "LOG pac_enabled_keys: 0000000000001009 \\(PR_PAC_APIAKEY, PR_PAC_APDBKEY, unknown "
               "0x1000\\)\\n");
}

TEST_F(TombstoneProtoToTextTest, crash_detail_string) {
  auto* crash_detail = tombstone_->add_crash_details();
  crash_detail->set_name("CRASH_DETAIL_NAME");
  crash_detail->set_data("crash_detail_value");
  ProtoToString();
  EXPECT_MATCH(text_, "(CRASH_DETAIL_NAME: 'crash_detail_value')");
}

TEST_F(TombstoneProtoToTextTest, crash_detail_bytes) {
  auto* crash_detail = tombstone_->add_crash_details();
  crash_detail->set_name("CRASH_DETAIL_NAME");
  crash_detail->set_data("helloworld\1\255\3");
  ProtoToString();
  EXPECT_MATCH(text_, R"(CRASH_DETAIL_NAME: 'helloworld\\1\\255\\3')");
}

TEST_F(TombstoneProtoToTextTest, stack_record) {
  auto* cause = tombstone_->add_causes();
  cause->set_human_readable("stack tag-mismatch on thread 123");
  auto* stack = tombstone_->mutable_stack_history_buffer();
  stack->set_tid(123);
  {
    auto* shb_entry = stack->add_entries();
    shb_entry->set_fp(0x1);
    shb_entry->set_tag(0xb);
    auto* addr = shb_entry->mutable_addr();
    addr->set_rel_pc(0x567);
    addr->set_file_name("foo.so");
    addr->set_build_id("ABC123");
  }
  {
    auto* shb_entry = stack->add_entries();
    shb_entry->set_fp(0x2);
    shb_entry->set_tag(0xc);
    auto* addr = shb_entry->mutable_addr();
    addr->set_rel_pc(0x678);
    addr->set_file_name("bar.so");
  }
  ProtoToString();
  EXPECT_MATCH(text_, "stack tag-mismatch on thread 123");
  EXPECT_MATCH(text_, "stack_record fp:0x1 tag:0xb pc:foo\\.so\\+0x567 \\(BuildId: ABC123\\)");
  EXPECT_MATCH(text_, "stack_record fp:0x2 tag:0xc pc:bar\\.so\\+0x678");
}
