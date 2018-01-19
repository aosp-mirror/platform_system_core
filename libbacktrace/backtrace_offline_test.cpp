/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <inttypes.h>
#include <libunwind.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>
#include <cutils/threads.h>

#include <gtest/gtest.h>

extern "C" {
// Prototypes for functions in the test library.
int test_level_one(int, int, int, int, void (*)(void*), void*);
int test_level_two(int, int, int, int, void (*)(void*), void*);
int test_level_three(int, int, int, int, void (*)(void*), void*);
int test_level_four(int, int, int, int, void (*)(void*), void*);
int test_recursive_call(int, void (*)(void*), void*);
void test_get_context_and_wait(unw_context_t* unw_context, volatile int* exit_flag);
}

static ucontext_t GetUContextFromUnwContext(const unw_context_t& unw_context) {
  ucontext_t ucontext;
  memset(&ucontext, 0, sizeof(ucontext));
#if defined(__arm__)
  ucontext.uc_mcontext.arm_r0 = unw_context.regs[0];
  ucontext.uc_mcontext.arm_r1 = unw_context.regs[1];
  ucontext.uc_mcontext.arm_r2 = unw_context.regs[2];
  ucontext.uc_mcontext.arm_r3 = unw_context.regs[3];
  ucontext.uc_mcontext.arm_r4 = unw_context.regs[4];
  ucontext.uc_mcontext.arm_r5 = unw_context.regs[5];
  ucontext.uc_mcontext.arm_r6 = unw_context.regs[6];
  ucontext.uc_mcontext.arm_r7 = unw_context.regs[7];
  ucontext.uc_mcontext.arm_r8 = unw_context.regs[8];
  ucontext.uc_mcontext.arm_r9 = unw_context.regs[9];
  ucontext.uc_mcontext.arm_r10 = unw_context.regs[10];
  ucontext.uc_mcontext.arm_fp = unw_context.regs[11];
  ucontext.uc_mcontext.arm_ip = unw_context.regs[12];
  ucontext.uc_mcontext.arm_sp = unw_context.regs[13];
  ucontext.uc_mcontext.arm_lr = unw_context.regs[14];
  ucontext.uc_mcontext.arm_pc = unw_context.regs[15];
#else
  ucontext.uc_mcontext = unw_context.uc_mcontext;
#endif
  return ucontext;
}

struct FunctionSymbol {
  std::string name;
  uint64_t start;
  uint64_t end;
};

static std::vector<FunctionSymbol> GetFunctionSymbols() {
  std::vector<FunctionSymbol> symbols = {
      {"unknown_start", 0, 0},
      {"test_level_one", reinterpret_cast<uint64_t>(&test_level_one), 0},
      {"test_level_two", reinterpret_cast<uint64_t>(&test_level_two), 0},
      {"test_level_three", reinterpret_cast<uint64_t>(&test_level_three), 0},
      {"test_level_four", reinterpret_cast<uint64_t>(&test_level_four), 0},
      {"test_recursive_call", reinterpret_cast<uint64_t>(&test_recursive_call), 0},
      {"test_get_context_and_wait", reinterpret_cast<uint64_t>(&test_get_context_and_wait), 0},
      {"unknown_end", static_cast<uint64_t>(-1), static_cast<uint64_t>(-1)},
  };
  std::sort(
      symbols.begin(), symbols.end(),
      [](const FunctionSymbol& s1, const FunctionSymbol& s2) { return s1.start < s2.start; });
  for (size_t i = 0; i + 1 < symbols.size(); ++i) {
    symbols[i].end = symbols[i + 1].start;
  }
  return symbols;
}

static std::string RawDataToHexString(const void* data, size_t size) {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  std::string s;
  for (size_t i = 0; i < size; ++i) {
    s += android::base::StringPrintf("%02x", p[i]);
  }
  return s;
}

static void HexStringToRawData(const char* s, void* data, size_t size) {
  uint8_t* p = static_cast<uint8_t*>(data);
  for (size_t i = 0; i < size; ++i) {
    int value;
    sscanf(s, "%02x", &value);
    *p++ = static_cast<uint8_t>(value);
    s += 2;
  }
}

struct OfflineThreadArg {
  unw_context_t unw_context;
  pid_t tid;
  volatile int exit_flag;
};

static void* OfflineThreadFunc(void* arg) {
  OfflineThreadArg* fn_arg = reinterpret_cast<OfflineThreadArg*>(arg);
  fn_arg->tid = gettid();
  test_get_context_and_wait(&fn_arg->unw_context, &fn_arg->exit_flag);
  return nullptr;
}

std::string GetTestPath(std::string path) {
  return android::base::GetExecutableDirectory() + "/testdata/" + ABI_STRING + '/' + path;
}

// This test is disable because it is for generating test data.
TEST(libbacktrace, DISABLED_generate_offline_testdata) {
  // Create a thread to generate the needed stack and registers information.
  const size_t stack_size = 16 * 1024;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, stack);
  uint64_t stack_addr = reinterpret_cast<uint64_t>(stack);
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setstack(&attr, reinterpret_cast<void*>(stack), stack_size));
  pthread_t thread;
  OfflineThreadArg arg;
  arg.exit_flag = 0;
  ASSERT_EQ(0, pthread_create(&thread, &attr, OfflineThreadFunc, &arg));
  // Wait for the offline thread to generate the stack and unw_context information.
  sleep(1);
  // Copy the stack information.
  std::vector<uint8_t> stack_data(reinterpret_cast<uint8_t*>(stack),
                                  reinterpret_cast<uint8_t*>(stack) + stack_size);
  arg.exit_flag = 1;
  ASSERT_EQ(0, pthread_join(thread, nullptr));
  ASSERT_EQ(0, munmap(stack, stack_size));

  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(getpid()));
  ASSERT_TRUE(map != nullptr);

  backtrace_stackinfo_t stack_info;
  stack_info.start = stack_addr;
  stack_info.end = stack_addr + stack_size;
  stack_info.data = stack_data.data();

  // Generate offline testdata.
  std::string testdata;
  // 1. Dump pid, tid
  testdata += android::base::StringPrintf("pid: %d tid: %d\n", getpid(), arg.tid);
  // 2. Dump maps
  for (auto it = map->begin(); it != map->end(); ++it) {
    const backtrace_map_t* entry = *it;
    testdata +=
        android::base::StringPrintf("map: start: %" PRIx64 " end: %" PRIx64 " offset: %" PRIx64
                                    " load_bias: %" PRIx64 " flags: %d name: %s\n",
                                    entry->start, entry->end, entry->offset, entry->load_bias,
                                    entry->flags, entry->name.c_str());
  }
  // 3. Dump registers
  testdata += android::base::StringPrintf("registers: %zu ", sizeof(arg.unw_context));
  testdata += RawDataToHexString(&arg.unw_context, sizeof(arg.unw_context));
  testdata.push_back('\n');

  // 4. Dump stack
  testdata += android::base::StringPrintf(
      "stack: start: %" PRIx64 " end: %" PRIx64 " size: %zu ",
      stack_info.start, stack_info.end, stack_data.size());
  testdata += RawDataToHexString(stack_data.data(), stack_data.size());
  testdata.push_back('\n');

  // 5. Dump function symbols
  std::vector<FunctionSymbol> function_symbols = GetFunctionSymbols();
  for (const auto& symbol : function_symbols) {
    testdata +=
        android::base::StringPrintf("function: start: %" PRIx64 " end: %" PRIx64 " name: %s\n",
                                    symbol.start, symbol.end, symbol.name.c_str());
  }

  ASSERT_TRUE(android::base::WriteStringToFile(testdata, "offline_testdata"));
}

// Return the name of the function which matches the address. Although we don't know the
// exact end of each function, it is accurate enough for the tests.
static std::string FunctionNameForAddress(uint64_t addr,
                                          const std::vector<FunctionSymbol>& symbols) {
  for (auto& symbol : symbols) {
    if (addr >= symbol.start && addr < symbol.end) {
      return symbol.name;
    }
  }
  return "";
}

struct OfflineTestData {
  int pid;
  int tid;
  std::vector<backtrace_map_t> maps;
  unw_context_t unw_context;
  backtrace_stackinfo_t stack_info;
  std::vector<uint8_t> stack;
  std::vector<FunctionSymbol> symbols;
};

bool ReadOfflineTestData(const std::string offline_testdata_path, OfflineTestData* testdata) {
  std::string s;
  if (!android::base::ReadFileToString(offline_testdata_path, &s)) {
    return false;
  }
  // Parse offline_testdata.
  std::vector<std::string> lines = android::base::Split(s, "\n");
  memset(&testdata->unw_context, 0, sizeof(testdata->unw_context));
  for (const auto& line : lines) {
    if (android::base::StartsWith(line, "pid:")) {
      sscanf(line.c_str(), "pid: %d tid: %d", &testdata->pid, &testdata->tid);
    } else if (android::base::StartsWith(line, "map:")) {
      testdata->maps.resize(testdata->maps.size() + 1);
      backtrace_map_t& map = testdata->maps.back();
      int pos;
      sscanf(line.c_str(),
             "map: start: %" SCNx64 " end: %" SCNx64 " offset: %" SCNx64 " load_bias: %" SCNx64
             " flags: %d name: %n",
             &map.start, &map.end, &map.offset, &map.load_bias, &map.flags, &pos);
      map.name = android::base::Trim(line.substr(pos));
    } else if (android::base::StartsWith(line, "registers:")) {
      size_t size;
      int pos;
      sscanf(line.c_str(), "registers: %zu %n", &size, &pos);
      if (sizeof(testdata->unw_context) != size) {
        return false;
      }
      HexStringToRawData(&line[pos], &testdata->unw_context, size);
    } else if (android::base::StartsWith(line, "regs:")) {
      std::vector<std::string> strs = android::base::Split(line.substr(6), " ");
      if (strs.size() % 2 != 0) {
        return false;
      }
      std::vector<std::pair<std::string, uint64_t>> items;
      for (size_t i = 0; i + 1 < strs.size(); i += 2) {
        if (!android::base::EndsWith(strs[i], ":")) {
          return false;
        }
        uint64_t value = std::stoul(strs[i + 1], nullptr, 16);
        items.push_back(std::make_pair(strs[i].substr(0, strs[i].size() - 1), value));
      }
#if defined(__arm__)
      for (auto& item : items) {
        if (item.first == "sp") {
          testdata->unw_context.regs[13] = item.second;
        } else if (item.first == "pc") {
          testdata->unw_context.regs[15] = item.second;
        } else {
          return false;
        }
      }
#elif defined(__aarch64__)
      for (auto& item : items) {
        if (item.first == "pc") {
          testdata->unw_context.uc_mcontext.pc = item.second;
        } else if (item.first == "sp") {
          testdata->unw_context.uc_mcontext.sp = item.second;
        } else if (item.first == "x29") {
          testdata->unw_context.uc_mcontext.regs[UNW_AARCH64_X29] = item.second;
        } else {
          return false;
        }
      }
#endif
    } else if (android::base::StartsWith(line, "stack:")) {
      size_t size;
      int pos;
      sscanf(line.c_str(),
             "stack: start: %" SCNx64 " end: %" SCNx64 " size: %zu %n",
             &testdata->stack_info.start, &testdata->stack_info.end, &size, &pos);
      CHECK_EQ(testdata->stack_info.end - testdata->stack_info.start, size);
      testdata->stack.resize(size);
      HexStringToRawData(&line[pos], &testdata->stack[0], size);
      testdata->stack_info.data = testdata->stack.data();
    } else if (android::base::StartsWith(line, "function:")) {
      testdata->symbols.resize(testdata->symbols.size() + 1);
      FunctionSymbol& symbol = testdata->symbols.back();
      int pos;
      sscanf(line.c_str(), "function: start: %" SCNx64 " end: %" SCNx64 " name: %n", &symbol.start,
             &symbol.end, &pos);
      symbol.name = line.substr(pos);
    }
  }
  return true;
}

static void BacktraceOfflineTest(const char* arch, const std::string& testlib_name) {
  // TODO: For now, we can only run this on the same arch as the library arch.
  if (std::string(ABI_STRING) != arch) {
    GTEST_LOG_(INFO) << "Ignoring arch " << arch << " for lib " << testlib_name;
    return;
  }

  const std::string testlib_path(GetTestPath(testlib_name));
  const std::string offline_testdata_path(GetTestPath("offline_testdata"));
  OfflineTestData testdata;
  ASSERT_TRUE(ReadOfflineTestData(offline_testdata_path, &testdata));

  // Fix path of libbacktrace_testlib.so.
  for (auto& map : testdata.maps) {
    if (map.name.find("libbacktrace_test.so") != std::string::npos) {
      map.name = testlib_path;
    }
  }

  // Do offline backtrace.
  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(testdata.pid, testdata.maps));
  ASSERT_TRUE(map != nullptr);

  std::unique_ptr<Backtrace> backtrace(
      Backtrace::CreateOffline(testdata.pid, testdata.tid, map.get(), testdata.stack_info));
  ASSERT_TRUE(backtrace != nullptr);

  ucontext_t ucontext = GetUContextFromUnwContext(testdata.unw_context);
  ASSERT_TRUE(backtrace->Unwind(0, &ucontext));

  // Collect pc values of the call stack frames.
  std::vector<uint64_t> pc_values;
  for (size_t i = 0; i < backtrace->NumFrames(); ++i) {
    pc_values.push_back(backtrace->GetFrame(i)->pc);
  }

  size_t test_one_index = 0;
  for (size_t i = 0; i < pc_values.size(); ++i) {
    if (FunctionNameForAddress(pc_values[i], testdata.symbols) == "test_level_one") {
      test_one_index = i;
      break;
    }
  }

  ASSERT_GE(test_one_index, 3u);
  ASSERT_EQ("test_level_one", FunctionNameForAddress(pc_values[test_one_index], testdata.symbols));
  ASSERT_EQ("test_level_two", FunctionNameForAddress(pc_values[test_one_index - 1],
                                                     testdata.symbols));
  ASSERT_EQ("test_level_three", FunctionNameForAddress(pc_values[test_one_index - 2],
                                                       testdata.symbols));
  ASSERT_EQ("test_level_four", FunctionNameForAddress(pc_values[test_one_index - 3],
                                                      testdata.symbols));
}

// For now, these tests can only run on the given architectures.
TEST(libbacktrace, offline_eh_frame) {
  BacktraceOfflineTest("arm64", "libbacktrace_test_eh_frame.so");
  BacktraceOfflineTest("x86_64", "libbacktrace_test_eh_frame.so");
}

TEST(libbacktrace, offline_debug_frame) {
  BacktraceOfflineTest("arm", "libbacktrace_test_debug_frame.so");
  BacktraceOfflineTest("x86", "libbacktrace_test_debug_frame.so");
}

TEST(libbacktrace, offline_gnu_debugdata) {
  BacktraceOfflineTest("arm", "libbacktrace_test_gnu_debugdata.so");
  BacktraceOfflineTest("x86", "libbacktrace_test_gnu_debugdata.so");
}

TEST(libbacktrace, offline_arm_exidx) {
  BacktraceOfflineTest("arm", "libbacktrace_test_arm_exidx.so");
}

static void LibUnwindingTest(const std::string& arch, const std::string& testdata_name,
                             const std::string& testlib_name) {
  if (std::string(ABI_STRING) != arch) {
    GTEST_LOG_(INFO) << "Skipping test since offline for arm on " << ABI_STRING
                     << " isn't supported.";
    return;
  }
  const std::string testlib_path(GetTestPath(testlib_name));
  struct stat st;
  ASSERT_EQ(0, stat(testlib_path.c_str(), &st)) << "can't find testlib " << testlib_path;

  const std::string offline_testdata_path(GetTestPath(testdata_name));
  OfflineTestData testdata;
  ASSERT_TRUE(ReadOfflineTestData(offline_testdata_path, &testdata));

  // Fix path of the testlib.
  for (auto& map : testdata.maps) {
    if (map.name.find(testlib_name) != std::string::npos) {
      map.name = testlib_path;
    }
  }

  // Do offline backtrace.
  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(testdata.pid, testdata.maps));
  ASSERT_TRUE(map != nullptr);

  std::unique_ptr<Backtrace> backtrace(
      Backtrace::CreateOffline(testdata.pid, testdata.tid, map.get(), testdata.stack_info));
  ASSERT_TRUE(backtrace != nullptr);

  ucontext_t ucontext = GetUContextFromUnwContext(testdata.unw_context);
  ASSERT_TRUE(backtrace->Unwind(0, &ucontext));

  ASSERT_EQ(testdata.symbols.size(), backtrace->NumFrames());
  for (size_t i = 0; i < backtrace->NumFrames(); ++i) {
    uint64_t vaddr_in_file =
        backtrace->GetFrame(i)->pc - testdata.maps[0].start + testdata.maps[0].load_bias;
    std::string name = FunctionNameForAddress(vaddr_in_file, testdata.symbols);
    ASSERT_EQ(name, testdata.symbols[i].name);
  }
  ASSERT_TRUE(backtrace->GetError().error_code == BACKTRACE_UNWIND_ERROR_ACCESS_MEM_FAILED ||
              backtrace->GetError().error_code == BACKTRACE_UNWIND_ERROR_MAP_MISSING);
}

// This test tests the situation that ranges of functions covered by .eh_frame and .ARM.exidx
// overlap with each other, which appears in /system/lib/libart.so.
TEST(libbacktrace, offline_unwind_mix_eh_frame_and_arm_exidx) {
  LibUnwindingTest("arm", "offline_testdata_for_libart", "libart.so");
}

TEST(libbacktrace, offline_debug_frame_with_load_bias) {
  LibUnwindingTest("arm", "offline_testdata_for_libandroid_runtime", "libandroid_runtime.so");
}

TEST(libbacktrace, offline_try_armexidx_after_debug_frame) {
  LibUnwindingTest("arm", "offline_testdata_for_libGLESv2_adreno", "libGLESv2_adreno.so");
}

TEST(libbacktrace, offline_cie_with_P_augmentation) {
  // Make sure we can unwind through functions with CIE entry containing P augmentation, which
  // makes unwinding library reading personality handler from memory. One example is
  // /system/lib64/libskia.so.
  LibUnwindingTest("arm64", "offline_testdata_for_libskia", "libskia.so");
}

TEST(libbacktrace, offline_empty_eh_frame_hdr) {
  // Make sure we can unwind through libraries with empty .eh_frame_hdr section. One example is
  // /vendor/lib64/egl/eglSubDriverAndroid.so.
  LibUnwindingTest("arm64", "offline_testdata_for_eglSubDriverAndroid", "eglSubDriverAndroid.so");
}

TEST(libbacktrace, offline_max_frames_limit) {
  // The length of callchain can reach 256 when recording an application.
  ASSERT_GE(MAX_BACKTRACE_FRAMES, 256);
}
