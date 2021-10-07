/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>

// Example:

// name: unzip -n
// before: mkdir -p d1/d2
// before: echo b > d1/d2/a.txt
// command: unzip -q -n $FILES/zip/example.zip d1/d2/a.txt && cat d1/d2/a.txt
// expected-stdout:
// 	b

struct Test {
  std::string test_filename;
  std::string name;
  std::string command;
  std::vector<std::string> befores;
  std::vector<std::string> afters;
  std::string expected_stdout;
  std::string expected_stderr;
  int exit_status = 0;
};

static const char* g_progname;
static bool g_verbose;

static const char* g_file;
static size_t g_line;

enum Color { kRed, kGreen };

static void Print(Color c, const char* lhs, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (isatty(0)) printf("%s", (c == kRed) ? "\e[31m" : "\e[32m");
  printf("%s%s", lhs, isatty(0) ? "\e[0m" : "");
  vfprintf(stdout, fmt, ap);
  putchar('\n');
  va_end(ap);
}

static void Die(int error, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "%s: ", g_progname);
  vfprintf(stderr, fmt, ap);
  if (error != 0) fprintf(stderr, ": %s", strerror(error));
  fprintf(stderr, "\n");
  va_end(ap);
  _exit(1);
}

static void V(const char* fmt, ...) {
  if (!g_verbose) return;

  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "           - ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

static void SetField(const char* what, std::string* field, std::string_view value) {
  if (!field->empty()) {
    Die(0, "%s:%zu: %s already set to '%s'", g_file, g_line, what, field->c_str());
  }
  field->assign(value);
}

// Similar to ConsumePrefix, but also trims, so "key:value" and "key: value"
// are equivalent.
static bool Match(std::string* s, const std::string& prefix) {
  if (!android::base::StartsWith(*s, prefix)) return false;
  s->assign(android::base::Trim(s->substr(prefix.length())));
  return true;
}

static void CollectTests(std::vector<Test>* tests, const char* test_filename) {
  std::string absolute_test_filename;
  if (!android::base::Realpath(test_filename, &absolute_test_filename)) {
    Die(errno, "realpath '%s'", test_filename);
  }

  std::string content;
  if (!android::base::ReadFileToString(test_filename, &content)) {
    Die(errno, "couldn't read '%s'", test_filename);
  }

  size_t count = 0;
  g_file = test_filename;
  g_line = 0;
  auto lines = android::base::Split(content, "\n");
  std::unique_ptr<Test> test(new Test);
  while (g_line < lines.size()) {
    auto line = lines[g_line++];
    if (line.empty() || line[0] == '#') continue;

    if (line[0] == '-') {
      if (test->name.empty() || test->command.empty()) {
        Die(0, "%s:%zu: each test requires both a name and a command", g_file, g_line);
      }
      test->test_filename = absolute_test_filename;
      tests->push_back(*test.release());
      test.reset(new Test);
      ++count;
    } else if (Match(&line, "name:")) {
      SetField("name", &test->name, line);
    } else if (Match(&line, "command:")) {
      SetField("command", &test->command, line);
    } else if (Match(&line, "before:")) {
      test->befores.push_back(line);
    } else if (Match(&line, "after:")) {
      test->afters.push_back(line);
    } else if (Match(&line, "expected-exit-status:")) {
      char* end_p;
      errno = 0;
      test->exit_status = strtol(line.c_str(), &end_p, 10);
      if (errno != 0 || *end_p != '\0') {
        Die(0, "%s:%zu: bad exit status: \"%s\"", g_file, g_line, line.c_str());
      }
    } else if (Match(&line, "expected-stdout:")) {
      // Collect tab-indented lines.
      std::string text;
      while (g_line < lines.size() && !lines[g_line].empty() && lines[g_line][0] == '\t') {
        text += lines[g_line++].substr(1) + "\n";
      }
      SetField("expected stdout", &test->expected_stdout, text);
    } else {
      Die(0, "%s:%zu: syntax error: \"%s\"", g_file, g_line, line.c_str());
    }
  }
  if (count == 0) Die(0, "no tests found in '%s'", g_file);
}

static const char* Plural(size_t n) {
  return (n == 1) ? "" : "s";
}

static std::string ExitStatusToString(int status) {
  if (WIFSIGNALED(status)) {
    return android::base::StringPrintf("was killed by signal %d (%s)", WTERMSIG(status),
                                       strsignal(WTERMSIG(status)));
  }
  if (WIFSTOPPED(status)) {
    return android::base::StringPrintf("was stopped by signal %d (%s)", WSTOPSIG(status),
                                       strsignal(WSTOPSIG(status)));
  }
  return android::base::StringPrintf("exited with status %d", WEXITSTATUS(status));
}

static bool RunCommands(const char* what, const std::vector<std::string>& commands) {
  bool result = true;
  for (auto& command : commands) {
    V("running %s \"%s\"", what, command.c_str());
    int exit_status = system(command.c_str());
    if (exit_status != 0) {
      result = false;
      fprintf(stderr, "Command (%s) \"%s\" %s\n", what, command.c_str(),
              ExitStatusToString(exit_status).c_str());
    }
  }
  return result;
}

static bool CheckOutput(const char* what, std::string actual_output,
                        const std::string& expected_output, const std::string& FILES) {
  // Rewrite the output to reverse any expansion of $FILES.
  actual_output = android::base::StringReplace(actual_output, FILES, "$FILES", true);

  bool result = (actual_output == expected_output);
  if (!result) {
    fprintf(stderr, "Incorrect %s.\nExpected:\n%s\nActual:\n%s\n", what, expected_output.c_str(),
            actual_output.c_str());
  }
  return result;
}

static int RunTests(const std::vector<Test>& tests) {
  std::vector<std::string> failures;

  Print(kGreen, "[==========]", " Running %zu tests.", tests.size());
  android::base::Timer total_timer;
  for (const auto& test : tests) {
    bool failed = false;

    Print(kGreen, "[ RUN      ]", " %s", test.name.c_str());
    android::base::Timer test_timer;

    // Set $FILES for this test.
    std::string FILES = android::base::Dirname(test.test_filename) + "/files";
    V("setenv(\"FILES\", \"%s\")", FILES.c_str());
    setenv("FILES", FILES.c_str(), 1);

    // Make a safe space to run the test.
    TemporaryDir td;
    V("chdir(\"%s\")", td.path);
    if (chdir(td.path)) Die(errno, "chdir(\"%s\")", td.path);

    // Perform any setup specified for this test.
    if (!RunCommands("before", test.befores)) failed = true;

    if (!failed) {
      V("running command \"%s\"", test.command.c_str());
      CapturedStdout test_stdout;
      CapturedStderr test_stderr;
      int status = system(test.command.c_str());
      test_stdout.Stop();
      test_stderr.Stop();

      V("system() returned status %d", status);
      if (WEXITSTATUS(status) != test.exit_status) {
        failed = true;
        fprintf(stderr, "Incorrect exit status: expected %d but %s\n", test.exit_status,
                ExitStatusToString(status).c_str());
      }

      if (!CheckOutput("stdout", test_stdout.str(), test.expected_stdout, FILES)) failed = true;
      if (!CheckOutput("stderr", test_stderr.str(), test.expected_stderr, FILES)) failed = true;

      if (!RunCommands("after", test.afters)) failed = true;
    }

    std::stringstream duration;
    duration << test_timer;
    if (failed) {
      failures.push_back(test.name);
      Print(kRed, "[  FAILED  ]", " %s (%s)", test.name.c_str(), duration.str().c_str());
    } else {
      Print(kGreen, "[       OK ]", " %s (%s)", test.name.c_str(), duration.str().c_str());
    }
  }

  // Summarize the whole run and explicitly list all the failures.

  std::stringstream duration;
  duration << total_timer;
  Print(kGreen, "[==========]", " %zu tests ran. (%s total)", tests.size(), duration.str().c_str());

  size_t fail_count = failures.size();
  size_t pass_count = tests.size() - fail_count;
  Print(kGreen, "[  PASSED  ]", " %zu test%s.", pass_count, Plural(pass_count));
  if (!failures.empty()) {
    Print(kRed, "[  FAILED  ]", " %zu test%s.", fail_count, Plural(fail_count));
    for (auto& failure : failures) {
      Print(kRed, "[  FAILED  ]", " %s", failure.c_str());
    }
  }
  return (fail_count == 0) ? 0 : 1;
}

static void ShowHelp(bool full) {
  fprintf(full ? stdout : stderr, "usage: %s [-v] FILE...\n", g_progname);
  if (!full) exit(EXIT_FAILURE);

  printf(
      "\n"
      "Run tests.\n"
      "\n"
      "-v\tVerbose (show workings)\n");
  exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[]) {
  g_progname = basename(argv[0]);

  static const struct option opts[] = {
      {"help", no_argument, 0, 'h'},
      {"verbose", no_argument, 0, 'v'},
      {},
  };

  int opt;
  while ((opt = getopt_long(argc, argv, "hv", opts, nullptr)) != -1) {
    switch (opt) {
      case 'h':
        ShowHelp(true);
        break;
      case 'v':
        g_verbose = true;
        break;
      default:
        ShowHelp(false);
        break;
    }
  }

  argv += optind;
  if (!*argv) Die(0, "no test files provided");
  std::vector<Test> tests;
  for (; *argv; ++argv) CollectTests(&tests, *argv);
  return RunTests(tests);
}
