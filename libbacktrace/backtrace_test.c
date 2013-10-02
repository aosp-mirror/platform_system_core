/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <inttypes.h>

#include <backtrace/backtrace.h>

#define FINISH(pid) dump_frames(&backtrace); if (pid < 0) exit(1); else return false;

// Prototypes for functions in the test library.
int test_level_one(int, int, int, int, bool (*)(pid_t));

int test_recursive_call(int, bool (*)(pid_t));

void dump_frames(const backtrace_t* backtrace) {
  for (size_t i = 0; i < backtrace->num_frames; i++) {
    printf("%zu ", i);
    if (backtrace->frames[i].map_name) {
      printf("%s", backtrace->frames[i].map_name);
    } else {
      printf("<unknown>");
    }
    if (backtrace->frames[i].proc_name) {
      printf(" %s", backtrace->frames[i].proc_name);
      if (backtrace->frames[i].proc_offset) {
        printf("+%" PRIuPTR, backtrace->frames[i].proc_offset);
      }
    }
    printf("\n");
  }
}

bool check_frame(const backtrace_t* backtrace, size_t frame_num,
                 const char* expected_name) {
  if (backtrace->frames[frame_num].proc_name == NULL) {
    printf("  Frame %zu function name expected %s, real value is NULL.\n",
           frame_num, expected_name);
    return false;
  }
  if (strcmp(backtrace->frames[frame_num].proc_name, expected_name) != 0) {
    printf("  Frame %zu function name expected %s, real value is %s.\n",
           frame_num, expected_name, backtrace->frames[frame_num].proc_name);
    return false;
  }
  return true;
}

bool verify_level_backtrace(pid_t pid) {
  const char* test_type;
  if (pid < 0) {
    test_type = "current";
  } else {
    test_type = "running";
  }

  backtrace_t backtrace;
  if (!backtrace_get_data(&backtrace, pid)) {
    printf("  backtrace_get_data failed on %s process.\n", test_type);
    FINISH(pid);
  }

  if (backtrace.num_frames == 0) {
    printf("  backtrace_get_data returned no frames for %s process.\n",
           test_type);
    FINISH(pid);
  }

  // Look through the frames starting at the highest to find the
  // frame we want.
  size_t frame_num = 0;
  for (size_t i = backtrace.num_frames-1; i > 2; i--) {
    if (backtrace.frames[i].proc_name != NULL &&
        strcmp(backtrace.frames[i].proc_name, "test_level_one") == 0) {
      frame_num = i;
      break;
    }
  }
  if (!frame_num) {
    printf("  backtrace_get_data did not include the test_level_one frame.\n");
    FINISH(pid);
  }

  if (!check_frame(&backtrace, frame_num, "test_level_one")) {
    FINISH(pid);
  }
  if (!check_frame(&backtrace, frame_num-1, "test_level_two")) {
    FINISH(pid);
  }
  if (!check_frame(&backtrace, frame_num-2, "test_level_three")) {
    FINISH(pid);
  }
  if (!check_frame(&backtrace, frame_num-3, "test_level_four")) {
    FINISH(pid);
  }
  backtrace_free_data(&backtrace);

  return true;
}

bool verify_max_backtrace(pid_t pid) {
  const char* test_type;
  if (pid < 0) {
    test_type = "current";
  } else {
    test_type = "running";
  }

  backtrace_t backtrace;
  if (!backtrace_get_data(&backtrace, pid)) {
    printf("  backtrace_get_data failed on %s process.\n", test_type);
    FINISH(pid);
  }

  if (backtrace.num_frames != MAX_BACKTRACE_FRAMES) {
    printf("  backtrace_get_data %s process max frame check failed:\n",
           test_type);
    printf("    Expected num frames to be %zu, found %zu\n",
           MAX_BACKTRACE_FRAMES, backtrace.num_frames);
    FINISH(pid);
  }
  backtrace_free_data(&backtrace);

  return true;
}

void verify_proc_test(pid_t pid, bool (*verify_func)(pid_t)) {
  printf("  Waiting 5 seconds for process to get to infinite loop.\n");
  sleep(5);
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
    printf("Failed to attach to pid %d\n", pid);
    kill(pid, SIGKILL);
    exit(1);
  }
  bool pass = verify_func(pid);
  if (ptrace(PTRACE_DETACH, pid, 0, 0) != 0) {
    printf("Failed to detach from pid %d\n", pid);
    kill(pid, SIGKILL);
    exit(1);
  }

  kill(pid, SIGKILL);
  int status;
  if (waitpid(pid, &status, 0) != pid) {
    printf("Forked process did not terminate properly.\n");
    exit(1);
  }

  if (!pass) {
    exit(1);
  }
}

int main() {
  printf("Running level test on current process...\n");
  int value = test_level_one(1, 2, 3, 4, verify_level_backtrace);
  if (value == 0) {
    printf("This should never happen.\n");
    exit(1);
  }
  printf("  Passed.\n");

  printf("Running max level test on current process...\n");
  value = test_recursive_call(MAX_BACKTRACE_FRAMES+10, verify_max_backtrace);
  if (value == 0) {
    printf("This should never happen.\n");
    exit(1);
  }
  printf("  Passed.\n");

  printf("Running level test on process...\n");
  pid_t pid;
  if ((pid = fork()) == 0) {
    value = test_level_one(1, 2, 3, 4, NULL);
    if (value == 0) {
      printf("This should never happen.\n");
    }
    exit(1);
  }
  verify_proc_test(pid, verify_level_backtrace);
  printf("  Passed.\n");

  printf("Running max frame test on process...\n");
  if ((pid = fork()) == 0) {
    value = test_recursive_call(MAX_BACKTRACE_FRAMES+10, NULL);
    if (value == 0) {
      printf("This should never happen.\n");
    }
    exit(1);
  }
  verify_proc_test(pid, verify_max_backtrace);
  printf("  Passed.\n");

  printf("All tests passed.\n");
  return 0;
}
