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

#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>
#include <lmkd.h>
#include <liblmkd_utils.h>
#include <log/log_properties.h>
#include <private/android_filesystem_config.h>

using namespace android::base;

#define INKERNEL_MINFREE_PATH "/sys/module/lowmemorykiller/parameters/minfree"
#define LMKDTEST_RESPAWN_FLAG "LMKDTEST_RESPAWN"

#define LMKD_LOGCAT_MARKER "lowmemorykiller"
#define LMKD_KILL_MARKER_TEMPLATE LMKD_LOGCAT_MARKER ": Killing '%s'"
#define OOM_MARKER "Out of memory"
#define OOM_KILL_MARKER "Killed process"
#define MIN_LOG_SIZE 100

#define ONE_MB (1 << 20)

/* Test constant parameters */
#define OOM_ADJ_MAX 1000
#define OOM_ADJ_MIN 0
#define OOM_ADJ_STEP 100
#define STEP_COUNT ((OOM_ADJ_MAX - OOM_ADJ_MIN) / OOM_ADJ_STEP + 1)

#define ALLOC_STEP (ONE_MB)
#define ALLOC_DELAY 1000

/* Utility functions */
std::string readCommand(const std::string& command) {
    FILE* fp = popen(command.c_str(), "r");
    std::string content;
    ReadFdToString(fileno(fp), &content);
    pclose(fp);
    return content;
}

std::string readLogcat(const std::string& marker) {
    std::string content = readCommand("logcat -d -b all");
    size_t pos = content.find(marker);
    if (pos == std::string::npos) return "";
    content.erase(0, pos);
    return content;
}

bool writeFile(const std::string& file, const std::string& string) {
    if (getuid() == static_cast<unsigned>(AID_ROOT)) {
        return WriteStringToFile(string, file);
    }
    return string == readCommand(
        "echo -n '" + string + "' | su root tee " + file + " 2>&1");
}

bool writeKmsg(const std::string& marker) {
    return writeFile("/dev/kmsg", marker);
}

std::string getTextAround(const std::string& text, size_t pos,
                          size_t lines_before, size_t lines_after) {
    size_t start_pos = pos;

    // find start position
    // move up lines_before number of lines
    while (lines_before > 0 &&
           (start_pos = text.rfind('\n', start_pos)) != std::string::npos) {
        lines_before--;
    }
    // move to the beginning of the line
    start_pos = text.rfind('\n', start_pos);
    start_pos = (start_pos == std::string::npos) ? 0 : start_pos + 1;

    // find end position
    // move down lines_after number of lines
    while (lines_after > 0 &&
           (pos = text.find('\n', pos)) != std::string::npos) {
        pos++;
        lines_after--;
    }
    return text.substr(start_pos, (pos == std::string::npos) ?
                       std::string::npos : pos - start_pos);
}

bool getExecPath(std::string &path) {
    // exec path as utf8z c_str().
    // std::string contains _all_ nul terminated argv[] strings.
    return android::base::ReadFileToString("/proc/self/cmdline", &path);
}

/* Child synchronization primitives */
#define STATE_INIT 0
#define STATE_CHILD_READY 1
#define STATE_PARENT_READY 2

struct state_sync {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int state;
};

struct state_sync * init_state_sync_obj() {
    struct state_sync *ssync;

    ssync = (struct state_sync*)mmap(NULL, sizeof(struct state_sync),
                PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (ssync == MAP_FAILED) {
        return NULL;
    }

    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(&ssync->mutex, &mattr);

    pthread_condattr_t cattr;
    pthread_condattr_init(&cattr);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
    pthread_cond_init(&ssync->condition, &cattr);

    ssync->state = STATE_INIT;
    return ssync;
}

void destroy_state_sync_obj(struct state_sync *ssync) {
    pthread_cond_destroy(&ssync->condition);
    pthread_mutex_destroy(&ssync->mutex);
    munmap(ssync, sizeof(struct state_sync));
}

void signal_state(struct state_sync *ssync, int state) {
    pthread_mutex_lock(&ssync->mutex);
    ssync->state = state;
    pthread_cond_signal(&ssync->condition);
    pthread_mutex_unlock(&ssync->mutex);
}

void wait_for_state(struct state_sync *ssync, int state) {
    pthread_mutex_lock(&ssync->mutex);
    while (ssync->state != state) {
        pthread_cond_wait(&ssync->condition, &ssync->mutex);
    }
    pthread_mutex_unlock(&ssync->mutex);
}

/* Memory allocation and data sharing */
struct shared_data {
    size_t allocated;
    bool finished;
    size_t total_size;
    size_t step_size;
    size_t step_delay;
    int oomadj;
};

volatile void *gptr;
void add_pressure(struct shared_data *data) {
    volatile void *ptr;
    size_t allocated_size = 0;

    data->finished = false;
    while (allocated_size < data->total_size) {
        ptr = mmap(NULL, data->step_size, PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
        if (ptr != MAP_FAILED) {
            /* create ptr aliasing to prevent compiler optimizing the access */
            gptr = ptr;
            /* make data non-zero */
            memset((void*)ptr, (int)(allocated_size + 1), data->step_size);
            allocated_size += data->step_size;
            data->allocated = allocated_size;
        }
        usleep(data->step_delay);
    }
    data->finished = (allocated_size >= data->total_size);
}

/* Memory stress test main body */
void runMemStressTest() {
    struct shared_data *data;
    struct state_sync *ssync;
    int sock;
    pid_t pid;
    uid_t uid = getuid();

    ASSERT_FALSE((sock = lmkd_connect()) < 0)
        << "Failed to connect to lmkd process, err=" << strerror(errno);

    /* allocate shared memory to communicate params with a child */
    data = (struct shared_data*)mmap(NULL, sizeof(struct shared_data),
                PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    ASSERT_FALSE(data == MAP_FAILED) << "Memory allocation failure";
    data->total_size = (size_t)-1; /* allocate until killed */
    data->step_size = ALLOC_STEP;
    data->step_delay = ALLOC_DELAY;

    /* allocate state sync object */
    ASSERT_FALSE((ssync = init_state_sync_obj()) == NULL)
        << "Memory allocation failure";

    /* run the test gradually decreasing oomadj */
    data->oomadj = OOM_ADJ_MAX;
    while (data->oomadj >= OOM_ADJ_MIN) {
        ASSERT_FALSE((pid = fork()) < 0)
            << "Failed to spawn a child process, err=" << strerror(errno);
        if (pid != 0) {
            /* Parent */
            struct lmk_procprio params;
            /* wait for child to start and get ready */
            wait_for_state(ssync, STATE_CHILD_READY);
            params.pid = pid;
            params.uid = uid;
            params.oomadj = data->oomadj;
            ASSERT_FALSE(lmkd_register_proc(sock, &params) < 0)
                << "Failed to communicate with lmkd, err=" << strerror(errno);
            // signal the child it can proceed
            signal_state(ssync, STATE_PARENT_READY);
            waitpid(pid, NULL, 0);
            if (data->finished) {
                GTEST_LOG_(INFO) << "Child [pid=" << pid << "] allocated "
                                 << data->allocated / ONE_MB << "MB";
            } else {
                GTEST_LOG_(INFO) << "Child [pid=" << pid << "] allocated "
                                 << data->allocated / ONE_MB
                                 << "MB before being killed";
            }
            data->oomadj -= OOM_ADJ_STEP;
        } else {
            /* Child */
            pid = getpid();
            GTEST_LOG_(INFO) << "Child [pid=" << pid
                             << "] is running at oomadj="
                             << data->oomadj;
            data->allocated = 0;
            data->finished = false;
            ASSERT_FALSE(create_memcg(uid, pid) != 0)
                << "Child [pid=" << pid << "] failed to create a cgroup";
            signal_state(ssync, STATE_CHILD_READY);
            wait_for_state(ssync, STATE_PARENT_READY);
            add_pressure(data);
            /* should not reach here, child should be killed by OOM/LMK */
            FAIL() << "Child [pid=" << pid << "] was not killed";
            break;
        }
    }
    destroy_state_sync_obj(ssync);
    munmap(data, sizeof(struct shared_data));
    close(sock);
}

TEST(lmkd, check_for_oom) {
    // test requirements
    //   userdebug build
    if (!__android_log_is_debuggable()) {
        GTEST_LOG_(INFO) << "Must be userdebug build, terminating test";
        return;
    }
    // check if in-kernel LMK driver is present
    if (!access(INKERNEL_MINFREE_PATH, W_OK)) {
        GTEST_LOG_(INFO) << "Must not have kernel lowmemorykiller driver,"
                         << " terminating test";
        return;
    }

    // if respawned test process then run the test and exit (no analysis)
    if (getenv(LMKDTEST_RESPAWN_FLAG) != NULL) {
        runMemStressTest();
        return;
    }

    // Main test process
    // mark the beginning of the test
    std::string marker = StringPrintf(
        "LMKD test start %lu\n", static_cast<unsigned long>(time(nullptr)));
    ASSERT_TRUE(writeKmsg(marker));

    // get executable complete path
    std::string test_path;
    ASSERT_TRUE(getExecPath(test_path));

    std::string test_output;
    if (getuid() != static_cast<unsigned>(AID_ROOT)) {
        // if not root respawn itself as root and capture output
        std::string command = StringPrintf(
            "%s=true su root %s --gtest_filter=lmkd.check_for_oom 2>&1",
            LMKDTEST_RESPAWN_FLAG, test_path.c_str());
        std::string test_output = readCommand(command);
        GTEST_LOG_(INFO) << test_output;
    } else {
        // main test process is root, run the test
        runMemStressTest();
    }

    // Analyze results
    // capture logcat containind kernel logs
    std::string logcat_out = readLogcat(marker);

    // 1. extract LMKD kills from logcat output, count kills
    std::stringstream kill_logs;
    int hit_count = 0;
    size_t pos = 0;
    marker = StringPrintf(LMKD_KILL_MARKER_TEMPLATE, test_path.c_str());

    while (true) {
        if ((pos = logcat_out.find(marker, pos)) != std::string::npos) {
            kill_logs << getTextAround(logcat_out, pos, 0, 1);
            pos += marker.length();
            hit_count++;
        } else {
            break;
        }
    }
    GTEST_LOG_(INFO) << "====Logged kills====" << std::endl
                     << kill_logs.str();
    EXPECT_TRUE(hit_count == STEP_COUNT) << "Number of kills " << hit_count
                                         << " is less than expected "
                                         << STEP_COUNT;

    // 2. check kernel logs for OOM kills
    pos = logcat_out.find(OOM_MARKER);
    bool oom_detected = (pos != std::string::npos);
    bool oom_kill_detected = (oom_detected &&
        logcat_out.find(OOM_KILL_MARKER, pos) != std::string::npos);

    EXPECT_FALSE(oom_kill_detected) << "OOM kill is detected!";
    if (oom_detected || oom_kill_detected) {
        // capture logcat with logs around all OOMs
        pos = 0;
        while ((pos = logcat_out.find(OOM_MARKER, pos)) != std::string::npos) {
            GTEST_LOG_(INFO) << "====Logs around OOM====" << std::endl
                             << getTextAround(logcat_out, pos,
                                    MIN_LOG_SIZE / 2, MIN_LOG_SIZE / 2);
            pos += strlen(OOM_MARKER);
        }
    }

    // output complete logcat with kernel (might get truncated)
    GTEST_LOG_(INFO) << "====Complete logcat output====" << std::endl
                     << logcat_out;
}

