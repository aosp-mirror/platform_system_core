/* http://frotznet.googlecode.com/svn/trunk/utils/fdevent.c
**
** Copyright 2006, Brian Swetland <swetland@frotz.net>
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define TRACE_TAG FDEVENT

#include "sysdeps.h"
#include "fdevent.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <functional>
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>

#include "adb_io.h"
#include "adb_trace.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"

#if !ADB_HOST
// This socket is used when a subproc shell service exists.
// It wakes up the fdevent_loop() and cause the correct handling
// of the shell's pseudo-tty master. I.e. force close it.
int SHELL_EXIT_NOTIFY_FD = -1;
#endif // !ADB_HOST

#define FDE_EVENTMASK  0x00ff
#define FDE_STATEMASK  0xff00

#define FDE_ACTIVE     0x0100
#define FDE_PENDING    0x0200
#define FDE_CREATED    0x0400

struct PollNode {
  fdevent* fde;
  adb_pollfd pollfd;

  explicit PollNode(fdevent* fde) : fde(fde) {
      memset(&pollfd, 0, sizeof(pollfd));
      pollfd.fd = fde->fd;

#if defined(__linux__)
      // Always enable POLLRDHUP, so the host server can take action when some clients disconnect.
      // Then we can avoid leaving many sockets in CLOSE_WAIT state. See http://b/23314034.
      pollfd.events = POLLRDHUP;
#endif
  }
};

// All operations to fdevent should happen only in the main thread.
// That's why we don't need a lock for fdevent.
static auto& g_poll_node_map = *new std::unordered_map<int, PollNode>();
static auto& g_pending_list = *new std::list<fdevent*>();
static std::atomic<bool> terminate_loop(false);
static bool main_thread_valid;
static unsigned long main_thread_id;

static auto& run_queue_notify_fd = *new unique_fd();
static auto& run_queue_mutex = *new std::mutex();
static auto& run_queue GUARDED_BY(run_queue_mutex) = *new std::vector<std::function<void()>>();

void check_main_thread() {
    if (main_thread_valid) {
        CHECK_EQ(main_thread_id, adb_thread_id());
    }
}

void set_main_thread() {
    main_thread_valid = true;
    main_thread_id = adb_thread_id();
}

static std::string dump_fde(const fdevent* fde) {
    std::string state;
    if (fde->state & FDE_ACTIVE) {
        state += "A";
    }
    if (fde->state & FDE_PENDING) {
        state += "P";
    }
    if (fde->state & FDE_CREATED) {
        state += "C";
    }
    if (fde->state & FDE_READ) {
        state += "R";
    }
    if (fde->state & FDE_WRITE) {
        state += "W";
    }
    if (fde->state & FDE_ERROR) {
        state += "E";
    }
    if (fde->state & FDE_DONT_CLOSE) {
        state += "D";
    }
    return android::base::StringPrintf("(fdevent %d %s)", fde->fd, state.c_str());
}

fdevent* fdevent_create(int fd, fd_func func, void* arg) {
    check_main_thread();
    fdevent *fde = (fdevent*) malloc(sizeof(fdevent));
    if(fde == 0) return 0;
    fdevent_install(fde, fd, func, arg);
    fde->state |= FDE_CREATED;
    return fde;
}

void fdevent_destroy(fdevent* fde) {
    check_main_thread();
    if(fde == 0) return;
    if(!(fde->state & FDE_CREATED)) {
        LOG(FATAL) << "destroying fde not created by fdevent_create(): " << dump_fde(fde);
    }
    fdevent_remove(fde);
    free(fde);
}

void fdevent_install(fdevent* fde, int fd, fd_func func, void* arg) {
    check_main_thread();
    CHECK_GE(fd, 0);
    memset(fde, 0, sizeof(fdevent));
    fde->state = FDE_ACTIVE;
    fde->fd = fd;
    fde->func = func;
    fde->arg = arg;
    if (!set_file_block_mode(fd, false)) {
        // Here is not proper to handle the error. If it fails here, some error is
        // likely to be detected by poll(), then we can let the callback function
        // to handle it.
        LOG(ERROR) << "failed to set non-blocking mode for fd " << fd;
    }
    auto pair = g_poll_node_map.emplace(fde->fd, PollNode(fde));
    CHECK(pair.second) << "install existing fd " << fd;
    D("fdevent_install %s", dump_fde(fde).c_str());
}

void fdevent_remove(fdevent* fde) {
    check_main_thread();
    D("fdevent_remove %s", dump_fde(fde).c_str());
    if (fde->state & FDE_ACTIVE) {
        g_poll_node_map.erase(fde->fd);
        if (fde->state & FDE_PENDING) {
            g_pending_list.remove(fde);
        }
        if (!(fde->state & FDE_DONT_CLOSE)) {
            adb_close(fde->fd);
            fde->fd = -1;
        }
        fde->state = 0;
        fde->events = 0;
    }
}

static void fdevent_update(fdevent* fde, unsigned events) {
    auto it = g_poll_node_map.find(fde->fd);
    CHECK(it != g_poll_node_map.end());
    PollNode& node = it->second;
    if (events & FDE_READ) {
        node.pollfd.events |= POLLIN;
    } else {
        node.pollfd.events &= ~POLLIN;
    }

    if (events & FDE_WRITE) {
        node.pollfd.events |= POLLOUT;
    } else {
        node.pollfd.events &= ~POLLOUT;
    }
    fde->state = (fde->state & FDE_STATEMASK) | events;
}

void fdevent_set(fdevent* fde, unsigned events) {
    check_main_thread();
    events &= FDE_EVENTMASK;
    if ((fde->state & FDE_EVENTMASK) == events) {
        return;
    }
    CHECK(fde->state & FDE_ACTIVE);
    fdevent_update(fde, events);
    D("fdevent_set: %s, events = %u", dump_fde(fde).c_str(), events);

    if (fde->state & FDE_PENDING) {
        // If we are pending, make sure we don't signal an event that is no longer wanted.
        fde->events &= events;
        if (fde->events == 0) {
            g_pending_list.remove(fde);
            fde->state &= ~FDE_PENDING;
        }
    }
}

void fdevent_add(fdevent* fde, unsigned events) {
    check_main_thread();
    fdevent_set(fde, (fde->state & FDE_EVENTMASK) | events);
}

void fdevent_del(fdevent* fde, unsigned events) {
    check_main_thread();
    fdevent_set(fde, (fde->state & FDE_EVENTMASK) & ~events);
}

static std::string dump_pollfds(const std::vector<adb_pollfd>& pollfds) {
    std::string result;
    for (const auto& pollfd : pollfds) {
        std::string op;
        if (pollfd.events & POLLIN) {
            op += "R";
        }
        if (pollfd.events & POLLOUT) {
            op += "W";
        }
        android::base::StringAppendF(&result, " %d(%s)", pollfd.fd, op.c_str());
    }
    return result;
}

static void fdevent_process() {
    std::vector<adb_pollfd> pollfds;
    for (const auto& pair : g_poll_node_map) {
        pollfds.push_back(pair.second.pollfd);
    }
    CHECK_GT(pollfds.size(), 0u);
    D("poll(), pollfds = %s", dump_pollfds(pollfds).c_str());
    int ret = adb_poll(&pollfds[0], pollfds.size(), -1);
    if (ret == -1) {
        PLOG(ERROR) << "poll(), ret = " << ret;
        return;
    }
    for (const auto& pollfd : pollfds) {
        if (pollfd.revents != 0) {
            D("for fd %d, revents = %x", pollfd.fd, pollfd.revents);
        }
        unsigned events = 0;
        if (pollfd.revents & POLLIN) {
            events |= FDE_READ;
        }
        if (pollfd.revents & POLLOUT) {
            events |= FDE_WRITE;
        }
        if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            // We fake a read, as the rest of the code assumes that errors will
            // be detected at that point.
            events |= FDE_READ | FDE_ERROR;
        }
#if defined(__linux__)
        if (pollfd.revents & POLLRDHUP) {
            events |= FDE_READ | FDE_ERROR;
        }
#endif
        if (events != 0) {
            auto it = g_poll_node_map.find(pollfd.fd);
            CHECK(it != g_poll_node_map.end());
            fdevent* fde = it->second.fde;
            CHECK_EQ(fde->fd, pollfd.fd);
            fde->events |= events;
            D("%s got events %x", dump_fde(fde).c_str(), events);
            fde->state |= FDE_PENDING;
            g_pending_list.push_back(fde);
        }
    }
}

static void fdevent_call_fdfunc(fdevent* fde) {
    unsigned events = fde->events;
    fde->events = 0;
    CHECK(fde->state & FDE_PENDING);
    fde->state &= (~FDE_PENDING);
    D("fdevent_call_fdfunc %s", dump_fde(fde).c_str());
    fde->func(fde->fd, events, fde->arg);
}

#if !ADB_HOST

#include <sys/ioctl.h>

static void fdevent_subproc_event_func(int fd, unsigned ev, void* /* userdata */) {
    D("subproc handling on fd = %d, ev = %x", fd, ev);

    CHECK_GE(fd, 0);

    if (ev & FDE_READ) {
        int subproc_fd;

        if(!ReadFdExactly(fd, &subproc_fd, sizeof(subproc_fd))) {
            LOG(FATAL) << "Failed to read the subproc's fd from " << fd;
        }
        auto it = g_poll_node_map.find(subproc_fd);
        if (it == g_poll_node_map.end()) {
            D("subproc_fd %d cleared from fd_table", subproc_fd);
            adb_close(subproc_fd);
            return;
        }
        fdevent* subproc_fde = it->second.fde;
        if(subproc_fde->fd != subproc_fd) {
            // Already reallocated?
            LOG(FATAL) << "subproc_fd(" << subproc_fd << ") != subproc_fde->fd(" << subproc_fde->fd
                       << ")";
            return;
        }

        subproc_fde->force_eof = 1;

        int rcount = 0;
        ioctl(subproc_fd, FIONREAD, &rcount);
        D("subproc with fd %d has rcount=%d, err=%d", subproc_fd, rcount, errno);
        if (rcount != 0) {
            // If there is data left, it will show up in the select().
            // This works because there is no other thread reading that
            // data when in this fd_func().
            return;
        }

        D("subproc_fde %s", dump_fde(subproc_fde).c_str());
        subproc_fde->events |= FDE_READ;
        if(subproc_fde->state & FDE_PENDING) {
            return;
        }
        subproc_fde->state |= FDE_PENDING;
        fdevent_call_fdfunc(subproc_fde);
    }
}

static void fdevent_subproc_setup() {
    int s[2];

    if(adb_socketpair(s)) {
        PLOG(FATAL) << "cannot create shell-exit socket-pair";
    }
    D("fdevent_subproc: socket pair (%d, %d)", s[0], s[1]);

    SHELL_EXIT_NOTIFY_FD = s[0];
    fdevent *fde = fdevent_create(s[1], fdevent_subproc_event_func, NULL);
    CHECK(fde != nullptr) << "cannot create fdevent for shell-exit handler";
    fdevent_add(fde, FDE_READ);
}
#endif // !ADB_HOST

static void fdevent_run_flush() REQUIRES(run_queue_mutex) {
    for (auto& f : run_queue) {
        f();
    }
    run_queue.clear();
}

static void fdevent_run_func(int fd, unsigned ev, void* /* userdata */) {
    CHECK_GE(fd, 0);
    CHECK(ev & FDE_READ);

    char buf[1024];

    // Empty the fd.
    if (adb_read(fd, buf, sizeof(buf)) == -1) {
        PLOG(FATAL) << "failed to empty run queue notify fd";
    }

    std::lock_guard<std::mutex> lock(run_queue_mutex);
    fdevent_run_flush();
}

static void fdevent_run_setup() {
    std::lock_guard<std::mutex> lock(run_queue_mutex);
    CHECK(run_queue_notify_fd.get() == -1);
    int s[2];
    if (adb_socketpair(s) != 0) {
        PLOG(FATAL) << "failed to create run queue notify socketpair";
    }

    run_queue_notify_fd.reset(s[0]);
    fdevent* fde = fdevent_create(s[1], fdevent_run_func, nullptr);
    CHECK(fde != nullptr);
    fdevent_add(fde, FDE_READ);

    fdevent_run_flush();
}

void fdevent_run_on_main_thread(std::function<void()> fn) {
    std::lock_guard<std::mutex> lock(run_queue_mutex);
    run_queue.push_back(std::move(fn));

    // run_queue_notify_fd could still be -1 if we're called before fdevent has finished setting up.
    // In that case, rely on the setup code to flush the queue without a notification being needed.
    if (run_queue_notify_fd != -1) {
        if (adb_write(run_queue_notify_fd.get(), "", 1) != 1) {
            PLOG(FATAL) << "failed to write to run queue notify fd";
        }
    }
}

void fdevent_loop() {
    set_main_thread();
#if !ADB_HOST
    fdevent_subproc_setup();
#endif // !ADB_HOST
    fdevent_run_setup();

    while (true) {
        if (terminate_loop) {
            return;
        }

        D("--- --- waiting for events");

        fdevent_process();

        while (!g_pending_list.empty()) {
            fdevent* fde = g_pending_list.front();
            g_pending_list.pop_front();
            fdevent_call_fdfunc(fde);
        }
    }
}

void fdevent_terminate_loop() {
    terminate_loop = true;
}

size_t fdevent_installed_count() {
    return g_poll_node_map.size();
}

void fdevent_reset() {
    g_poll_node_map.clear();
    g_pending_list.clear();

    std::lock_guard<std::mutex> lock(run_queue_mutex);
    run_queue_notify_fd.reset();
    run_queue.clear();

    main_thread_valid = false;
    terminate_loop = false;
}
