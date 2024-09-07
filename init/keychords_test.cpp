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

#include "keychords.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <stdint.h>
#include <sys/types.h>

#include <chrono>
#include <set>
#include <string>
#include <vector>

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "epoll.h"

using namespace std::chrono_literals;

namespace android {
namespace init {

namespace {

// This class is used to inject keys.
class EventHandler {
  public:
    EventHandler();
    EventHandler(const EventHandler&) = delete;
    EventHandler(EventHandler&&) noexcept;
    EventHandler& operator=(const EventHandler&) = delete;
    EventHandler& operator=(EventHandler&&) noexcept;
    ~EventHandler() noexcept;

    bool init();

    bool send(struct input_event& e);
    bool send(uint16_t type, uint16_t code, uint16_t value);
    bool send(uint16_t code, bool value);

  private:
    int fd_;
};

EventHandler::EventHandler() : fd_(-1) {}

EventHandler::EventHandler(EventHandler&& rval) noexcept : fd_(rval.fd_) {
    rval.fd_ = -1;
}

EventHandler& EventHandler::operator=(EventHandler&& rval) noexcept {
    fd_ = rval.fd_;
    rval.fd_ = -1;
    return *this;
}

EventHandler::~EventHandler() {
    if (fd_ == -1) return;
    ::ioctl(fd_, UI_DEV_DESTROY);
    ::close(fd_);
}

bool EventHandler::init() {
    if (fd_ != -1) return true;
    auto fd = TEMP_FAILURE_RETRY(::open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC));
    if (fd == -1) return false;
    if (::ioctl(fd, UI_SET_EVBIT, EV_KEY) == -1) {
        ::close(fd);
        return false;
    }

    static const struct uinput_user_dev u = {
        .name = "com.google.android.init.test",
        .id.bustype = BUS_VIRTUAL,
        .id.vendor = 0x1AE0,   // Google
        .id.product = 0x494E,  // IN
        .id.version = 1,
    };
    if (TEMP_FAILURE_RETRY(::write(fd, &u, sizeof(u))) != sizeof(u)) {
        ::close(fd);
        return false;
    }

    // all keys
    for (uint16_t i = 0; i < KEY_MAX; ++i) {
        if (::ioctl(fd, UI_SET_KEYBIT, i) == -1) {
            ::close(fd);
            return false;
        }
    }
    if (::ioctl(fd, UI_DEV_CREATE) == -1) {
        ::close(fd);
        return false;
    }
    fd_ = fd;
    return true;
}

bool EventHandler::send(struct input_event& e) {
    gettimeofday(&e.time, nullptr);
    return TEMP_FAILURE_RETRY(::write(fd_, &e, sizeof(e))) == sizeof(e);
}

bool EventHandler::send(uint16_t type, uint16_t code, uint16_t value) {
    struct input_event e = {.type = type, .code = code, .value = value};
    return send(e);
}

bool EventHandler::send(uint16_t code, bool value) {
    return (code < KEY_MAX) && init() && send(EV_KEY, code, value) && send(EV_SYN, SYN_REPORT, 0);
}

std::string InitFds(const char* prefix, pid_t pid = getpid()) {
    std::string ret;

    std::string init_fds("/proc/");
    init_fds += std::to_string(pid) + "/fd";
    std::unique_ptr<DIR, decltype(&closedir)> fds(opendir(init_fds.c_str()), closedir);
    if (!fds) return ret;

    dirent* entry;
    while ((entry = readdir(fds.get()))) {
        if (entry->d_name[0] == '.') continue;
        std::string devname = init_fds + '/' + entry->d_name;
        char buf[256];
        auto retval = readlink(devname.c_str(), buf, sizeof(buf) - 1);
        if ((retval < 0) || (size_t(retval) >= (sizeof(buf) - 1))) continue;
        buf[retval] = '\0';
        if (!android::base::StartsWith(buf, prefix)) continue;
        if (ret.size() != 0) ret += ",";
        ret += buf;
    }
    return ret;
}

std::string InitInputFds() {
    return InitFds("/dev/input/");
}

std::string InitInotifyFds() {
    return InitFds("anon_inode:inotify");
}

// NB: caller (this series of tests, or conversely the service parser in init)
// is responsible for validation, sorting and uniqueness of the chords, so no
// fuzzing is advised.

const std::vector<int> escape_chord = {KEY_ESC};
const std::vector<int> triple1_chord = {KEY_BACKSPACE, KEY_VOLUMEDOWN, KEY_VOLUMEUP};
const std::vector<int> triple2_chord = {KEY_VOLUMEDOWN, KEY_VOLUMEUP, KEY_BACK};

const std::vector<const std::vector<int>> empty_chords;
const std::vector<const std::vector<int>> chords = {
    escape_chord,
    triple1_chord,
    triple2_chord,
};

class TestFrame {
  public:
    TestFrame(const std::vector<const std::vector<int>>& chords, EventHandler* ev = nullptr);

    void RelaxForMs(std::chrono::milliseconds wait = 1ms);

    void SetChord(int key, bool value = true);
    void SetChords(const std::vector<int>& chord, bool value = true);
    void ClrChord(int key);
    void ClrChords(const std::vector<int>& chord);

    bool IsOnlyChord(const std::vector<int>& chord) const;
    bool IsNoChord() const;
    bool IsChord(const std::vector<int>& chord) const;
    void WaitForChord(const std::vector<int>& chord);

    std::string Format() const;

  private:
    static std::string Format(const std::vector<const std::vector<int>>& chords);

    Epoll epoll_;
    Keychords keychords_;
    std::vector<const std::vector<int>> keycodes_;
    EventHandler* ev_;
};

TestFrame::TestFrame(const std::vector<const std::vector<int>>& chords, EventHandler* ev)
    : ev_(ev) {
    if (!epoll_.Open().ok()) return;
    for (const auto& keycodes : chords) keychords_.Register(keycodes);
    keychords_.Start(&epoll_, [this](const std::vector<int>& keycodes) {
        this->keycodes_.emplace_back(keycodes);
    });
}

void TestFrame::RelaxForMs(std::chrono::milliseconds wait) {
    auto epoll_result = epoll_.Wait(wait);
    ASSERT_RESULT_OK(epoll_result);
}

void TestFrame::SetChord(int key, bool value) {
    ASSERT_TRUE(!!ev_);
    RelaxForMs();
    EXPECT_TRUE(ev_->send(key, value));
}

void TestFrame::SetChords(const std::vector<int>& chord, bool value) {
    ASSERT_TRUE(!!ev_);
    for (auto& key : chord) SetChord(key, value);
    RelaxForMs();
}

void TestFrame::ClrChord(int key) {
    ASSERT_TRUE(!!ev_);
    SetChord(key, false);
}

void TestFrame::ClrChords(const std::vector<int>& chord) {
    ASSERT_TRUE(!!ev_);
    SetChords(chord, false);
}

bool TestFrame::IsOnlyChord(const std::vector<int>& chord) const {
    auto ret = false;
    for (const auto& keycode : keycodes_) {
        if (keycode != chord) return false;
        ret = true;
    }
    return ret;
}

bool TestFrame::IsNoChord() const {
    return keycodes_.empty();
}

bool TestFrame::IsChord(const std::vector<int>& chord) const {
    for (const auto& keycode : keycodes_) {
        if (keycode == chord) return true;
    }
    return false;
}

void TestFrame::WaitForChord(const std::vector<int>& chord) {
    for (int retry = 1000; retry && !IsChord(chord); --retry) RelaxForMs();
}

std::string TestFrame::Format(const std::vector<const std::vector<int>>& chords) {
    std::string ret("{");
    if (!chords.empty()) {
        ret += android::base::Join(chords.front(), ' ');
        for (auto it = std::next(chords.begin()); it != chords.end(); ++it) {
            ret += ',';
            ret += android::base::Join(*it, ' ');
        }
    }
    return ret + '}';
}

std::string TestFrame::Format() const {
    return Format(keycodes_);
}

}  // namespace

TEST(keychords, not_instantiated) {
    TestFrame test_frame(empty_chords);
    EXPECT_TRUE(InitInotifyFds().size() == 0);
}

TEST(keychords, instantiated) {
    // Test if a valid set of chords results in proper instantiation of the
    // underlying mechanisms for /dev/input/ attachment.
    TestFrame test_frame(chords);
    EXPECT_TRUE(InitInotifyFds().size() != 0);
}

TEST(keychords, init_inotify) {
    std::string before(InitInputFds());

    TestFrame test_frame(chords);

    EventHandler ev;
    EXPECT_TRUE(ev.init());

    for (int retry = 1000; retry && before == InitInputFds(); --retry) test_frame.RelaxForMs();
    std::string after(InitInputFds());
    EXPECT_NE(before, after);
}

TEST(keychords, key) {
    EventHandler ev;
    EXPECT_TRUE(ev.init());
    TestFrame test_frame(chords, &ev);

    test_frame.SetChords(escape_chord);
    test_frame.WaitForChord(escape_chord);
    test_frame.ClrChords(escape_chord);
    EXPECT_TRUE(test_frame.IsOnlyChord(escape_chord))
        << "expected only " << android::base::Join(escape_chord, ' ') << " got "
        << test_frame.Format();
}

TEST(keychords, keys_in_series) {
    EventHandler ev;
    EXPECT_TRUE(ev.init());
    TestFrame test_frame(chords, &ev);

    for (auto& key : triple1_chord) {
        test_frame.SetChord(key);
        test_frame.ClrChord(key);
    }
    test_frame.WaitForChord(triple1_chord);
    EXPECT_TRUE(test_frame.IsNoChord()) << "expected nothing got " << test_frame.Format();
}

TEST(keychords, keys_in_parallel) {
    EventHandler ev;
    EXPECT_TRUE(ev.init());
    TestFrame test_frame(chords, &ev);

    test_frame.SetChords(triple2_chord);
    test_frame.WaitForChord(triple2_chord);
    test_frame.ClrChords(triple2_chord);
    EXPECT_TRUE(test_frame.IsOnlyChord(triple2_chord))
        << "expected only " << android::base::Join(triple2_chord, ' ') << " got "
        << test_frame.Format();
}

}  // namespace init
}  // namespace android
