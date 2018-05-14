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

#include "keychords.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/cdefs.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "init.h"

namespace android {
namespace init {

namespace {

int keychords_count;

struct KeychordEntry {
    const std::vector<int> keycodes;
    bool notified;
    int id;

    KeychordEntry(const std::vector<int>& keycodes, int id)
        : keycodes(keycodes), notified(false), id(id) {}
};

std::vector<KeychordEntry> keychord_entries;

// Bit management
class KeychordMask {
  private:
    typedef unsigned int mask_t;
    std::vector<mask_t> bits;
    static constexpr size_t bits_per_byte = 8;

  public:
    explicit KeychordMask(size_t bit = 0) : bits((bit + sizeof(mask_t) - 1) / sizeof(mask_t), 0) {}

    void SetBit(size_t bit, bool value = true) {
        auto idx = bit / (bits_per_byte * sizeof(mask_t));
        if (idx >= bits.size()) return;
        if (value) {
            bits[idx] |= mask_t(1) << (bit % (bits_per_byte * sizeof(mask_t)));
        } else {
            bits[idx] &= ~(mask_t(1) << (bit % (bits_per_byte * sizeof(mask_t))));
        }
    }

    bool GetBit(size_t bit) const {
        auto idx = bit / (bits_per_byte * sizeof(mask_t));
        return bits[idx] & (mask_t(1) << (bit % (bits_per_byte * sizeof(mask_t))));
    }

    size_t bytesize() const { return bits.size() * sizeof(mask_t); }
    void* data() { return bits.data(); }
    size_t size() const { return bits.size() * sizeof(mask_t) * bits_per_byte; }
    void resize(size_t bit) {
        auto idx = bit / (bits_per_byte * sizeof(mask_t));
        if (idx >= bits.size()) {
            bits.resize(idx + 1, 0);
        }
    }

    operator bool() const {
        for (size_t i = 0; i < bits.size(); ++i) {
            if (bits[i]) return true;
        }
        return false;
    }

    KeychordMask operator&(const KeychordMask& rval) const {
        auto len = std::min(bits.size(), rval.bits.size());
        KeychordMask ret;
        ret.bits.resize(len);
        for (size_t i = 0; i < len; ++i) {
            ret.bits[i] = bits[i] & rval.bits[i];
        }
        return ret;
    }

    void operator|=(const KeychordMask& rval) {
        size_t len = rval.bits.size();
        bits.resize(len);
        for (size_t i = 0; i < len; ++i) {
            bits[i] |= rval.bits[i];
        }
    }
};

KeychordMask keychord_current;

constexpr char kDevicePath[] = "/dev/input";

std::map<std::string, int> keychord_registration;

void HandleKeychord(int id) {
    // Only handle keychords if adb is enabled.
    std::string adb_enabled = android::base::GetProperty("init.svc.adbd", "");
    if (adb_enabled == "running") {
        Service* svc = ServiceList::GetInstance().FindService(id, &Service::keychord_id);
        if (svc) {
            LOG(INFO) << "Starting service '" << svc->name() << "' from keychord " << id;
            if (auto result = svc->Start(); !result) {
                LOG(ERROR) << "Could not start service '" << svc->name() << "' from keychord " << id
                           << ": " << result.error();
            }
        } else {
            LOG(ERROR) << "Service for keychord " << id << " not found";
        }
    } else {
        LOG(WARNING) << "Not starting service for keychord " << id << " because ADB is disabled";
    }
}

void KeychordLambdaCheck() {
    for (auto& e : keychord_entries) {
        bool found = true;
        for (auto& code : e.keycodes) {
            if (!keychord_current.GetBit(code)) {
                e.notified = false;
                found = false;
                break;
            }
        }
        if (!found) continue;
        if (e.notified) continue;
        e.notified = true;
        HandleKeychord(e.id);
    }
}

void KeychordLambdaHandler(int fd) {
    input_event event;
    auto res = TEMP_FAILURE_RETRY(::read(fd, &event, sizeof(event)));
    if ((res != sizeof(event)) || (event.type != EV_KEY)) return;
    keychord_current.SetBit(event.code, event.value);
    KeychordLambdaCheck();
}

bool KeychordGeteventEnable(int fd) {
    static bool EviocsmaskSupported = true;

    // Make sure it is an event channel, should pass this ioctl call
    int version;
    if (::ioctl(fd, EVIOCGVERSION, &version)) return false;

    if (EviocsmaskSupported) {
        KeychordMask mask(EV_KEY);
        mask.SetBit(EV_KEY);
        input_mask msg = {};
        msg.type = EV_SYN;
        msg.codes_size = mask.bytesize();
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        if (::ioctl(fd, EVIOCSMASK, &msg) == -1) {
            PLOG(WARNING) << "EVIOCSMASK not supported";
            EviocsmaskSupported = false;
        }
    }

    KeychordMask mask;
    for (auto& e : keychord_entries) {
        for (auto& code : e.keycodes) {
            mask.resize(code);
            mask.SetBit(code);
        }
    }

    keychord_current.resize(mask.size());
    KeychordMask available(mask.size());
    auto res = ::ioctl(fd, EVIOCGBIT(EV_KEY, available.bytesize()), available.data());
    if (res == -1) return false;
    if (!(available & mask)) return false;

    if (EviocsmaskSupported) {
        input_mask msg = {};
        msg.type = EV_KEY;
        msg.codes_size = mask.bytesize();
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        ::ioctl(fd, EVIOCSMASK, &msg);
    }

    KeychordMask set(mask.size());
    res = ::ioctl(fd, EVIOCGKEY(res), set.data());
    if (res > 0) {
        keychord_current |= mask & available & set;
        KeychordLambdaCheck();
    }
    register_epoll_handler(fd, [fd]() { KeychordLambdaHandler(fd); });
    return true;
}

void GeteventOpenDevice(const std::string& device) {
    if (keychord_registration.count(device)) return;
    auto fd = TEMP_FAILURE_RETRY(::open(device.c_str(), O_RDWR | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Can not open " << device;
        return;
    }
    if (!KeychordGeteventEnable(fd)) {
        ::close(fd);
    } else {
        keychord_registration.emplace(device, fd);
    }
}

void GeteventCloseDevice(const std::string& device) {
    auto it = keychord_registration.find(device);
    if (it == keychord_registration.end()) return;
    auto fd = (*it).second;
    unregister_epoll_handler(fd);
    keychord_registration.erase(it);
    ::close(fd);
}

int inotify_fd = -1;

void InotifyHandler() {
    unsigned char buf[512];

    auto res = TEMP_FAILURE_RETRY(::read(inotify_fd, buf, sizeof(buf)));
    if (res < 0) {
        PLOG(WARNING) << "could not get event";
        return;
    }

    auto event_buf = buf;
    while (static_cast<size_t>(res) >= sizeof(inotify_event)) {
        auto event = reinterpret_cast<inotify_event*>(event_buf);
        auto event_size = sizeof(inotify_event) + event->len;
        if (static_cast<size_t>(res) < event_size) break;
        if (event->len) {
            std::string devname(kDevicePath);
            devname += '/';
            devname += event->name;
            if (event->mask & IN_CREATE) {
                GeteventOpenDevice(devname);
            } else {
                GeteventCloseDevice(devname);
            }
        }
        res -= event_size;
        event_buf += event_size;
    }
}

void GeteventOpenDevice() {
    inotify_fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd < 0) {
        PLOG(WARNING) << "Could not instantiate inotify for " << kDevicePath;
    } else if (::inotify_add_watch(inotify_fd, kDevicePath, IN_DELETE | IN_CREATE | IN_ONLYDIR) < 0) {
        PLOG(WARNING) << "Could not add watch for " << kDevicePath;
        ::close(inotify_fd);
        inotify_fd = -1;
    }

    std::unique_ptr<DIR, decltype(&closedir)> device(opendir(kDevicePath), closedir);
    if (device) {
        dirent* entry;
        while ((entry = readdir(device.get()))) {
            if (entry->d_name[0] == '.') continue;
            std::string devname(kDevicePath);
            devname += '/';
            devname += entry->d_name;
            GeteventOpenDevice(devname);
        }
    }

    if (inotify_fd >= 0) register_epoll_handler(inotify_fd, InotifyHandler);
}

void AddServiceKeycodes(Service* svc) {
    if (svc->keycodes().empty()) return;
    for (auto& code : svc->keycodes()) {
        if ((code < 0) || (code >= KEY_MAX)) return;
    }
    ++keychords_count;
    keychord_entries.emplace_back(KeychordEntry(svc->keycodes(), keychords_count));
    svc->set_keychord_id(keychords_count);
}

}  // namespace

void KeychordInit() {
    for (const auto& service : ServiceList::GetInstance()) {
        AddServiceKeycodes(service.get());
    }
    if (keychords_count) GeteventOpenDevice();
}

}  // namespace init
}  // namespace android
