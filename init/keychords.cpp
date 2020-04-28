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

namespace android {
namespace init {

Keychords::Keychords() : epoll_(nullptr), inotify_fd_(-1) {}

Keychords::~Keychords() noexcept {
    if (inotify_fd_ >= 0) {
        epoll_->UnregisterHandler(inotify_fd_).IgnoreError();
        ::close(inotify_fd_);
    }
    while (!registration_.empty()) GeteventCloseDevice(registration_.begin()->first);
}

Keychords::Mask::Mask(size_t bit) : bits_((bit + sizeof(mask_t) - 1) / sizeof(mask_t), 0) {}

void Keychords::Mask::SetBit(size_t bit, bool value) {
    auto idx = bit / (kBitsPerByte * sizeof(mask_t));
    if (idx >= bits_.size()) return;
    if (value) {
        bits_[idx] |= mask_t(1) << (bit % (kBitsPerByte * sizeof(mask_t)));
    } else {
        bits_[idx] &= ~(mask_t(1) << (bit % (kBitsPerByte * sizeof(mask_t))));
    }
}

bool Keychords::Mask::GetBit(size_t bit) const {
    auto idx = bit / (kBitsPerByte * sizeof(mask_t));
    return bits_[idx] & (mask_t(1) << (bit % (kBitsPerByte * sizeof(mask_t))));
}

size_t Keychords::Mask::bytesize() const {
    return bits_.size() * sizeof(mask_t);
}

void* Keychords::Mask::data() {
    return bits_.data();
}

size_t Keychords::Mask::size() const {
    return bits_.size() * sizeof(mask_t) * kBitsPerByte;
}

void Keychords::Mask::resize(size_t bit) {
    auto idx = bit / (kBitsPerByte * sizeof(mask_t));
    if (idx >= bits_.size()) {
        bits_.resize(idx + 1, 0);
    }
}

Keychords::Mask::operator bool() const {
    for (size_t i = 0; i < bits_.size(); ++i) {
        if (bits_[i]) return true;
    }
    return false;
}

Keychords::Mask Keychords::Mask::operator&(const Keychords::Mask& rval) const {
    auto len = std::min(bits_.size(), rval.bits_.size());
    Keychords::Mask ret;
    ret.bits_.resize(len);
    for (size_t i = 0; i < len; ++i) {
        ret.bits_[i] = bits_[i] & rval.bits_[i];
    }
    return ret;
}

void Keychords::Mask::operator|=(const Keychords::Mask& rval) {
    auto len = rval.bits_.size();
    bits_.resize(len);
    for (size_t i = 0; i < len; ++i) {
        bits_[i] |= rval.bits_[i];
    }
}

Keychords::Entry::Entry() : notified(false) {}

void Keychords::LambdaCheck() {
    for (auto& [keycodes, entry] : entries_) {
        auto found = true;
        for (auto& code : keycodes) {
            if (!current_.GetBit(code)) {
                entry.notified = false;
                found = false;
                break;
            }
        }
        if (!found) continue;
        if (entry.notified) continue;
        entry.notified = true;
        handler_(keycodes);
    }
}

void Keychords::LambdaHandler(int fd) {
    input_event event;
    auto res = TEMP_FAILURE_RETRY(::read(fd, &event, sizeof(event)));
    if ((res != sizeof(event)) || (event.type != EV_KEY)) return;
    current_.SetBit(event.code, event.value);
    LambdaCheck();
}

bool Keychords::GeteventEnable(int fd) {
    // Make sure it is an event channel, should pass this ioctl call
    int version;
    if (::ioctl(fd, EVIOCGVERSION, &version)) return false;

#ifdef EVIOCSMASK
    static auto EviocsmaskSupported = true;
    if (EviocsmaskSupported) {
        Keychords::Mask mask(EV_KEY);
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
#endif

    Keychords::Mask mask;
    for (auto& [keycodes, entry] : entries_) {
        for (auto& code : keycodes) {
            mask.resize(code);
            mask.SetBit(code);
        }
    }

    current_.resize(mask.size());
    Keychords::Mask available(mask.size());
    auto res = ::ioctl(fd, EVIOCGBIT(EV_KEY, available.bytesize()), available.data());
    if (res == -1) return false;
    if (!(available & mask)) return false;

#ifdef EVIOCSMASK
    if (EviocsmaskSupported) {
        input_mask msg = {};
        msg.type = EV_KEY;
        msg.codes_size = mask.bytesize();
        msg.codes_ptr = reinterpret_cast<uintptr_t>(mask.data());
        ::ioctl(fd, EVIOCSMASK, &msg);
    }
#endif

    Keychords::Mask set(mask.size());
    res = ::ioctl(fd, EVIOCGKEY(res), set.data());
    if (res > 0) {
        current_ |= mask & available & set;
        LambdaCheck();
    }
    if (auto result = epoll_->RegisterHandler(fd, [this, fd]() { this->LambdaHandler(fd); });
        !result) {
        LOG(WARNING) << "Could not register keychord epoll handler: " << result.error();
        return false;
    }
    return true;
}

void Keychords::GeteventOpenDevice(const std::string& device) {
    if (registration_.count(device)) return;
    auto fd = TEMP_FAILURE_RETRY(::open(device.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd == -1) {
        PLOG(ERROR) << "Can not open " << device;
        return;
    }
    if (!GeteventEnable(fd)) {
        ::close(fd);
    } else {
        registration_.emplace(device, fd);
    }
}

void Keychords::GeteventCloseDevice(const std::string& device) {
    auto it = registration_.find(device);
    if (it == registration_.end()) return;
    auto fd = (*it).second;
    epoll_->UnregisterHandler(fd).IgnoreError();
    registration_.erase(it);
    ::close(fd);
}

void Keychords::InotifyHandler() {
    unsigned char buf[512];  // History shows 32-64 bytes typical

    auto res = TEMP_FAILURE_RETRY(::read(inotify_fd_, buf, sizeof(buf)));
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

void Keychords::GeteventOpenDevice() {
    inotify_fd_ = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd_ < 0) {
        PLOG(WARNING) << "Could not instantiate inotify for " << kDevicePath;
    } else if (::inotify_add_watch(inotify_fd_, kDevicePath, IN_DELETE | IN_CREATE | IN_ONLYDIR) <
               0) {
        PLOG(WARNING) << "Could not add watch for " << kDevicePath;
        ::close(inotify_fd_);
        inotify_fd_ = -1;
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

    if (inotify_fd_ >= 0) {
        if (auto result =
                    epoll_->RegisterHandler(inotify_fd_, [this]() { this->InotifyHandler(); });
            !result) {
            LOG(WARNING) << "Could not register keychord epoll handler: " << result.error();
        }
    }
}

void Keychords::Register(const std::vector<int>& keycodes) {
    if (keycodes.empty()) return;
    entries_.try_emplace(keycodes, Entry());
}

void Keychords::Start(Epoll* epoll, std::function<void(const std::vector<int>&)> handler) {
    epoll_ = epoll;
    handler_ = handler;
    if (entries_.size()) GeteventOpenDevice();
}

}  // namespace init
}  // namespace android
