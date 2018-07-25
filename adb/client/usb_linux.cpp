/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG USB

#include "sysdeps.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usbdevice_fs.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <list>
#include <mutex>
#include <string>
#include <thread>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb.h"
#include "transport.h"
#include "usb.h"

using namespace std::chrono_literals;
using namespace std::literals;

/* usb scan debugging is waaaay too verbose */
#define DBGX(x...)

namespace native {
struct usb_handle : public ::usb_handle {
    ~usb_handle() {
      if (fd != -1) unix_close(fd);
    }

    std::string path;
    int fd = -1;
    unsigned char ep_in;
    unsigned char ep_out;

    size_t max_packet_size;
    unsigned zero_mask;
    unsigned writeable = 1;

    usbdevfs_urb urb_in;
    usbdevfs_urb urb_out;

    bool urb_in_busy = false;
    bool urb_out_busy = false;
    bool dead = false;

    std::condition_variable cv;
    std::mutex mutex;

    // for garbage collecting disconnected devices
    bool mark;

    // ID of thread currently in REAPURB
    pthread_t reaper_thread = 0;
};

static auto& g_usb_handles_mutex = *new std::mutex();
static auto& g_usb_handles = *new std::list<usb_handle*>();

static int is_known_device(const char* dev_name) {
    std::lock_guard<std::mutex> lock(g_usb_handles_mutex);
    for (usb_handle* usb : g_usb_handles) {
        if (usb->path == dev_name) {
            // set mark flag to indicate this device is still alive
            usb->mark = true;
            return 1;
        }
    }
    return 0;
}

static void kick_disconnected_devices() {
    std::lock_guard<std::mutex> lock(g_usb_handles_mutex);
    // kick any devices in the device list that were not found in the device scan
    for (usb_handle* usb : g_usb_handles) {
        if (!usb->mark) {
            usb_kick(usb);
        } else {
            usb->mark = false;
        }
    }
}

static inline bool contains_non_digit(const char* name) {
    while (*name) {
        if (!isdigit(*name++)) return true;
    }
    return false;
}

static void find_usb_device(const std::string& base,
                            void (*register_device_callback)(const char*, const char*,
                                                             unsigned char, unsigned char, int, int,
                                                             unsigned, size_t)) {
    std::unique_ptr<DIR, int(*)(DIR*)> bus_dir(opendir(base.c_str()), closedir);
    if (!bus_dir) return;

    dirent* de;
    while ((de = readdir(bus_dir.get())) != nullptr) {
        if (contains_non_digit(de->d_name)) continue;

        std::string bus_name = base + "/" + de->d_name;

        std::unique_ptr<DIR, int(*)(DIR*)> dev_dir(opendir(bus_name.c_str()), closedir);
        if (!dev_dir) continue;

        while ((de = readdir(dev_dir.get()))) {
            unsigned char devdesc[4096];
            unsigned char* bufptr = devdesc;
            unsigned char* bufend;
            struct usb_device_descriptor* device;
            struct usb_config_descriptor* config;
            struct usb_interface_descriptor* interface;
            struct usb_endpoint_descriptor *ep1, *ep2;
            unsigned zero_mask = 0;
            size_t max_packet_size = 0;
            unsigned vid, pid;

            if (contains_non_digit(de->d_name)) continue;

            std::string dev_name = bus_name + "/" + de->d_name;
            if (is_known_device(dev_name.c_str())) {
                continue;
            }

            int fd = unix_open(dev_name.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd == -1) {
                continue;
            }

            size_t desclength = unix_read(fd, devdesc, sizeof(devdesc));
            bufend = bufptr + desclength;

                // should have device and configuration descriptors, and atleast two endpoints
            if (desclength < USB_DT_DEVICE_SIZE + USB_DT_CONFIG_SIZE) {
                D("desclength %zu is too small", desclength);
                unix_close(fd);
                continue;
            }

            device = (struct usb_device_descriptor*)bufptr;
            bufptr += USB_DT_DEVICE_SIZE;

            if((device->bLength != USB_DT_DEVICE_SIZE) || (device->bDescriptorType != USB_DT_DEVICE)) {
                unix_close(fd);
                continue;
            }

            vid = device->idVendor;
            pid = device->idProduct;
            DBGX("[ %s is V:%04x P:%04x ]\n", dev_name.c_str(), vid, pid);

                // should have config descriptor next
            config = (struct usb_config_descriptor *)bufptr;
            bufptr += USB_DT_CONFIG_SIZE;
            if (config->bLength != USB_DT_CONFIG_SIZE || config->bDescriptorType != USB_DT_CONFIG) {
                D("usb_config_descriptor not found");
                unix_close(fd);
                continue;
            }

                // loop through all the descriptors and look for the ADB interface
            while (bufptr < bufend) {
                unsigned char length = bufptr[0];
                unsigned char type = bufptr[1];

                if (type == USB_DT_INTERFACE) {
                    interface = (struct usb_interface_descriptor *)bufptr;
                    bufptr += length;

                    if (length != USB_DT_INTERFACE_SIZE) {
                        D("interface descriptor has wrong size");
                        break;
                    }

                    DBGX("bInterfaceClass: %d,  bInterfaceSubClass: %d,"
                         "bInterfaceProtocol: %d, bNumEndpoints: %d\n",
                         interface->bInterfaceClass, interface->bInterfaceSubClass,
                         interface->bInterfaceProtocol, interface->bNumEndpoints);

                    if (interface->bNumEndpoints == 2 &&
                        is_adb_interface(interface->bInterfaceClass, interface->bInterfaceSubClass,
                                         interface->bInterfaceProtocol)) {
                        struct stat st;
                        char pathbuf[128];
                        char link[256];
                        char *devpath = nullptr;

                        DBGX("looking for bulk endpoints\n");
                            // looks like ADB...
                        ep1 = (struct usb_endpoint_descriptor *)bufptr;
                        bufptr += USB_DT_ENDPOINT_SIZE;
                            // For USB 3.0 SuperSpeed devices, skip potential
                            // USB 3.0 SuperSpeed Endpoint Companion descriptor
                        if (bufptr+2 <= devdesc + desclength &&
                            bufptr[0] == USB_DT_SS_EP_COMP_SIZE &&
                            bufptr[1] == USB_DT_SS_ENDPOINT_COMP) {
                            bufptr += USB_DT_SS_EP_COMP_SIZE;
                        }
                        ep2 = (struct usb_endpoint_descriptor *)bufptr;
                        bufptr += USB_DT_ENDPOINT_SIZE;
                        if (bufptr+2 <= devdesc + desclength &&
                            bufptr[0] == USB_DT_SS_EP_COMP_SIZE &&
                            bufptr[1] == USB_DT_SS_ENDPOINT_COMP) {
                            bufptr += USB_DT_SS_EP_COMP_SIZE;
                        }

                        if (bufptr > devdesc + desclength ||
                            ep1->bLength != USB_DT_ENDPOINT_SIZE ||
                            ep1->bDescriptorType != USB_DT_ENDPOINT ||
                            ep2->bLength != USB_DT_ENDPOINT_SIZE ||
                            ep2->bDescriptorType != USB_DT_ENDPOINT) {
                            D("endpoints not found");
                            break;
                        }

                            // both endpoints should be bulk
                        if (ep1->bmAttributes != USB_ENDPOINT_XFER_BULK ||
                            ep2->bmAttributes != USB_ENDPOINT_XFER_BULK) {
                            D("bulk endpoints not found");
                            continue;
                        }
                            /* aproto 01 needs 0 termination */
                        if (interface->bInterfaceProtocol == ADB_PROTOCOL) {
                            max_packet_size = ep1->wMaxPacketSize;
                            zero_mask = ep1->wMaxPacketSize - 1;
                        }

                            // we have a match.  now we just need to figure out which is in and which is out.
                        unsigned char local_ep_in, local_ep_out;
                        if (ep1->bEndpointAddress & USB_ENDPOINT_DIR_MASK) {
                            local_ep_in = ep1->bEndpointAddress;
                            local_ep_out = ep2->bEndpointAddress;
                        } else {
                            local_ep_in = ep2->bEndpointAddress;
                            local_ep_out = ep1->bEndpointAddress;
                        }

                            // Determine the device path
                        if (!fstat(fd, &st) && S_ISCHR(st.st_mode)) {
                            snprintf(pathbuf, sizeof(pathbuf), "/sys/dev/char/%d:%d",
                                     major(st.st_rdev), minor(st.st_rdev));
                            ssize_t link_len = readlink(pathbuf, link, sizeof(link) - 1);
                            if (link_len > 0) {
                                link[link_len] = '\0';
                                const char* slash = strrchr(link, '/');
                                if (slash) {
                                    snprintf(pathbuf, sizeof(pathbuf),
                                             "usb:%s", slash + 1);
                                    devpath = pathbuf;
                                }
                            }
                        }

                        register_device_callback(dev_name.c_str(), devpath, local_ep_in,
                                                 local_ep_out, interface->bInterfaceNumber,
                                                 device->iSerialNumber, zero_mask, max_packet_size);
                        break;
                    }
                } else {
                    bufptr += length;
                }
            } // end of while

            unix_close(fd);
        }
    }
}

static int usb_bulk_write(usb_handle* h, const void* data, int len) {
    std::unique_lock<std::mutex> lock(h->mutex);
    D("++ usb_bulk_write ++");

    usbdevfs_urb* urb = &h->urb_out;
    memset(urb, 0, sizeof(*urb));
    urb->type = USBDEVFS_URB_TYPE_BULK;
    urb->endpoint = h->ep_out;
    urb->status = -1;
    urb->buffer = const_cast<void*>(data);
    urb->buffer_length = len;

    if (h->dead) {
        errno = EINVAL;
        return -1;
    }

    if (TEMP_FAILURE_RETRY(ioctl(h->fd, USBDEVFS_SUBMITURB, urb)) == -1) {
        return -1;
    }

    h->urb_out_busy = true;
    while (true) {
        auto now = std::chrono::system_clock::now();
        if (h->cv.wait_until(lock, now + 5s) == std::cv_status::timeout || h->dead) {
            // TODO: call USBDEVFS_DISCARDURB?
            errno = ETIMEDOUT;
            return -1;
        }
        if (!h->urb_out_busy) {
            if (urb->status != 0) {
                errno = -urb->status;
                return -1;
            }
            return urb->actual_length;
        }
    }
}

static int usb_bulk_read(usb_handle* h, void* data, int len) {
    std::unique_lock<std::mutex> lock(h->mutex);
    D("++ usb_bulk_read ++");

    usbdevfs_urb* urb = &h->urb_in;
    memset(urb, 0, sizeof(*urb));
    urb->type = USBDEVFS_URB_TYPE_BULK;
    urb->endpoint = h->ep_in;
    urb->status = -1;
    urb->buffer = data;
    urb->buffer_length = len;

    if (h->dead) {
        errno = EINVAL;
        return -1;
    }

    if (TEMP_FAILURE_RETRY(ioctl(h->fd, USBDEVFS_SUBMITURB, urb)) == -1) {
        return -1;
    }

    h->urb_in_busy = true;
    while (true) {
        D("[ reap urb - wait ]");
        h->reaper_thread = pthread_self();
        int fd = h->fd;
        lock.unlock();

        // This ioctl must not have TEMP_FAILURE_RETRY because we send SIGALRM to break out.
        usbdevfs_urb* out = nullptr;
        int res = ioctl(fd, USBDEVFS_REAPURB, &out);
        int saved_errno = errno;

        lock.lock();
        h->reaper_thread = 0;
        if (h->dead) {
            errno = EINVAL;
            return -1;
        }
        if (res < 0) {
            if (saved_errno == EINTR) {
                continue;
            }
            D("[ reap urb - error ]");
            errno = saved_errno;
            return -1;
        }
        D("[ urb @%p status = %d, actual = %d ]", out, out->status, out->actual_length);

        if (out == &h->urb_in) {
            D("[ reap urb - IN complete ]");
            h->urb_in_busy = false;
            if (urb->status != 0) {
                errno = -urb->status;
                return -1;
            }
            return urb->actual_length;
        }
        if (out == &h->urb_out) {
            D("[ reap urb - OUT compelete ]");
            h->urb_out_busy = false;
            h->cv.notify_all();
        }
    }
}

int usb_write(usb_handle *h, const void *_data, int len)
{
    D("++ usb_write ++");

    unsigned char *data = (unsigned char*) _data;
    int n = usb_bulk_write(h, data, len);
    if (n != len) {
        D("ERROR: n = %d, errno = %d (%s)", n, errno, strerror(errno));
        return -1;
    }

    if (h->zero_mask && !(len & h->zero_mask)) {
        // If we need 0-markers and our transfer is an even multiple of the packet size,
        // then send a zero marker.
        return usb_bulk_write(h, _data, 0) == 0 ? n : -1;
    }

    D("-- usb_write --");
    return n;
}

int usb_read(usb_handle *h, void *_data, int len)
{
    unsigned char *data = (unsigned char*) _data;
    int n;

    D("++ usb_read ++");
    int orig_len = len;
    while (len == orig_len) {
        int xfer = len;

        D("[ usb read %d fd = %d], path=%s", xfer, h->fd, h->path.c_str());
        n = usb_bulk_read(h, data, xfer);
        D("[ usb read %d ] = %d, path=%s", xfer, n, h->path.c_str());
        if (n <= 0) {
            if((errno == ETIMEDOUT) && (h->fd != -1)) {
                D("[ timeout ]");
                continue;
            }
            D("ERROR: n = %d, errno = %d (%s)",
                n, errno, strerror(errno));
            return -1;
        }

        len -= n;
        data += n;
    }

    D("-- usb_read --");
    return orig_len - len;
}

void usb_kick(usb_handle* h) {
    std::lock_guard<std::mutex> lock(h->mutex);
    D("[ kicking %p (fd = %d) ]", h, h->fd);
    if (!h->dead) {
        h->dead = true;

        if (h->writeable) {
            /* HACK ALERT!
            ** Sometimes we get stuck in ioctl(USBDEVFS_REAPURB).
            ** This is a workaround for that problem.
            */
            if (h->reaper_thread) {
                pthread_kill(h->reaper_thread, SIGALRM);
            }

            /* cancel any pending transactions
            ** these will quietly fail if the txns are not active,
            ** but this ensures that a reader blocked on REAPURB
            ** will get unblocked
            */
            ioctl(h->fd, USBDEVFS_DISCARDURB, &h->urb_in);
            ioctl(h->fd, USBDEVFS_DISCARDURB, &h->urb_out);
            h->urb_in.status = -ENODEV;
            h->urb_out.status = -ENODEV;
            h->urb_in_busy = false;
            h->urb_out_busy = false;
            h->cv.notify_all();
        } else {
            unregister_usb_transport(h);
        }
    }
}

int usb_close(usb_handle* h) {
    std::lock_guard<std::mutex> lock(g_usb_handles_mutex);
    g_usb_handles.remove(h);

    D("-- usb close %p (fd = %d) --", h, h->fd);

    delete h;

    return 0;
}

size_t usb_get_max_packet_size(usb_handle* h) {
    return h->max_packet_size;
}

static void register_device(const char* dev_name, const char* dev_path, unsigned char ep_in,
                            unsigned char ep_out, int interface, int serial_index,
                            unsigned zero_mask, size_t max_packet_size) {
    // Since Linux will not reassign the device ID (and dev_name) as long as the
    // device is open, we can add to the list here once we open it and remove
    // from the list when we're finally closed and everything will work out
    // fine.
    //
    // If we have a usb_handle on the list of handles with a matching name, we
    // have no further work to do.
    {
        std::lock_guard<std::mutex> lock(g_usb_handles_mutex);
        for (usb_handle* usb: g_usb_handles) {
            if (usb->path == dev_name) {
                return;
            }
        }
    }

    D("[ usb located new device %s (%d/%d/%d) ]", dev_name, ep_in, ep_out, interface);
    std::unique_ptr<usb_handle> usb(new usb_handle);
    usb->path = dev_name;
    usb->ep_in = ep_in;
    usb->ep_out = ep_out;
    usb->zero_mask = zero_mask;
    usb->max_packet_size = max_packet_size;

    // Initialize mark so we don't get garbage collected after the device scan.
    usb->mark = true;

    usb->fd = unix_open(usb->path.c_str(), O_RDWR | O_CLOEXEC);
    if (usb->fd == -1) {
        // Opening RW failed, so see if we have RO access.
        usb->fd = unix_open(usb->path.c_str(), O_RDONLY | O_CLOEXEC);
        if (usb->fd == -1) {
            D("[ usb open %s failed: %s]", usb->path.c_str(), strerror(errno));
            return;
        }
        usb->writeable = 0;
    }

    D("[ usb opened %s%s, fd=%d]",
      usb->path.c_str(), (usb->writeable ? "" : " (read-only)"), usb->fd);

    if (usb->writeable) {
        if (ioctl(usb->fd, USBDEVFS_CLAIMINTERFACE, &interface) != 0) {
            D("[ usb ioctl(%d, USBDEVFS_CLAIMINTERFACE) failed: %s]", usb->fd, strerror(errno));
            return;
        }
    }

    // Read the device's serial number.
    std::string serial_path = android::base::StringPrintf(
        "/sys/bus/usb/devices/%s/serial", dev_path + 4);
    std::string serial;
    if (!android::base::ReadFileToString(serial_path, &serial)) {
        D("[ usb read %s failed: %s ]", serial_path.c_str(), strerror(errno));
        // We don't actually want to treat an unknown serial as an error because
        // devices aren't able to communicate a serial number in early bringup.
        // http://b/20883914
        serial = "";
    }
    serial = android::base::Trim(serial);

    // Add to the end of the active handles.
    usb_handle* done_usb = usb.release();
    {
        std::lock_guard<std::mutex> lock(g_usb_handles_mutex);
        g_usb_handles.push_back(done_usb);
    }
    register_usb_transport(done_usb, serial.c_str(), dev_path, done_usb->writeable);
}

static void device_poll_thread() {
    adb_thread_setname("device poll");
    D("Created device thread");
    while (true) {
        // TODO: Use inotify.
        find_usb_device("/dev/bus/usb", register_device);
        kick_disconnected_devices();
        std::this_thread::sleep_for(1s);
    }
}

void usb_init() {
    struct sigaction actions;
    memset(&actions, 0, sizeof(actions));
    sigemptyset(&actions.sa_mask);
    actions.sa_flags = 0;
    actions.sa_handler = [](int) {};
    sigaction(SIGALRM, &actions, nullptr);

    std::thread(device_poll_thread).detach();
}

void usb_cleanup() {}

} // namespace native
