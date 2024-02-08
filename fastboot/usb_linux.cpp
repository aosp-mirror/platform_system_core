/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/usbdevice_fs.h>
#include <linux/version.h>
#include <linux/usb/ch9.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <chrono>
#include <memory>
#include <thread>

#include "usb.h"
#include "util.h"

using namespace std::chrono_literals;

#define MAX_RETRIES 2

/* Timeout in seconds for usb_wait_for_disconnect.
 * It doesn't usually take long for a device to disconnect (almost always
 * under 2 seconds) but we'll time out after 3 seconds just in case.
 */
#define WAIT_FOR_DISCONNECT_TIMEOUT  3

#ifdef TRACE_USB
#define DBG1(x...) fprintf(stderr, x)
#define DBG(x...) fprintf(stderr, x)
#else
#define DBG(x...)
#define DBG1(x...)
#endif

// Kernels before 3.3 have a 16KiB transfer limit. That limit was replaced
// with a 16MiB global limit in 3.3, but each URB submitted required a
// contiguous kernel allocation, so you would get ENOMEM if you tried to
// send something larger than the biggest available contiguous kernel
// memory region. 256KiB contiguous allocations are generally not reliable
// on a device kernel that has been running for a while fragmenting its
// memory, but that shouldn't be a problem for fastboot on the host.
// In 3.6, the contiguous buffer limit was removed by allocating multiple
// 16KiB chunks and having the USB driver stitch them back together while
// transmitting using a scatter-gather list, so 256KiB bulk transfers should
// be reliable.
// 256KiB seems to work, but 1MiB bulk transfers lock up my z620 with a 3.13
// kernel.
#define MAX_USBFS_BULK_SIZE (16 * 1024)

struct usb_handle
{
    char fname[64];
    int desc;
    unsigned char ep_in;
    unsigned char ep_out;
};

class LinuxUsbTransport : public UsbTransport {
  public:
    explicit LinuxUsbTransport(std::unique_ptr<usb_handle> handle, uint32_t ms_timeout = 0)
        : handle_(std::move(handle)), ms_timeout_(ms_timeout) {}
    ~LinuxUsbTransport() override;

    ssize_t Read(void* data, size_t len) override;
    ssize_t Write(const void* data, size_t len) override;
    int Close() override;
    int Reset() override;
    int WaitForDisconnect() override;

  private:
    std::unique_ptr<usb_handle> handle_;
    const uint32_t ms_timeout_;

    DISALLOW_COPY_AND_ASSIGN(LinuxUsbTransport);
};

/* True if name isn't a valid name for a USB device in /sys/bus/usb/devices.
 * Device names are made up of numbers, dots, and dashes, e.g., '7-1.5'.
 * We reject interfaces (e.g., '7-1.5:1.0') and host controllers (e.g. 'usb1').
 * The name must also start with a digit, to disallow '.' and '..'
 */
static inline int badname(const char *name)
{
    if (!isdigit(*name))
      return 1;
    while(*++name) {
        if(!isdigit(*name) && *name != '.' && *name != '-')
            return 1;
    }
    return 0;
}

static int check(void *_desc, int len, unsigned type, int size)
{
    struct usb_descriptor_header *hdr = (struct usb_descriptor_header *)_desc;

    if(len < size) return -1;
    if(hdr->bLength < size) return -1;
    if(hdr->bLength > len) return -1;
    if(hdr->bDescriptorType != type) return -1;

    return 0;
}

static int filter_usb_device(char* sysfs_name,
                             char *ptr, int len, int writable,
                             ifc_match_func callback,
                             int *ept_in_id, int *ept_out_id, int *ifc_id)
{
    struct usb_device_descriptor *dev;
    struct usb_config_descriptor *cfg;
    struct usb_interface_descriptor *ifc;
    struct usb_endpoint_descriptor *ept;
    struct usb_ifc_info info;

    int in, out;
    unsigned i;
    unsigned e;

    if (check(ptr, len, USB_DT_DEVICE, USB_DT_DEVICE_SIZE))
        return -1;
    dev = (struct usb_device_descriptor *)ptr;
    len -= dev->bLength;
    ptr += dev->bLength;

    if (check(ptr, len, USB_DT_CONFIG, USB_DT_CONFIG_SIZE))
        return -1;
    cfg = (struct usb_config_descriptor *)ptr;
    len -= cfg->bLength;
    ptr += cfg->bLength;

    info.dev_vendor = dev->idVendor;
    info.dev_product = dev->idProduct;
    info.dev_class = dev->bDeviceClass;
    info.dev_subclass = dev->bDeviceSubClass;
    info.dev_protocol = dev->bDeviceProtocol;
    info.writable = writable;

    snprintf(info.device_path, sizeof(info.device_path), "usb:%s", sysfs_name);

    /* Read device serial number (if there is one).
     * We read the serial number from sysfs, since it's faster and more
     * reliable than issuing a control pipe read, and also won't
     * cause problems for devices which don't like getting descriptor
     * requests while they're in the middle of flashing.
     */
    info.serial_number[0] = '\0';
    if (dev->iSerialNumber) {
        char path[80];
        int fd;

        snprintf(path, sizeof(path),
                 "/sys/bus/usb/devices/%s/serial", sysfs_name);
        path[sizeof(path) - 1] = '\0';

        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            int chars_read = read(fd, info.serial_number,
                                  sizeof(info.serial_number) - 1);
            close(fd);

            if (chars_read <= 0)
                info.serial_number[0] = '\0';
            else if (info.serial_number[chars_read - 1] == '\n') {
                // strip trailing newline
                info.serial_number[chars_read - 1] = '\0';
            }
        }
    }

    for(i = 0; i < cfg->bNumInterfaces; i++) {

        while (len > 0) {
	        struct usb_descriptor_header *hdr = (struct usb_descriptor_header *)ptr;
            if (check(hdr, len, USB_DT_INTERFACE, USB_DT_INTERFACE_SIZE) == 0)
                break;
            len -= hdr->bLength;
            ptr += hdr->bLength;
        }

        if (len <= 0)
            return -1;

        ifc = (struct usb_interface_descriptor *)ptr;
        len -= ifc->bLength;
        ptr += ifc->bLength;

        in = -1;
        out = -1;
        info.ifc_class = ifc->bInterfaceClass;
        info.ifc_subclass = ifc->bInterfaceSubClass;
        info.ifc_protocol = ifc->bInterfaceProtocol;

        for(e = 0; e < ifc->bNumEndpoints; e++) {
            while (len > 0) {
	            struct usb_descriptor_header *hdr = (struct usb_descriptor_header *)ptr;
                if (check(hdr, len, USB_DT_ENDPOINT, USB_DT_ENDPOINT_SIZE) == 0)
                    break;
                len -= hdr->bLength;
                ptr += hdr->bLength;
            }
            if (len < 0) {
                break;
            }

            ept = (struct usb_endpoint_descriptor *)ptr;
            len -= ept->bLength;
            ptr += ept->bLength;

            if((ept->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) != USB_ENDPOINT_XFER_BULK)
                continue;

            if(ept->bEndpointAddress & USB_ENDPOINT_DIR_MASK) {
                in = ept->bEndpointAddress;
            } else {
                out = ept->bEndpointAddress;
            }

            // For USB 3.0 devices skip the SS Endpoint Companion descriptor
            if (check((struct usb_descriptor_hdr *)ptr, len,
                      USB_DT_SS_ENDPOINT_COMP, USB_DT_SS_EP_COMP_SIZE) == 0) {
                len -= USB_DT_SS_EP_COMP_SIZE;
                ptr += USB_DT_SS_EP_COMP_SIZE;
            }
        }

        info.has_bulk_in = (in != -1);
        info.has_bulk_out = (out != -1);

        std::string interface;
        auto path = android::base::StringPrintf("/sys/bus/usb/devices/%s/%s:1.%d/interface",
                                                sysfs_name, sysfs_name, ifc->bInterfaceNumber);
        if (android::base::ReadFileToString(path, &interface)) {
            snprintf(info.interface, sizeof(info.interface), "%s", interface.c_str());
        }

        if(callback(&info) == 0) {
            *ept_in_id = in;
            *ept_out_id = out;
            *ifc_id = ifc->bInterfaceNumber;
            return 0;
        }
    }

    return -1;
}

static int read_sysfs_string(const char *sysfs_name, const char *sysfs_node,
                             char* buf, int bufsize)
{
    char path[80];
    int fd, n;

    snprintf(path, sizeof(path),
             "/sys/bus/usb/devices/%s/%s", sysfs_name, sysfs_node);
    path[sizeof(path) - 1] = '\0';

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    n = read(fd, buf, bufsize - 1);
    close(fd);

    if (n < 0)
        return -1;

    buf[n] = '\0';

    return n;
}

static int read_sysfs_number(const char *sysfs_name, const char *sysfs_node)
{
    char buf[16];
    int value;

    if (read_sysfs_string(sysfs_name, sysfs_node, buf, sizeof(buf)) < 0)
        return -1;

    if (sscanf(buf, "%d", &value) != 1)
        return -1;

    return value;
}

/* Given the name of a USB device in sysfs, get the name for the same
 * device in devfs. Returns 0 for success, -1 for failure.
 */
static int convert_to_devfs_name(const char* sysfs_name,
                                 char* devname, int devname_size)
{
    int busnum, devnum;

    busnum = read_sysfs_number(sysfs_name, "busnum");
    if (busnum < 0)
        return -1;

    devnum = read_sysfs_number(sysfs_name, "devnum");
    if (devnum < 0)
        return -1;

    snprintf(devname, devname_size, "/dev/bus/usb/%03d/%03d", busnum, devnum);
    return 0;
}

static std::unique_ptr<usb_handle> find_usb_device(const char* base, ifc_match_func callback)
{
    std::unique_ptr<usb_handle> usb;
    char devname[64];
    char desc[1024];
    int n, in, out, ifc;

    struct dirent *de;
    int fd;
    int writable;

    std::unique_ptr<DIR, decltype(&closedir)> busdir(opendir(base), closedir);
    if (busdir == 0) return 0;

    while ((de = readdir(busdir.get())) && (usb == nullptr)) {
        if (badname(de->d_name)) continue;

        if (!convert_to_devfs_name(de->d_name, devname, sizeof(devname))) {

//            DBG("[ scanning %s ]\n", devname);
            writable = 1;
            if ((fd = open(devname, O_RDWR)) < 0) {
                // Check if we have read-only access, so we can give a helpful
                // diagnostic like "adb devices" does.
                writable = 0;
                if ((fd = open(devname, O_RDONLY)) < 0) {
                    continue;
                }
            }

            n = read(fd, desc, sizeof(desc));

            if (filter_usb_device(de->d_name, desc, n, writable, callback, &in, &out, &ifc) == 0) {
                usb.reset(new usb_handle());
                strcpy(usb->fname, devname);
                usb->ep_in = in;
                usb->ep_out = out;
                usb->desc = fd;

                n = ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifc);
                if (n != 0) {
                    close(fd);
                    usb.reset();
                    continue;
                }
            } else {
                close(fd);
            }
        }
    }

    return usb;
}

LinuxUsbTransport::~LinuxUsbTransport() {
    Close();
}

ssize_t LinuxUsbTransport::Write(const void* _data, size_t len)
{
    unsigned char *data = (unsigned char*) _data;
    unsigned count = 0;
    struct usbdevfs_urb urb[2] = {};
    bool pending[2] = {};

    if (handle_->ep_out == 0 || handle_->desc == -1) {
        return -1;
    }

    auto submit_urb = [&](size_t i) {
        int xfer = (len > MAX_USBFS_BULK_SIZE) ? MAX_USBFS_BULK_SIZE : len;

        urb[i].type = USBDEVFS_URB_TYPE_BULK;
        urb[i].endpoint = handle_->ep_out;
        urb[i].buffer_length = xfer;
        urb[i].buffer = data;
        urb[i].usercontext = (void *)i;

        int n = ioctl(handle_->desc, USBDEVFS_SUBMITURB, &urb[i]);
        if (n != 0) {
            DBG("ioctl(USBDEVFS_SUBMITURB) failed\n");
            return false;
        }

        pending[i] = true;
        count += xfer;
        len -= xfer;
        data += xfer;

        return true;
    };

    auto reap_urb = [&](size_t i) {
        while (pending[i]) {
            struct usbdevfs_urb *urbp;
            int res = ioctl(handle_->desc, USBDEVFS_REAPURB, &urbp);
            if (res != 0) {
                DBG("ioctl(USBDEVFS_REAPURB) failed\n");
                return false;
            }
            size_t done = (size_t)urbp->usercontext;
            if (done >= 2 || !pending[done]) {
                DBG("unexpected urb\n");
                return false;
            }
            if (urbp->status != 0 || urbp->actual_length != urbp->buffer_length) {
                DBG("urb returned error\n");
                return false;
            }
            pending[done] = false;
        }
        return true;
    };

    if (!submit_urb(0)) {
        return -1;
    }
    while (len > 0) {
        if (!submit_urb(1)) {
            return -1;
        }
        if (!reap_urb(0)) {
            return -1;
        }
        if (len <= 0) {
            if (!reap_urb(1)) {
                return -1;
            }
            return count;
        }
        if (!submit_urb(0)) {
            return -1;
        }
        if (!reap_urb(1)) {
            return -1;
        }
    }
    if (!reap_urb(0)) {
        return -1;
    }
    return count;
}

ssize_t LinuxUsbTransport::Read(void* _data, size_t len)
{
    unsigned char *data = (unsigned char*) _data;
    unsigned count = 0;
    struct usbdevfs_bulktransfer bulk;
    int n, retry;

    if (handle_->ep_in == 0 || handle_->desc == -1) {
        return -1;
    }

    while (len > 0) {
        int xfer = (len > MAX_USBFS_BULK_SIZE) ? MAX_USBFS_BULK_SIZE : len;

        bulk.ep = handle_->ep_in;
        bulk.len = xfer;
        bulk.data = data;
        bulk.timeout = ms_timeout_;
        retry = 0;

        do {
            DBG("[ usb read %d fd = %d], fname=%s\n", xfer, handle_->desc, handle_->fname);
            n = ioctl(handle_->desc, USBDEVFS_BULK, &bulk);
            DBG("[ usb read %d ] = %d, fname=%s, Retry %d \n", xfer, n, handle_->fname, retry);

            if (n < 0) {
                DBG1("ERROR: n = %d, errno = %d (%s)\n",n, errno, strerror(errno));
                if (++retry > MAX_RETRIES) return -1;
                std::this_thread::sleep_for(100ms);
            }
        } while (n < 0);

        count += n;
        len -= n;
        data += n;

        if(n < xfer) {
            break;
        }
    }

    return count;
}

int LinuxUsbTransport::Close()
{
    int fd;

    fd = handle_->desc;
    handle_->desc = -1;
    if(fd >= 0) {
        close(fd);
        DBG("[ usb closed %d ]\n", fd);
    }

    return 0;
}

int LinuxUsbTransport::Reset() {
    int ret = 0;
    // We reset the USB connection
    if ((ret = ioctl(handle_->desc, USBDEVFS_RESET, 0))) {
        return ret;
    }

    return 0;
}

std::unique_ptr<UsbTransport> usb_open(ifc_match_func callback, uint32_t timeout_ms) {
    std::unique_ptr<UsbTransport> result;
    std::unique_ptr<usb_handle> handle = find_usb_device("/sys/bus/usb/devices", callback);

    if (handle) {
        result = std::make_unique<LinuxUsbTransport>(std::move(handle), timeout_ms);
    }

    return result;
}

/* Wait for the system to notice the device is gone, so that a subsequent
 * fastboot command won't try to access the device before it's rebooted.
 * Returns 0 for success, -1 for timeout.
 */
int LinuxUsbTransport::WaitForDisconnect()
{
  double deadline = now() + WAIT_FOR_DISCONNECT_TIMEOUT;
  while (now() < deadline) {
    if (access(handle_->fname, F_OK)) return 0;
    std::this_thread::sleep_for(50ms);
  }
  return -1;
}
