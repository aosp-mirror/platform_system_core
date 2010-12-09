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

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <usbhost/usbhost.h>

static int lsusb_device_added(const char *dev_name, void *client_data)
{
    struct usb_device *dev = usb_device_open(dev_name);
    uint16_t vid, pid;
    char *mfg_name, *product_name, *serial;

    if (!dev) {
        fprintf(stderr, "can't open device %s: %s\n", dev_name, strerror(errno));
        return 0;
    }

    vid = usb_device_get_vendor_id(dev);
    pid = usb_device_get_product_id(dev);
    mfg_name = usb_device_get_manufacturer_name(dev);
    product_name = usb_device_get_product_name(dev);
    serial = usb_device_get_serial(dev);

    printf("%s: %04x:%04x %s %s %s\n", dev_name, vid, pid,
           mfg_name, product_name, serial);

    free(mfg_name);
    free(product_name);
    free(serial);

    usb_device_close(dev);

    return 0;
}

static int lsusb_device_removed(const char *dev_name, void *client_data)
{
    return 0;
}


static int lsusb_discovery_done(void *client_data)
{
    return 1;
}



int lsusb_main(int argc, char **argv)
{
    struct usb_host_context *ctx = usb_host_init();
    if (!ctx) {
        perror("usb_host_init:");
        return 1;
    }

    usb_host_run(ctx,
                 lsusb_device_added,
                 lsusb_device_removed,
                 lsusb_discovery_done,
                 NULL);

    usb_host_cleanup(ctx);

    return 0;
}

