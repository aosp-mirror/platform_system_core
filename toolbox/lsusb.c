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

#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <usbhost/usbhost.h>

static int verbose = 0;
static char str_buff[4096];

static const char *get_str(struct usb_device *dev, int id)
{
    char *str = usb_device_get_string(dev, id);

    if (id && str) {
        strlcpy(str_buff, str, sizeof(str_buff));
        free(str);
    } else {
        snprintf(str_buff, sizeof(str_buff), "%02x", id);
    }

    return str_buff;
}


static void lsusb_parse_device_descriptor(struct usb_device *dev,
                                          struct usb_device_descriptor *desc)
{
    printf("  Device Descriptor\n");
    printf("\tbcdUSB: %04x\n", letoh16(desc->bcdUSB));
    printf("\tbDeviceClass: %02x\n", desc->bDeviceClass);
    printf("\tbDeviceSubClass: %02x\n", desc->bDeviceSubClass);
    printf("\tbDeviceProtocol: %02x\n", desc->bDeviceProtocol);
    printf("\tbMaxPacketSize0: %02x\n", desc->bMaxPacketSize0);
    printf("\tidVendor: %04x\n", letoh16(desc->idVendor));
    printf("\tidProduct: %04x\n", letoh16(desc->idProduct));
    printf("\tbcdDevice: %04x\n", letoh16(desc->bcdDevice));
    printf("\tiManufacturer: %s\n", get_str(dev, desc->iManufacturer));
    printf("\tiProduct: %s\n", get_str(dev, desc->iProduct));
    printf("\tiSerialNumber: %s\n", get_str(dev,desc->iSerialNumber));
    printf("\tbNumConfiguration: %02x\n", desc->bNumConfigurations);
    printf("\n");
}

static void lsusb_parse_config_descriptor(struct usb_device *dev,
                                          struct usb_config_descriptor *desc)
{
    printf("  Config Descriptor\n");
    printf("\twTotalLength: %04x\n", letoh16(desc->wTotalLength));
    printf("\tbNumInterfaces: %02x\n", desc->bNumInterfaces);
    printf("\tbConfigurationValue: %02x\n", desc->bConfigurationValue);
    printf("\tiConfiguration: %s\n", get_str(dev, desc->iConfiguration));
    printf("\tbmAttributes: %02x\n", desc->bmAttributes);
    printf("\tbMaxPower: %d mA\n", desc->bMaxPower * 2);
    printf("\n");
}

static void lsusb_parse_interface_descriptor(struct usb_device *dev,
                                             struct usb_interface_descriptor *desc)
{
    printf("  Interface Descriptor\n");
    printf("\tbInterfaceNumber: %02x\n", desc->bInterfaceNumber);
    printf("\tbAlternateSetting: %02x\n", desc->bAlternateSetting);
    printf("\tbNumEndpoints: %02x\n", desc->bNumEndpoints);
    printf("\tbInterfaceClass: %02x\n", desc->bInterfaceClass);
    printf("\tbInterfaceSubClass: %02x\n", desc->bInterfaceSubClass);
    printf("\tbInterfaceProtocol: %02x\n", desc->bInterfaceProtocol);
    printf("\tiInterface: %s\n", get_str(dev, desc->iInterface));
    printf("\n");
}

static void lsusb_parse_endpoint_descriptor(struct usb_device *dev,
                                            struct usb_endpoint_descriptor *desc)
{
    printf("  Endpoint Descriptor\n");
    printf("\tbEndpointAddress: %02x\n", desc->bEndpointAddress);
    printf("\tbmAttributes: %02x\n", desc->bmAttributes);
    printf("\twMaxPacketSize: %02x\n", letoh16(desc->wMaxPacketSize));
    printf("\tbInterval: %02x\n", desc->bInterval);
    printf("\tbRefresh: %02x\n", desc->bRefresh);
    printf("\tbSynchAddress: %02x\n", desc->bSynchAddress);
    printf("\n");
}

static void lsusb_dump_descriptor(struct usb_device *dev,
                                  struct usb_descriptor_header *desc)
{
    int i;
    printf("  Descriptor type %02x\n", desc->bDescriptorType);

    for (i = 0; i < desc->bLength; i++ ) {
        if ((i % 16) == 0)
            printf("\t%02x:", i);
        printf(" %02x", ((uint8_t *)desc)[i]);
        if ((i % 16) == 15)
            printf("\n");
    }

    if ((i % 16) != 0)
        printf("\n");
    printf("\n");
}

static void lsusb_parse_descriptor(struct usb_device *dev,
                                   struct usb_descriptor_header *desc)
{
    switch (desc->bDescriptorType) {
    case USB_DT_DEVICE:
        lsusb_parse_device_descriptor(dev, (struct usb_device_descriptor *) desc);
        break;

    case USB_DT_CONFIG:
        lsusb_parse_config_descriptor(dev, (struct usb_config_descriptor *) desc);
        break;

    case USB_DT_INTERFACE:
        lsusb_parse_interface_descriptor(dev, (struct usb_interface_descriptor *) desc);
        break;

    case USB_DT_ENDPOINT:
        lsusb_parse_endpoint_descriptor(dev, (struct usb_endpoint_descriptor *) desc);
        break;

    default:
        lsusb_dump_descriptor(dev, desc);

        break;
    }
}

static int lsusb_device_added(const char *dev_name, void *client_data)
{
    struct usb_device *dev = usb_device_open(dev_name);

    if (!dev) {
        fprintf(stderr, "can't open device %s: %s\n", dev_name, strerror(errno));
        return 0;
    }

    if (verbose) {
        struct usb_descriptor_iter iter;
        struct usb_descriptor_header *desc;

        printf("%s:\n", dev_name);

        usb_descriptor_iter_init(dev, &iter);

        while ((desc = usb_descriptor_iter_next(&iter)) != NULL)
            lsusb_parse_descriptor(dev, desc);

    } else {
        uint16_t vid, pid;
        char *mfg_name, *product_name, *serial;

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
    }

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
    struct usb_host_context *ctx;

    if (argc == 2 && !strcmp(argv[1], "-v"))
        verbose = 1;

    ctx = usb_host_init();
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

