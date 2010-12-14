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

#ifndef __USB_HOST_H
#define __USB_HOST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#include <linux/usb/ch9.h>
#else
#include <linux/usb_ch9.h>
#endif

struct usb_host_context;
struct usb_endpoint_descriptor;

struct usb_descriptor_iter {
    unsigned char*  config;
    unsigned char*  config_end;
    unsigned char*  curr_desc;
};

/* Callback for notification when new USB devices are attached.
 * Return true to exit from usb_host_run.
 */
typedef int (* usb_device_added_cb)(const char *dev_name, void *client_data);

/* Callback for notification when USB devices are removed.
 * Return true to exit from usb_host_run.
 */
typedef int (* usb_device_removed_cb)(const char *dev_name, void *client_data);

/* Callback indicating that initial device discovery is done.
 * Return true to exit from usb_host_run.
 */
typedef int (* usb_discovery_done_cb)(void *client_data);

/* Call this to initialize the USB host library. */
struct usb_host_context *usb_host_init(void);

/* Call this to cleanup the USB host library. */
void usb_host_cleanup(struct usb_host_context *context);

/* Call this to monitor the USB bus for new and removed devices.
 * This is intended to be called from a dedicated thread,
 * as it will not return until one of the callbacks returns true.
 * added_cb will be called immediately for each existing USB device,
 * and subsequently each time a new device is added.
 * removed_cb is called when USB devices are removed from the bus.
 * discovery_done_cb is called after the initial discovery of already
 * connected devices is complete.
 */
void usb_host_run(struct usb_host_context *context,
                  usb_device_added_cb added_cb,
                  usb_device_removed_cb removed_cb,
                  usb_discovery_done_cb discovery_done_cb,
                  void *client_data);

/* Creates a usb_device object for a USB device */
struct usb_device *usb_device_open(const char *dev_name);

/* Releases all resources associated with the USB device */
void usb_device_close(struct usb_device *device);

/* Creates a usb_device object for already open USB device.
 * This is intended to facilitate sharing USB devices across address spaces.
 */
struct usb_device *usb_device_new(const char *dev_name, int fd);

/* Returns the file descriptor for the usb_device.  Used in conjunction with
 * usb_device_new() for sharing USB devices across address spaces.
 */
int usb_device_get_fd(struct usb_device *device);

/* Returns the name for the USB device, which is the same as
 * the dev_name passed to usb_device_open()
 */
const char* usb_device_get_name(struct usb_device *device);

/* Returns a unique ID for the device.  Currently this is generated from the
 * dev_name path.
 */
int usb_device_get_unique_id(struct usb_device *device);

int usb_device_get_unique_id_from_name(const char* name);

/* Returns the USB vendor ID from the device descriptor for the USB device */
uint16_t usb_device_get_vendor_id(struct usb_device *device);

/* Returns the USB product ID from the device descriptor for the USB device */
uint16_t usb_device_get_product_id(struct usb_device *device);

/* Sends a control message to the specified device on endpoint zero */
int usb_device_send_control(struct usb_device *device,
                            int requestType,
                            int request,
                            int value,
                            int index,
                            int length,
                            void* buffer);

/* Returns a USB descriptor string for the given string ID.
 * Used to implement usb_device_get_manufacturer_name,
 * usb_device_get_product_name and usb_device_get_serial.
 * Call free() to free the result when you are done with it.
 */
char* usb_device_get_string(struct usb_device *device, int id);

/* Returns the manufacturer name for the USB device.
 * Call free() to free the result when you are done with it.
 */
char* usb_device_get_manufacturer_name(struct usb_device *device);

/* Returns the product name for the USB device.
 * Call free() to free the result when you are done with it.
 */
char* usb_device_get_product_name(struct usb_device *device);

/* Returns the USB serial number for the USB device.
 * Call free() to free the result when you are done with it.
 */
char* usb_device_get_serial(struct usb_device *device);

/* Returns true if we have write access to the USB device,
 * and false if we only have access to the USB device configuration.
 */
int usb_device_is_writeable(struct usb_device *device);

/* Initializes a usb_descriptor_iter, which can be used to iterate through all
 * the USB descriptors for a USB device.
 */
void usb_descriptor_iter_init(struct usb_device *device, struct usb_descriptor_iter *iter);

/* Returns the next USB descriptor for a device, or NULL if we have reached the
 * end of the list.
 */
struct usb_descriptor_header *usb_descriptor_iter_next(struct usb_descriptor_iter *iter);

/* Claims the specified interface of a USB device */
int usb_device_claim_interface(struct usb_device *device, unsigned int interface);

/* Releases the specified interface of a USB device */
int usb_device_release_interface(struct usb_device *device, unsigned int interface);


/* Creates a new usb_endpoint for the specified endpoint of a USB device.
 * This can be used to read or write data across the endpoint.
 */
struct usb_endpoint *usb_endpoint_open(struct usb_device *dev,
                const struct usb_endpoint_descriptor *desc);

/* Releases all resources associated with the endpoint */
void usb_endpoint_close(struct usb_endpoint *ep);

/* Begins a read or write operation on the specified endpoint */
int usb_endpoint_queue(struct usb_endpoint *ep, void *data, int len);

 /* Waits for the results of a previous usb_endpoint_queue operation on the
  * specified endpoint.  Returns number of bytes transferred, or a negative
  * value for error.
  */
int usb_endpoint_wait(struct usb_device *device, int *out_ep_num);

/* Cancels a pending usb_endpoint_queue() operation on an endpoint. */
int usb_endpoint_cancel(struct usb_endpoint *ep);

/* Returns the usb_device for the given endpoint */
struct usb_device *usb_endpoint_get_device(struct usb_endpoint *ep);

/* Returns the endpoint address for the given endpoint */
int usb_endpoint_number(struct usb_endpoint *ep);

/* Returns the maximum packet size for the given endpoint.
 * For bulk endpoints this should be 512 for highspeed or 64 for fullspeed.
 */
int usb_endpoint_max_packet(struct usb_endpoint *ep);

#ifdef __cplusplus
}
#endif
#endif /* __USB_HOST_H */
