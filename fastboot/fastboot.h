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

#ifndef _FASTBOOT_H_
#define _FASTBOOT_H_

#include "usb.h"

/* protocol.c - fastboot protocol */
int fb_command(usb_handle *usb, const char *cmd);
int fb_command_response(usb_handle *usb, const char *cmd, char *response);
int fb_download_data(usb_handle *usb, const void *data, unsigned size);
char *fb_get_error(void);

#define FB_COMMAND_SZ 64
#define FB_RESPONSE_SZ 64

/* engine.c - high level command queue engine */
void fb_queue_flash(const char *ptn, void *data, unsigned sz);;
void fb_queue_erase(const char *ptn);
void fb_queue_require(const char *prod, const char *var, int invert,
        unsigned nvalues, const char **value);
void fb_queue_display(const char *var, const char *prettyname);
void fb_queue_query_save(const char *var, char *dest, unsigned dest_size);
void fb_queue_reboot(void);
void fb_queue_command(const char *cmd, const char *msg);
void fb_queue_download(const char *name, void *data, unsigned size);
void fb_queue_notice(const char *notice);
int fb_execute_queue(usb_handle *usb);

/* util stuff */
void die(const char *fmt, ...);

/* Current product */
extern char cur_product[FB_RESPONSE_SZ + 1];

#endif
