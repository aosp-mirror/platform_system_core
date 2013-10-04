/*
 * Copyright (c) 2009-2013, Google Inc.
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
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
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

#include <stdlib.h>

#include "vendor_trigger.h"
#include "debug.h"

unsigned int debug_level = DEBUG;

static const int version = 1;

int check_version(const int fastboot_version, int *libversion) {
    *libversion = version;
    return !(fastboot_version == version);
}

int gpt_layout(struct GPT_content *table) {
    D(DEBUG, "message from libvendor");
    return 0;
}

int oem_cmd(const char *arg, const char **response) {
    D(DEBUG, "message from libvendor, oem catched request %s", arg);
    return 0;
}

static int close_triggers(struct vendor_trigger_t *dev)
{
    if (dev)
        free(dev);

    return 0;
}

static int open_triggers(const struct hw_module_t *module, char const *name,
                         struct hw_device_t **device) {
    struct vendor_trigger_t *dev = malloc(sizeof(struct vendor_trigger_t));
    klog_init();
    klog_set_level(6);

    memset(dev, 0, sizeof(*dev));
    dev->common.module = (struct hw_module_t *) module;
    dev->common.close  = (int (*)(struct hw_device_t *)) close_triggers;

    dev->gpt_layout = gpt_layout;
    dev->oem_cmd = oem_cmd;

    *device = (struct hw_device_t *) dev;

    return 0;
}


static struct hw_module_methods_t trigger_module_methods = {
    .open = open_triggers,
};

struct hw_module_t HAL_MODULE_INFO_SYM = {
    .tag = HARDWARE_MODULE_TAG,
    .version_major = 1,
    .version_minor = 0,
    .id = TRIGGER_MODULE_ID,
    .name = "vendor trigger library for fastbootd",
    .author = "Google, Inc.",
    .methods = &trigger_module_methods,
};

