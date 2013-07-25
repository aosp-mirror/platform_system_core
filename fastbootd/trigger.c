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

#include <dlfcn.h>

#include <hardware/hardware.h>
#include "debug.h"
#include "trigger.h"
#include "protocol.h"
#include "vendor_trigger.h"

static const int version = 1;

static struct vendor_trigger_t *triggers = NULL;

int load_trigger() {
    int err;
    hw_module_t* module;
    hw_device_t* device;
    int libversion;

    err = hw_get_module(TRIGGER_MODULE_ID, (hw_module_t const**)&module);

    if (err == 0) {
        err = module->methods->open(module, NULL, &device);

        if (err == 0) {
            triggers = (struct vendor_trigger_t *) device;
        } else {
            D(WARN, "Libvendor load error");
            return 1;
        }
    }
    else {
        D(WARN, "Libvendor not load: %s", strerror(-err));
        return 0;
    }

    if (triggers->check_version != NULL &&
        triggers->check_version(version, &libversion)) {

        triggers = NULL;
        D(ERR, "Library report incompability");
        return 1;
    }
    D(INFO, "libvendortrigger loaded");

    return 0;
}

int trigger_oem_cmd(const char *arg, const char **response) {
    if (triggers != NULL && triggers->oem_cmd != NULL)
        return triggers->oem_cmd(arg, response);
    return 0;
}

int trigger_gpt_layout(struct GPT_content *table) {
    if (triggers != NULL && triggers->gpt_layout != NULL)
        return triggers->gpt_layout(table);
    return 0;
}

