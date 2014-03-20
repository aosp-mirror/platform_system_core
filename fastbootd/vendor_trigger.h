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

#ifndef __VENDOR_TRIGGER_H_
#define __VENDOR_TRIGGER_H_

__BEGIN_DECLS

struct GPT_entry_raw;
struct GPT_content;

/*
 * Implemented in libvendortrigger to handle platform-specific behavior.
 */

/*
 * trigger_init() is called once at startup time before calling any other method
 *
 * returns 0 on success and nonzero on error
 */
int trigger_init(void);

/*
 * This function runs once after trigger_init completes.
 *
 * version is number parameter indicating version on the fastbootd side
 * libversion is version indicateing version of the library version
 *
 * returns 0 if it can cooperate with the current version and 1 in opposite
 */
int trigger_check_version(const int version, int *libversion);

/*
 * Return value -1 forbid the action from the vendor site and sets errno
 */
int trigger_gpt_layout(struct GPT_content *);
int trigger_oem_cmd(const char *arg, const char **response);

__END_DECLS

#endif
