/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <keyutils.h>

#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>

// keyctl(2) is deliberately not exposed. Callers should use the typed APIs instead.

key_serial_t add_key(const char* type, const char* description, const void* payload,
                     size_t payload_length, key_serial_t ring_id) {
  return syscall(__NR_add_key, type, description, payload, payload_length, ring_id);
}

key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create) {
  return syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, id, create);
}

long keyctl_revoke(key_serial_t id) {
  return syscall(__NR_keyctl, KEYCTL_REVOKE, id);
}

long keyctl_search(key_serial_t ring_id, const char* type, const char* description,
                   key_serial_t dest_ring_id) {
  return syscall(__NR_keyctl, KEYCTL_SEARCH, ring_id, type, description, dest_ring_id);
}

long keyctl_setperm(key_serial_t id, int permissions) {
  return syscall(__NR_keyctl, KEYCTL_SETPERM, id, permissions);
}

long keyctl_unlink(key_serial_t key, key_serial_t keyring) {
  return syscall(__NR_keyctl, KEYCTL_UNLINK, key, keyring);
}

long keyctl_restrict_keyring(key_serial_t keyring, const char* type, const char* restriction) {
  return syscall(__NR_keyctl, KEYCTL_RESTRICT_KEYRING, keyring, type, restriction);
}

long keyctl_get_security(key_serial_t id, char* buffer, size_t buflen) {
  return syscall(__NR_keyctl, KEYCTL_GET_SECURITY, id, buffer, buflen);
}
