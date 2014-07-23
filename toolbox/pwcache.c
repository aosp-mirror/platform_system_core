/*
 * Copyright (C) 2014, The Android Open Source Project
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

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>

int uid_from_user(const char* name, uid_t* uid) {
  struct passwd* pw = getpwnam(name);
  if (pw == NULL) {
    return -1;
  }
  *uid = pw->pw_uid;
  return 0;
}

char* group_from_gid(gid_t gid, int noname) {
  struct group* g = getgrgid(gid);
  if (g == NULL) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "%lu", (long) gid);
    return noname ? NULL : buf;
  }
  return g->gr_name;
}

char* user_from_uid(uid_t uid, int noname) {
  struct passwd* pw = getpwuid(uid);
  if (pw == NULL) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "%lu", (long) uid);
    return noname ? NULL : buf;
  }
  return pw->pw_name;
}
