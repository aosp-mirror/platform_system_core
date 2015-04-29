/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _FILE_SYNC_SERVICE_H_
#define _FILE_SYNC_SERVICE_H_

#include <string>

#define htoll(x) (x)
#define ltohl(x) (x)

#define MKID(a,b,c,d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

#define ID_STAT MKID('S','T','A','T')
#define ID_LIST MKID('L','I','S','T')
#define ID_ULNK MKID('U','L','N','K')
#define ID_SEND MKID('S','E','N','D')
#define ID_RECV MKID('R','E','C','V')
#define ID_DENT MKID('D','E','N','T')
#define ID_DONE MKID('D','O','N','E')
#define ID_DATA MKID('D','A','T','A')
#define ID_OKAY MKID('O','K','A','Y')
#define ID_FAIL MKID('F','A','I','L')
#define ID_QUIT MKID('Q','U','I','T')

union syncmsg {
    unsigned id;
    struct {
        unsigned id;
        unsigned namelen;
    } req;
    struct {
        unsigned id;
        unsigned mode;
        unsigned size;
        unsigned time;
    } stat;
    struct {
        unsigned id;
        unsigned mode;
        unsigned size;
        unsigned time;
        unsigned namelen;
    } dent;
    struct {
        unsigned id;
        unsigned size;
    } data;
    struct {
        unsigned id;
        unsigned msglen;
    } status;
} ;


void file_sync_service(int fd, void *cookie);
int do_sync_ls(const char *path);
int do_sync_push(const char *lpath, const char *rpath, int show_progress);
int do_sync_sync(const std::string& lpath, const std::string& rpath, bool list_only);
int do_sync_pull(const char *rpath, const char *lpath, int show_progress, int pullTime);

#define SYNC_DATA_MAX (64*1024)

#endif
