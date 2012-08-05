/*
 * Copyright (C) 2005 The Android Open Source Project
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

#define LOG_TAG "misc"

//
// Miscellaneous utility functions.
//
#include <utils/misc.h>
#include <utils/Log.h>

#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>

#if defined(HAVE_PTHREADS)
# include <pthread.h>
#endif

#include <utils/Vector.h>

using namespace android;

namespace android {

/*
 * Get a file's type.
 */
FileType getFileType(const char* fileName)
{
    struct stat sb;

    if (stat(fileName, &sb) < 0) {
        if (errno == ENOENT || errno == ENOTDIR)
            return kFileTypeNonexistent;
        else {
            fprintf(stderr, "getFileType got errno=%d on '%s'\n",
                errno, fileName);
            return kFileTypeUnknown;
        }
    } else {
        if (S_ISREG(sb.st_mode))
            return kFileTypeRegular;
        else if (S_ISDIR(sb.st_mode))
            return kFileTypeDirectory;
        else if (S_ISCHR(sb.st_mode))
            return kFileTypeCharDev;
        else if (S_ISBLK(sb.st_mode))
            return kFileTypeBlockDev;
        else if (S_ISFIFO(sb.st_mode))
            return kFileTypeFifo;
#ifdef HAVE_SYMLINKS            
        else if (S_ISLNK(sb.st_mode))
            return kFileTypeSymlink;
        else if (S_ISSOCK(sb.st_mode))
            return kFileTypeSocket;
#endif            
        else
            return kFileTypeUnknown;
    }
}

/*
 * Get a file's modification date.
 */
time_t getFileModDate(const char* fileName)
{
    struct stat sb;

    if (stat(fileName, &sb) < 0)
        return (time_t) -1;

    return sb.st_mtime;
}

struct sysprop_change_callback_info {
    sysprop_change_callback callback;
    int priority;
};

#if defined(HAVE_PTHREADS)
static pthread_mutex_t gSyspropMutex = PTHREAD_MUTEX_INITIALIZER;
static Vector<sysprop_change_callback_info>* gSyspropList = NULL;
#endif

void add_sysprop_change_callback(sysprop_change_callback cb, int priority) {
#if defined(HAVE_PTHREADS)
    pthread_mutex_lock(&gSyspropMutex);
    if (gSyspropList == NULL) {
        gSyspropList = new Vector<sysprop_change_callback_info>();
    }
    sysprop_change_callback_info info;
    info.callback = cb;
    info.priority = priority;
    bool added = false;
    for (size_t i=0; i<gSyspropList->size(); i++) {
        if (priority >= gSyspropList->itemAt(i).priority) {
            gSyspropList->insertAt(info, i);
            added = true;
            break;
        }
    }
    if (!added) {
        gSyspropList->add(info);
    }
    pthread_mutex_unlock(&gSyspropMutex);
#endif
}

void report_sysprop_change() {
#if defined(HAVE_PTHREADS)
    pthread_mutex_lock(&gSyspropMutex);
    Vector<sysprop_change_callback_info> listeners;
    if (gSyspropList != NULL) {
        listeners = *gSyspropList;
    }
    pthread_mutex_unlock(&gSyspropMutex);

    //ALOGI("Reporting sysprop change to %d listeners", listeners.size());
    for (size_t i=0; i<listeners.size(); i++) {
        listeners[i].callback();
    }
#endif
}

}; // namespace android
