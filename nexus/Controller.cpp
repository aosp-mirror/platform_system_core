/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "Controller"

#include <cutils/log.h>

#include "Controller.h"
#include "InterfaceConfig.h"

extern "C" int init_module(void *, unsigned int, const char *);
extern "C" int delete_module(const char *, unsigned int);

Controller::Controller(const char *name, PropertyManager *propMngr,
                       IControllerHandler *handlers) {
    mPropMngr = propMngr;
    mName = strdup(name);
    mHandlers = handlers;
    mBoundInterface = NULL;
}

Controller::~Controller() {
    if (mBoundInterface)
        free(mBoundInterface);
    if (mName)
        free(mName);
}

int Controller::start() {
    return 0;
}

int Controller::stop() {
    return 0;
}

int Controller::loadKernelModule(char *modpath, const char *args) {
    void *module;
    unsigned int size;

    module = loadFile(modpath, &size);
    if (!module) {
        errno = -EIO;
        return -1;
    }

    int rc = init_module(module, size, args);
    free (module);
    return rc;
}

int Controller::unloadKernelModule(const char *modtag) {
    int rc = -1;
    int retries = 10;

    while (retries--) {
        rc = delete_module(modtag, O_NONBLOCK | O_EXCL);
        if (rc < 0 && errno == EAGAIN)
            usleep(1000*500);
        else
            break;
    }

    if (rc != 0) {
        LOGW("Unable to unload kernel driver '%s' (%s)", modtag,
             strerror(errno));
    }
    return rc;
}

bool Controller::isKernelModuleLoaded(const char *modtag) {
    FILE *fp = fopen("/proc/modules", "r");

    if (!fp) {
        LOGE("Unable to open /proc/modules (%s)", strerror(errno));
        return false;
    }

    char line[255];
    while(fgets(line, sizeof(line), fp)) {
        char *endTag = strchr(line, ' ');

        if (!endTag) {
            LOGW("Unable to find tag for line '%s'", line);
            continue;
        }
        if (!strncmp(line, modtag, (endTag - line))) {
            fclose(fp);
            return true;
        }
    }

    fclose(fp);
    return false;
}

void *Controller::loadFile(char *filename, unsigned int *_size)
{
	int ret, fd;
	struct stat sb;
	ssize_t size;
	void *buffer = NULL;

	/* open the file */
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	/* find out how big it is */
	if (fstat(fd, &sb) < 0)
		goto bail;
	size = sb.st_size;

	/* allocate memory for it to be read into */
	buffer = malloc(size);
	if (!buffer)
		goto bail;

	/* slurp it into our buffer */
	ret = read(fd, buffer, size);
	if (ret != size)
		goto bail;

	/* let the caller know how big it is */
	*_size = size;

bail:
	close(fd);
	return buffer;
}

int Controller::bindInterface(const char *ifname) {
    mBoundInterface = strdup(ifname);
    return 0;
}

int Controller::unbindInterface(const char *ifname) {
    free(mBoundInterface);
    mBoundInterface = NULL;
    return 0;
}
