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

/*
**	mountd server support
*/

#include "mountd.h"
#include "ASEC.h"

#include <cutils/properties.h>
#include <cutils/sockets.h>

#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#include <private/android_filesystem_config.h>


// current client file descriptor
static int sFD = -1;

// to synchronize writing to client
static pthread_mutex_t sWriteMutex = PTHREAD_MUTEX_INITIALIZER;

// path for media that failed to mount before the runtime is connected
static char* sDeferredUnmountableMediaPath = NULL;

// last asec msg before the runtime was connected
static char* sAsecDeferredMessage = NULL;
static char* sAsecDeferredArgument = NULL;

static int Write(const char* message)
{
    int result = -1;

    pthread_mutex_lock(&sWriteMutex);
    
    LOG_SERVER("Write: %s\n", message);
    if (sFD >= 0)
        result = write(sFD, message, strlen(message) + 1);

    pthread_mutex_unlock(&sWriteMutex); 
    
    return result;
}

static int Write2(const char* message, const char* data)
{
    int result = -1;

    char* buffer = (char *)alloca(strlen(message) + strlen(data) + 1);
    if (!buffer)
    {
        LOG_ERROR("alloca failed in Write2\n");
        return -1;
    }

    strcpy(buffer, message);
    strcat(buffer, data);
    return Write(buffer);
}

static void SendStatus()
{
    Write(IsMassStorageConnected() ? MOUNTD_UMS_CONNECTED : MOUNTD_UMS_DISCONNECTED);
    Write(IsMassStorageEnabled() ? MOUNTD_UMS_ENABLED : MOUNTD_UMS_DISABLED);
}

static void DoCommand(const char* command)
{
    LOG_SERVER("DoCommand %s\n", command);
    
    if (strcmp(command, MOUNTD_ENABLE_UMS) == 0)
    {
        EnableMassStorage(true);
        Write(MOUNTD_UMS_ENABLED);
     }
    else if (strcmp(command, MOUNTD_DISABLE_UMS) == 0) 
    {
        EnableMassStorage(false);
        Write(MOUNTD_UMS_DISABLED);
    }
    else if (strcmp(command, MOUNTD_SEND_STATUS) == 0)
    {
        SendStatus();
    }
    else if (strncmp(command, MOUNTD_MOUNT_MEDIA, strlen(MOUNTD_MOUNT_MEDIA)) == 0)
    {
        const char* path = command + strlen(MOUNTD_MOUNT_MEDIA);
        MountMedia(path);
    }
    else if (strncmp(command, MOUNTD_EJECT_MEDIA, strlen(MOUNTD_EJECT_MEDIA)) == 0)
    {
        const char* path = command + strlen(MOUNTD_EJECT_MEDIA);
        UnmountMedia(path);
    } 
    else if (strncmp(command, ASEC_CMD_ENABLE, strlen(ASEC_CMD_ENABLE)) == 0) {
        LOG_ASEC("Got ASEC_CMD_ENABLE\n");
	// XXX: SAN: Impliment
    }
    else if (strncmp(command, ASEC_CMD_DISABLE, strlen(ASEC_CMD_DISABLE)) == 0) {
        LOG_ASEC("Got ASEC_CMD_DISABLE\n");
	// XXX: SAN: Impliment
    }
    else if (strncmp(command, ASEC_CMD_SEND_STATUS, strlen(ASEC_CMD_SEND_STATUS)) == 0) {
        LOG_ASEC("Got ASEC_CMD_SEND_STATUS\n");
	// XXX: SAN: Impliment
    }
    else
        LOGE("unknown command %s\n", command);
}

int RunServer()
{
    int socket = android_get_control_socket(MOUNTD_SOCKET);
    if (socket < 0) {
        LOGE("Obtaining file descriptor for socket '%s' failed: %s",
             MOUNTD_SOCKET, strerror(errno));
        return -1;
    }

    if (listen(socket, 4) < 0) {
        LOGE("Unable to listen on file descriptor '%d' for socket '%s': %s",
             socket, MOUNTD_SOCKET, strerror(errno));
        return -1;
    }

    while (1)
    {
        struct sockaddr addr;
        socklen_t alen;
        struct ucred cred;
        socklen_t size;
        
        alen = sizeof(addr);
        sFD = accept(socket, &addr, &alen);
        if (sFD < 0)
            continue;
            
        if (sDeferredUnmountableMediaPath) {
            NotifyMediaState(sDeferredUnmountableMediaPath, MEDIA_UNMOUNTABLE, false);
            free(sDeferredUnmountableMediaPath);
            sDeferredUnmountableMediaPath = NULL;
        }

        if (sAsecDeferredMessage) {
    
            if (Write2(sAsecDeferredMessage, sAsecDeferredArgument) < 0)
                LOG_ERROR("Failed to deliver deferred ASEC msg to framework\n");
            free(sAsecDeferredMessage);
            free(sAsecDeferredArgument);
            sAsecDeferredMessage = sAsecDeferredArgument = NULL;
        }

        while (1)
        {    
            char    buffer[101];
            int result = read(sFD, buffer, sizeof(buffer) - 1);
            if (result > 0)
            {
                int start = 0;
                int i;
                // command should be zero terminated, but just in case
                buffer[result] = 0;
                for (i = 0; i < result; i++) 
                {
                    if (buffer[i] == 0) 
                    {
                        DoCommand(buffer + start);
                        start = i + 1;
                    }                   
                }
            }
            else
            {
                close(sFD);
                sFD = -1;
                break;
            }
        }
    }  

    // should never get here
    return 0;
}

void SendMassStorageConnected(boolean connected)
{
    Write(connected ? MOUNTD_UMS_CONNECTED : MOUNTD_UMS_DISCONNECTED);
}

void SendUnmountRequest(const char* path)
{
    Write2(MOUNTD_REQUEST_EJECT, path);
}

void NotifyAsecState(AsecState state, const char *argument)
{
    const char *event = NULL;
    const char *status = NULL;
    boolean deferr = true;;

    switch (state) {
        case ASEC_DISABLED:
            event = ASEC_EVENT_DISABLED;
            status = ASEC_STATUS_DISABLED;
            break;
        case ASEC_AVAILABLE:
            event = ASEC_EVENT_AVAILABLE;
            status = ASEC_STATUS_AVAILABLE;
            break;
        case ASEC_BUSY:
            event = ASEC_EVENT_BUSY;
            status = ASEC_STATUS_BUSY;
            deferr = false;
            break;
        case ASEC_FAILED_INTERR:
            event = ASEC_EVENT_FAILED_INTERR;
            status = ASEC_STATUS_FAILED_INTERR;
            break;
        case ASEC_FAILED_NOMEDIA:
            event = ASEC_EVENT_FAILED_NOMEDIA;
            status = ASEC_STATUS_FAILED_NOMEDIA;
            break;
        case ASEC_FAILED_BADMEDIA:
            event = ASEC_EVENT_FAILED_BADMEDIA;
            status = ASEC_STATUS_FAILED_BADMEDIA;
            break;
        case ASEC_FAILED_BADKEY:
            event = ASEC_EVENT_FAILED_BADKEY;
            status = ASEC_STATUS_FAILED_BADKEY;
            break;
        default:
            LOG_ERROR("unknown AsecState %d in NotifyAsecState\n", state);
            return;
    }

    property_set(ASEC_STATUS, status);

    int result = Write2(event, argument);
    if ((result < 0) && deferr) {
        if (sAsecDeferredMessage) 
            free(sAsecDeferredMessage);
        sAsecDeferredMessage = strdup(event);
        if (sAsecDeferredArgument)
            free(sAsecDeferredArgument);
        sAsecDeferredArgument = strdup(argument);
        LOG_ASEC("Deferring event '%s' arg '%s' until framework connects\n", event, argument);
    }
}

void NotifyMediaState(const char* path, MediaState state, boolean readOnly)
{
    const char* event = NULL;
    const char* propertyValue = NULL;
    
    switch (state) {
        case MEDIA_REMOVED:
            event = MOUNTD_MEDIA_REMOVED;
            propertyValue = EXTERNAL_STORAGE_REMOVED;
            break;
        case MEDIA_UNMOUNTED:
            event = MOUNTD_MEDIA_UNMOUNTED;
            propertyValue = EXTERNAL_STORAGE_UNMOUNTED;
            break;
        case MEDIA_MOUNTED:
            event = (readOnly ? MOUNTD_MEDIA_MOUNTED_READ_ONLY : MOUNTD_MEDIA_MOUNTED);
             propertyValue = (readOnly ? EXTERNAL_STORAGE_MOUNTED_READ_ONLY : EXTERNAL_STORAGE_MOUNTED);
           break;
        case MEDIA_SHARED:
            event = MOUNTD_MEDIA_SHARED;
            propertyValue = EXTERNAL_STORAGE_SHARED;
            break;
        case MEDIA_BAD_REMOVAL:
            event = MOUNTD_MEDIA_BAD_REMOVAL;
            propertyValue = EXTERNAL_STORAGE_BAD_REMOVAL;
            break;
        case MEDIA_UNMOUNTABLE:
            event = MOUNTD_MEDIA_UNMOUNTABLE;
            propertyValue = EXTERNAL_STORAGE_UNMOUNTABLE;
            break;
        default:
            LOG_ERROR("unknown MediaState %d in NotifyMediaState\n", state);
            return;
    }
    
    property_set(EXTERNAL_STORAGE_STATE, propertyValue);
    int result = Write2(event, path);
    if (result < 0 && state == MEDIA_UNMOUNTABLE) {
    
        // if we cannot communicate with the runtime, defer this message until the runtime is available
        sDeferredUnmountableMediaPath = strdup(path);
    }
}
