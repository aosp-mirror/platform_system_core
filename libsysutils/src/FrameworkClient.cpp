#include <alloca.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>

#define LOG_TAG "FrameworkClient"
#include <cutils/log.h>

#include <sysutils/FrameworkClient.h>

FrameworkClient::FrameworkClient(int socket) {
    mSocket = socket;
    pthread_mutex_init(&mWriteMutex, NULL);
}

int FrameworkClient::sendMsg(const char *msg) {
    if (mSocket < 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    pthread_mutex_lock(&mWriteMutex);
    if (write(mSocket, msg, strlen(msg) +1) < 0) {
        LOGW("Unable to send msg '%s' (%s)", msg, strerror(errno));
    }
    pthread_mutex_unlock(&mWriteMutex);
    return 0;
}

int FrameworkClient::sendMsg(const char *msg, const char *data) {
    char *buffer = (char *) alloca(strlen(msg) + strlen(data) + 1);
    if (!buffer) {
        errno = -ENOMEM;
        return -1;
    }
    strcpy(buffer, msg);
    strcat(buffer, data);
    return sendMsg(buffer);
}

