#include <alloca.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>

#define LOG_TAG "SocketClient"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

SocketClient::SocketClient(int socket) {
    mSocket = socket;
    pthread_mutex_init(&mWriteMutex, NULL);
}

int SocketClient::sendMsg(char *msg) {
    LOGD("SocketClient::sendMsg(%s)", msg);
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

int SocketClient::sendMsg(char *msg, char *data) {
    char *buffer = (char *) alloca(strlen(msg) + strlen(data) + 1);
    if (!buffer) {
        errno = -ENOMEM;
        return -1;
    }
    strcpy(buffer, msg);
    strcat(buffer, data);
    return sendMsg(buffer);
}

