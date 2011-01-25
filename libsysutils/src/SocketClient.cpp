#include <alloca.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>

#define LOG_TAG "SocketClient"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

SocketClient::SocketClient(int socket)
        : mSocket(socket)
        , mPid(-1)
        , mUid(-1)
        , mGid(-1)
{
    pthread_mutex_init(&mWriteMutex, NULL);

    struct ucred creds;
    socklen_t szCreds = sizeof(creds);
    memset(&creds, 0, szCreds);

    int err = getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &creds, &szCreds);
    if (err == 0) {
        mPid = creds.pid;
        mUid = creds.uid;
        mGid = creds.gid;
    }
}

int SocketClient::sendMsg(int code, const char *msg, bool addErrno) {
    char *buf;

    if (addErrno) {
        buf = (char *) alloca(strlen(msg) + strlen(strerror(errno)) + 8);
        sprintf(buf, "%.3d %s (%s)", code, msg, strerror(errno));
    } else {
        buf = (char *) alloca(strlen(msg) + strlen("XXX "));
        sprintf(buf, "%.3d %s", code, msg);
    }
    return sendMsg(buf);
}

int SocketClient::sendMsg(const char *msg) {
    if (mSocket < 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    // Send the message including null character
    if (sendData(msg, strlen(msg) + 1) != 0) {
        SLOGW("Unable to send msg '%s'", msg);
        return -1;
    }
    return 0;
}

int SocketClient::sendData(const void* data, int len) {
    int rc = 0;
    const char *p = (const char*) data;
    int brtw = len;

    if (len == 0) {
        return 0;
    }

    pthread_mutex_lock(&mWriteMutex);
    while (brtw > 0) {
        if ((rc = write(mSocket, p, brtw)) < 0) {
            SLOGW("write error (%s)", strerror(errno));
            pthread_mutex_unlock(&mWriteMutex);
            return -1;
        } else if (!rc) {
            SLOGW("0 length write :(");
            errno = EIO;
            pthread_mutex_unlock(&mWriteMutex);
            return -1;
        }
        p += rc;
        brtw -= rc;
    }
    pthread_mutex_unlock(&mWriteMutex);
    return 0;
}
