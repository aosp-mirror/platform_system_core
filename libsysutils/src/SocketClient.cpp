#include <alloca.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>

#define LOG_TAG "SocketClient"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

SocketClient::SocketClient(int socket, bool owned) {
    init(socket, owned, false);
}

SocketClient::SocketClient(int socket, bool owned, bool useCmdNum) {
    init(socket, owned, useCmdNum);
}

void SocketClient::init(int socket, bool owned, bool useCmdNum) {
    mSocket = socket;
    mSocketOwned = owned;
    mUseCmdNum = useCmdNum;
    pthread_mutex_init(&mWriteMutex, NULL);
    pthread_mutex_init(&mRefCountMutex, NULL);
    mPid = -1;
    mUid = -1;
    mGid = -1;
    mRefCount = 1;
    mCmdNum = 0;

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

SocketClient::~SocketClient()
{
    if (mSocketOwned) {
        close(mSocket);
    }
}

int SocketClient::sendMsg(int code, const char *msg, bool addErrno) {
    return sendMsg(code, msg, addErrno, mUseCmdNum);
}

int SocketClient::sendMsg(int code, const char *msg, bool addErrno, bool useCmdNum) {
    char *buf;
    int ret = 0;

    if (addErrno) {
        if (useCmdNum) {
            ret = asprintf(&buf, "%d %d %s (%s)", code, getCmdNum(), msg, strerror(errno));
        } else {
            ret = asprintf(&buf, "%d %s (%s)", code, msg, strerror(errno));
        }
    } else {
        if (useCmdNum) {
            ret = asprintf(&buf, "%d %d %s", code, getCmdNum(), msg);
        } else {
            ret = asprintf(&buf, "%d %s", code, msg);
        }
    }
    /* Send the zero-terminated message */
    if (ret != -1) {
        ret = sendMsg(buf);
        free(buf);
    }
    return ret;
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
        rc = write(mSocket, p, brtw);
        if (rc > 0) {
            p += rc;
            brtw -= rc;
            continue;
        }

        if (rc < 0 && errno == EINTR)
            continue;

        pthread_mutex_unlock(&mWriteMutex);
        if (rc == 0) {
            SLOGW("0 length write :(");
            errno = EIO;
        } else {
            SLOGW("write error (%s)", strerror(errno));
        }
        return -1;
    }
    pthread_mutex_unlock(&mWriteMutex);
    return 0;
}

void SocketClient::incRef() {
    pthread_mutex_lock(&mRefCountMutex);
    mRefCount++;
    pthread_mutex_unlock(&mRefCountMutex);
}

bool SocketClient::decRef() {
    bool deleteSelf = false;
    pthread_mutex_lock(&mRefCountMutex);
    mRefCount--;
    if (mRefCount == 0) {
        deleteSelf = true;
    } else if (mRefCount < 0) {
        SLOGE("SocketClient refcount went negative!");
    }
    pthread_mutex_unlock(&mRefCountMutex);
    if (deleteSelf) {
        delete this;
    }
    return deleteSelf;
}
