#include <alloca.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>

#define LOG_TAG "SocketClient"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

SocketClient::SocketClient(int socket) {
    mSocket = socket;
    pthread_mutex_init(&mWriteMutex, NULL);
}

int SocketClient::sendMsg(int code, char *msg, bool addErrno) {
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

int SocketClient::sendMsg(char *msg) {
    if (mSocket < 0) {
        errno = EHOSTUNREACH;
        return -1;
    }

    char *bp;
  
    if (msg[strlen(msg)] != '\n') {
        bp = (char *) alloca(strlen(msg) + 1);
        strcpy(bp, msg);
        strcat(bp, "\n");
    } else
        bp = msg;
       
    int rc = 0;
    char *p = bp;
    int brtw = strlen(bp);

    pthread_mutex_lock(&mWriteMutex);
    while(brtw) {
        if ((rc = write(mSocket,p, brtw)) < 0) {
            LOGW("Unable to send msg '%s' (%s)", msg, strerror(errno));
            pthread_mutex_unlock(&mWriteMutex);
            return -1;
        } else if (!rc) {
            LOGW("0 length write :(");
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
