#ifndef _SOCKET_CLIENT_H
#define _SOCKET_CLIENT_H

#include "../../../frameworks/base/include/utils/List.h"

#include <pthread.h>
#include <sys/types.h>

class SocketClient {
    int             mSocket;
    pthread_mutex_t mWriteMutex;

    /* Peer process ID */
    pid_t mPid;

    /* Peer user ID */
    uid_t mUid;

    /* Peer group ID */
    gid_t mGid;

public:
    SocketClient(int sock);
    virtual ~SocketClient() {}

    int getSocket() { return mSocket; }
    pid_t getPid() const { return mPid; }
    uid_t getUid() const { return mUid; }
    gid_t getGid() const { return mGid; }

    // Send null-terminated C strings:
    int sendMsg(int code, const char *msg, bool addErrno);
    int sendMsg(const char *msg);

    // Sending binary data:
    int sendData(const void *data, int len);
};

typedef android::List<SocketClient *> SocketClientCollection;
#endif
