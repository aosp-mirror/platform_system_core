#ifndef _SOCKET_CLIENT_H
#define _SOCKET_CLIENT_H

#include "../../../frameworks/base/include/utils/List.h"

#include <pthread.h>

class SocketClient {
    int             mSocket;
    pthread_mutex_t mWriteMutex;

public:
    SocketClient(int sock);
    virtual ~SocketClient() {}

    int getSocket() { return mSocket; }

    int sendMsg(int code, const char *msg, bool addErrno);
    int sendMsg(const char *msg);
};

typedef android::List<SocketClient *> SocketClientCollection;
#endif
