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

    int sendMsg(char *msg);
    int sendMsg(char *msg, char *data);
};

typedef android::List<SocketClient *> SocketClientCollection;
#endif
