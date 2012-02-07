#ifndef _SOCKET_CLIENT_H
#define _SOCKET_CLIENT_H

#include "../../../frameworks/base/include/utils/List.h"

#include <pthread.h>
#include <cutils/atomic.h>
#include <sys/types.h>

class SocketClient {
    int             mSocket;
    bool            mSocketOwned;
    pthread_mutex_t mWriteMutex;

    /* Peer process ID */
    pid_t mPid;

    /* Peer user ID */
    uid_t mUid;

    /* Peer group ID */
    gid_t mGid;

    /* Reference count (starts at 1) */
    pthread_mutex_t mRefCountMutex;
    int mRefCount;

    int mCmdNum;

    bool mUseCmdNum;

public:
    SocketClient(int sock, bool owned);
    SocketClient(int sock, bool owned, bool useCmdNum);
    virtual ~SocketClient();

    int getSocket() { return mSocket; }
    pid_t getPid() const { return mPid; }
    uid_t getUid() const { return mUid; }
    gid_t getGid() const { return mGid; }
    void setCmdNum(int cmdNum) { android_atomic_release_store(cmdNum, &mCmdNum); }
    int getCmdNum() { return mCmdNum; }

    // Send null-terminated C strings:
    int sendMsg(int code, const char *msg, bool addErrno);
    int sendMsg(int code, const char *msg, bool addErrno, bool useCmdNum);

    //Sending binary data:
    int sendData(const void *data, int len);

    // Optional reference counting.  Reference count starts at 1.  If
    // it's decremented to 0, it deletes itself.
    // SocketListener creates a SocketClient (at refcount 1) and calls
    // decRef() when it's done with the client.
    void incRef();
    bool decRef(); // returns true at 0 (but note: SocketClient already deleted)

private:
    // Send null-terminated C strings
    int sendMsg(const char *msg);
    void init(int socket, bool owned, bool useCmdNum);
};

typedef android::List<SocketClient *> SocketClientCollection;
#endif
