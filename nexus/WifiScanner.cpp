#include <errno.h>
#include <pthread.h>

#define LOG_TAG "WifiScanner"
#include <cutils/log.h>

#include "WifiScanner.h"
#include "Supplicant.h"

extern "C" int pthread_cancel(pthread_t thread);

WifiScanner::WifiScanner(Supplicant *suppl, int period) {
    mSuppl = suppl;
    mPeriod = period;
    mActive = false;
    mWorkerRunning = false;
    mAbortRequest = false;
    pthread_mutex_init(&mAbortRequestLock, NULL);
    pthread_mutex_init(&mWorkerLock, NULL);
}

int WifiScanner::startPeriodicScan(bool active) {
    mActive = active;

    pthread_mutex_lock(&mWorkerLock);
    if (mWorkerRunning) {
        errno = EBUSY;
        return -1;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&mWorker, &attr, WifiScanner::threadStart, this))
        return -1;

    return 0;
}

void *WifiScanner::threadStart(void *obj) {
    WifiScanner *me = reinterpret_cast<WifiScanner *>(obj);
    me->run();
    pthread_exit(NULL);
    return NULL;
}

void WifiScanner::threadCleanup(void *obj) {
    WifiScanner *me = reinterpret_cast<WifiScanner *>(obj);

    me->mWorkerRunning = false;
    pthread_mutex_unlock(&me->mWorkerLock);

    if (me->mAbortRequest) {
        me->mAbortRequest = false;
        pthread_mutex_unlock(&me->mAbortRequestLock);
    }
}

int WifiScanner::stopPeriodicScan() {
    pthread_mutex_lock(&mAbortRequestLock);
    pthread_mutex_lock(&mWorkerLock);
    if (mWorkerRunning)
        mAbortRequest = true;
    pthread_mutex_unlock(&mWorkerLock);
    pthread_mutex_unlock(&mAbortRequestLock);

    return 0;
}

void WifiScanner::run() {
    LOGD("Thread started");

    mWorkerRunning = true;
    pthread_cleanup_push(WifiScanner::threadCleanup, this);
    pthread_mutex_unlock(&mWorkerLock);

    while(1) {
        LOGD("Triggering periodic scan");
        if (mSuppl->triggerScan(mActive)) {
            LOGW("Error triggering scan (%s)", strerror(errno));
        }

        sleep(mPeriod);
        pthread_mutex_lock(&mAbortRequestLock);
        if (mAbortRequest) {
            LOGD("Abort request!");
            goto out;
        }
        pthread_mutex_unlock(&mAbortRequestLock);
    }

out:
    pthread_cleanup_pop(1);
    pthread_mutex_unlock(&mWorkerLock);
}
