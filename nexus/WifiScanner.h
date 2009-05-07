#ifndef _WIFISCANNER_H
#define _WIFISCANNER_H

#include <pthread.h>

class Supplicant;

class WifiScanner {
    pthread_t       mWorker;
    pthread_mutex_t mWorkerLock;
    bool            mWorkerRunning;
    bool            mAbortRequest;
    pthread_mutex_t mAbortRequestLock;

    Supplicant *mSuppl;
    int        mPeriod;
    bool       mActive;
    

public:
    WifiScanner(Supplicant *suppl, int period);
    virtual ~WifiScanner() {}

    int getPeriod() { return mPeriod; }

    int startPeriodicScan(bool active);
    int stopPeriodicScan();

private:
    static void *threadStart(void *obj);
    static void threadCleanup(void *obj);

    void run();
};

#endif
