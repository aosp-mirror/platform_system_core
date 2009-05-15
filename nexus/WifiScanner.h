#ifndef _WIFISCANNER_H
#define _WIFISCANNER_H

#include <pthread.h>

class Supplicant;

class WifiScanner {
    pthread_t  mThread;
    int        mCtrlPipe[2];
    Supplicant *mSuppl;
    int        mPeriod;
    bool       mActive;
    

public:
    WifiScanner(Supplicant *suppl, int period);
    virtual ~WifiScanner() {}

    int getPeriod() { return mPeriod; }

    int start(bool active);
    int stop();

private:
    static void *threadStart(void *obj);

    void run();
};

#endif
