#include <errno.h>

#include <sysutils/ServiceManager.h>

#define LOG_TAG "Service"
#include <cutils/log.h>
#include <cutils/properties.h>

ServiceManager::ServiceManager() {
}

int ServiceManager::start(const char *name) {
    if (isRunning(name)) {
        SLOGW("Service '%s' is already running", name);
        return 0;
    }

    SLOGD("Starting service '%s'", name);
    property_set("ctl.start", name);

    int count = 200;
    while(count--) {
        sched_yield();
        if (isRunning(name))
            break;
    }
    if (!count) {
        SLOGW("Timed out waiting for service '%s' to start", name);
        errno = ETIMEDOUT;
        return -1;
    }
    SLOGD("Sucessfully started '%s'", name);
    return 0;
}

int ServiceManager::stop(const char *name) {
    if (!isRunning(name)) {
        SLOGW("Service '%s' is already stopped", name);
        return 0;
    }

    SLOGD("Stopping service '%s'", name);
    property_set("ctl.stop", name);

    int count = 200;
    while(count--) {
        sched_yield();
        if (!isRunning(name))
            break;
    }

    if (!count) {
        SLOGW("Timed out waiting for service '%s' to stop", name);
        errno = ETIMEDOUT;
        return -1;
    }
    SLOGD("Sucessfully stopped '%s'", name);
    return 0;
}

bool ServiceManager::isRunning(const char *name) {
    char propVal[PROPERTY_VALUE_MAX];
    char propName[255];

    snprintf(propName, sizeof(propVal), "init.svc.%s", name);


    if (property_get(propName, propVal, NULL)) {
        if (!strcmp(propVal, "running"))
            return true;
    }
    return false;
}
