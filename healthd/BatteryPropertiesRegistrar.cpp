/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "BatteryPropertiesRegistrar.h"
#include <batteryservice/BatteryService.h>
#include <batteryservice/IBatteryPropertiesListener.h>
#include <batteryservice/IBatteryPropertiesRegistrar.h>
#include <binder/IServiceManager.h>
#include <utils/Errors.h>
#include <utils/Mutex.h>
#include <utils/String16.h>

namespace android {

BatteryPropertiesRegistrar::BatteryPropertiesRegistrar(BatteryMonitor* monitor) {
    mBatteryMonitor = monitor;
}

void BatteryPropertiesRegistrar::publish() {
    defaultServiceManager()->addService(String16("batterypropreg"), this);
}

void BatteryPropertiesRegistrar::notifyListeners(struct BatteryProperties props) {
    Mutex::Autolock _l(mRegistrationLock);
    for (size_t i = 0; i < mListeners.size(); i++) {
        mListeners[i]->batteryPropertiesChanged(props);
    }
}

void BatteryPropertiesRegistrar::registerListener(const sp<IBatteryPropertiesListener>& listener) {
    {
        Mutex::Autolock _l(mRegistrationLock);
        // check whether this is a duplicate
        for (size_t i = 0; i < mListeners.size(); i++) {
            if (mListeners[i]->asBinder() == listener->asBinder()) {
                return;
            }
        }

        mListeners.add(listener);
        listener->asBinder()->linkToDeath(this);
    }
    mBatteryMonitor->update();
}

void BatteryPropertiesRegistrar::unregisterListener(const sp<IBatteryPropertiesListener>& listener) {
    Mutex::Autolock _l(mRegistrationLock);
    for (size_t i = 0; i < mListeners.size(); i++) {
        if (mListeners[i]->asBinder() == listener->asBinder()) {
            mListeners[i]->asBinder()->unlinkToDeath(this);
            mListeners.removeAt(i);
            break;
        }
    }
}

void BatteryPropertiesRegistrar::binderDied(const wp<IBinder>& who) {
    Mutex::Autolock _l(mRegistrationLock);

    for (size_t i = 0; i < mListeners.size(); i++) {
        if (mListeners[i]->asBinder() == who) {
            mListeners.removeAt(i);
            break;
        }
    }
}

}  // namespace android
