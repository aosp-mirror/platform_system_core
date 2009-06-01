/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _ISUPPLICANT_EVENT_HANDLER_H
#define _ISUPPLICANT_EVENT_HANDLER_H

class ISupplicantEventHandler {
public:
    virtual int onConnectedEvent(SupplicantEvent *evt) = 0;
    virtual int onDisconnectedEvent(SupplicantEvent *evt) = 0;
    virtual int onTerminatingEvent(SupplicantEvent *evt) = 0;
    virtual int onPasswordChangedEvent(SupplicantEvent *evt) = 0;
    virtual int onEapNotificationEvent(SupplicantEvent *evt) = 0;
    virtual int onEapStartedEvent(SupplicantEvent *evt) = 0;
    virtual int onEapMethodEvent(SupplicantEvent *evt) = 0;
    virtual int onEapSuccessEvent(SupplicantEvent *evt) = 0;
    virtual int onEapFailureEvent(SupplicantEvent *evt) = 0;
    virtual int onScanResultsEvent(SupplicantEvent *evt) = 0;
    virtual int onStateChangeEvent(SupplicantEvent *evt) = 0;
    virtual int onLinkSpeedEvent(SupplicantEvent *evt) = 0;
    virtual int onDriverStateEvent(SupplicantEvent *evt) = 0;
};

#endif

