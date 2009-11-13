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

class SupplicantAssociatingEvent;
class SupplicantAssociatedEvent;
class SupplicantConnectedEvent;
class SupplicantScanResultsEvent;
class SupplicantStateChangeEvent;
class SupplicantConnectionTimeoutEvent;
class SupplicantDisconnectedEvent;

class ISupplicantEventHandler {
public:
    virtual ~ISupplicantEventHandler(){}
    virtual void onAssociatingEvent(SupplicantAssociatingEvent *evt) = 0;
    virtual void onAssociatedEvent(SupplicantAssociatedEvent *evt) = 0;
    virtual void onConnectedEvent(SupplicantConnectedEvent *evt) = 0;
    virtual void onScanResultsEvent(SupplicantScanResultsEvent *evt) = 0;
    virtual void onStateChangeEvent(SupplicantStateChangeEvent *evt) = 0;
    virtual void onConnectionTimeoutEvent(SupplicantConnectionTimeoutEvent *evt) = 0;
    virtual void onDisconnectedEvent(SupplicantDisconnectedEvent *evt) = 0;
#if 0
    virtual void onTerminatingEvent(SupplicantEvent *evt) = 0;
    virtual void onPasswordChangedEvent(SupplicantEvent *evt) = 0;
    virtual void onEapNotificationEvent(SupplicantEvent *evt) = 0;
    virtual void onEapStartedEvent(SupplicantEvent *evt) = 0;
    virtual void onEapMethodEvent(SupplicantEvent *evt) = 0;
    virtual void onEapSuccessEvent(SupplicantEvent *evt) = 0;
    virtual void onEapFailureEvent(SupplicantEvent *evt) = 0;
    virtual void onLinkSpeedEvent(SupplicantEvent *evt) = 0;
    virtual void onDriverStateEvent(SupplicantEvent *evt) = 0;
#endif
};

#endif

