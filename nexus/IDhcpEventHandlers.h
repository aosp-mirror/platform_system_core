
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

#ifndef _IDhcpEventHandlers_H
#define _IDhcpEventHandlers_H

class IDhcpEventHandlers {
public:
    virtual ~IDhcpEventHandlers() {}
    virtual void onDhcpStateChanged(Controller *c, int state) = 0;
    virtual void onDhcpEvent(Controller *c, int event) = 0;
    virtual void onDhcpLeaseUpdated(Controller *c,
                                    struct in_addr *addr, struct in_addr *net,
                                    struct in_addr *brd,
                                    struct in_addr *gw, struct in_addr *dns1,
                                    struct in_addr *dns2) = 0;
};

#endif
