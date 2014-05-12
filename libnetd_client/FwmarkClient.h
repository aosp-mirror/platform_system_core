/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef NETD_CLIENT_FWMARK_CLIENT_H
#define NETD_CLIENT_FWMARK_CLIENT_H

#include <sys/socket.h>

class FwmarkClient {
public:
    // Returns true if |sockfd| should be sent to the fwmark server to have its SO_MARK set.
    static bool shouldSetFwmark(int sockfd, const sockaddr* addr);

    FwmarkClient();
    ~FwmarkClient();

    // Sends |data| to the fwmark server, along with |fd| as ancillary data using cmsg(3).
    // Returns true on success.
    bool send(void* data, size_t len, int fd);

private:
    int mChannel;
};

#endif  // NETD_CLIENT_INCLUDE_FWMARK_CLIENT_H
