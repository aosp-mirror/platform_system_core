/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "lmkd_service.h"

#include <errno.h>

#include <android-base/logging.h>
#include <liblmkd_utils.h>

#include "service_list.h"

namespace android {
namespace init {

enum LmkdRegistrationResult {
    LMKD_REG_SUCCESS,
    LMKD_CONN_FAILED,
    LMKD_REG_FAILED,
};

static int lmkd_socket = -1;

static LmkdRegistrationResult RegisterProcess(uid_t uid, pid_t pid, int oom_score_adjust) {
    // connect to lmkd if not already connected
    if (lmkd_socket < 0) {
        lmkd_socket = lmkd_connect();
        if (lmkd_socket < 0) {
            return LMKD_CONN_FAILED;
        }
    }

    // register service with lmkd
    struct lmk_procprio params;
    params.pid = pid;
    params.uid = uid;
    params.oomadj = oom_score_adjust;
    params.ptype = PROC_TYPE_SERVICE;
    if (lmkd_register_proc(lmkd_socket, &params) != 0) {
        // data transfer failed, reset the connection
        close(lmkd_socket);
        lmkd_socket = -1;
        return LMKD_REG_FAILED;
    }

    return LMKD_REG_SUCCESS;
}

static bool UnregisterProcess(pid_t pid) {
    if (lmkd_socket < 0) {
        // no connection or it was lost, no need to unregister
        return false;
    }

    // unregister service
    struct lmk_procremove params;
    params.pid = pid;
    if (lmkd_unregister_proc(lmkd_socket, &params) != 0) {
        // data transfer failed, reset the connection
        close(lmkd_socket);
        lmkd_socket = -1;
        return false;
    }

    return true;
}

static void RegisterServices(pid_t exclude_pid) {
    for (const auto& service : ServiceList::GetInstance()) {
        auto svc = service.get();
        if (svc->oom_score_adjust() != DEFAULT_OOM_SCORE_ADJUST) {
            // skip if process is excluded or not yet forked (pid==0)
            if (svc->pid() == exclude_pid || svc->pid() == 0) {
                continue;
            }
            if (RegisterProcess(svc->uid(), svc->pid(), svc->oom_score_adjust()) !=
                LMKD_REG_SUCCESS) {
                // a failure here resets the connection, will retry during next registration
                break;
            }
        }
    }
}

void LmkdRegister(const std::string& name, uid_t uid, pid_t pid, int oom_score_adjust) {
    bool new_connection = lmkd_socket == -1;
    LmkdRegistrationResult result;

    result = RegisterProcess(uid, pid, oom_score_adjust);
    if (result == LMKD_REG_FAILED) {
        // retry one time if connection to lmkd was lost
        result = RegisterProcess(uid, pid, oom_score_adjust);
        new_connection = result == LMKD_REG_SUCCESS;
    }
    switch (result) {
        case LMKD_REG_SUCCESS:
            // register existing services once new connection is established
            if (new_connection) {
                RegisterServices(pid);
            }
            break;
        case LMKD_CONN_FAILED:
            PLOG(ERROR) << "lmkd connection failed when " << name << " process got started";
            break;
        case LMKD_REG_FAILED:
            PLOG(ERROR) << "lmkd failed to register " << name << " process";
            break;
    }
}

void LmkdUnregister(const std::string& name, pid_t pid) {
    if (!UnregisterProcess(pid)) {
        PLOG(ERROR) << "lmkd failed to unregister " << name << " process";
    }
}

}  // namespace init
}  // namespace android
