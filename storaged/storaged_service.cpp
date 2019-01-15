/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <inttypes.h>
#include <stdint.h>

#include <vector>

#include <android-base/parseint.h>
#include <android-base/parsedouble.h>
#include <binder/IBinder.h>
#include <binder/IInterface.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <private/android_filesystem_config.h>

#include <storaged.h>
#include <storaged_utils.h>
#include <storaged_service.h>

using namespace std;
using namespace android::base;

extern sp<storaged_t> storaged_sp;

status_t StoragedService::start() {
    return BinderService<StoragedService>::publish();
}

void StoragedService::dumpUidRecords(int fd, const vector<uid_record>& entries) {
    map<string, io_usage> merged_entries = merge_io_usage(entries);
    for (const auto& rec : merged_entries) {
        dprintf(fd, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                rec.first.c_str(),
                rec.second.bytes[READ][FOREGROUND][CHARGER_OFF],
                rec.second.bytes[WRITE][FOREGROUND][CHARGER_OFF],
                rec.second.bytes[READ][BACKGROUND][CHARGER_OFF],
                rec.second.bytes[WRITE][BACKGROUND][CHARGER_OFF],
                rec.second.bytes[READ][FOREGROUND][CHARGER_ON],
                rec.second.bytes[WRITE][FOREGROUND][CHARGER_ON],
                rec.second.bytes[READ][BACKGROUND][CHARGER_ON],
                rec.second.bytes[WRITE][BACKGROUND][CHARGER_ON]);
    }
}

void StoragedService::dumpUidRecordsDebug(int fd, const vector<uid_record>& entries) {
    for (const auto& record : entries) {
        const io_usage& uid_usage = record.ios.uid_ios;
        dprintf(fd, "%s_%d %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                record.name.c_str(), record.ios.user_id,
                uid_usage.bytes[READ][FOREGROUND][CHARGER_OFF],
                uid_usage.bytes[WRITE][FOREGROUND][CHARGER_OFF],
                uid_usage.bytes[READ][BACKGROUND][CHARGER_OFF],
                uid_usage.bytes[WRITE][BACKGROUND][CHARGER_OFF],
                uid_usage.bytes[READ][FOREGROUND][CHARGER_ON],
                uid_usage.bytes[WRITE][FOREGROUND][CHARGER_ON],
                uid_usage.bytes[READ][BACKGROUND][CHARGER_ON],
                uid_usage.bytes[WRITE][BACKGROUND][CHARGER_ON]);

        for (const auto& task_it : record.ios.task_ios) {
            const io_usage& task_usage = task_it.second;
            const string& comm = task_it.first;
            dprintf(fd, "-> %s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                    " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                    comm.c_str(),
                    task_usage.bytes[READ][FOREGROUND][CHARGER_OFF],
                    task_usage.bytes[WRITE][FOREGROUND][CHARGER_OFF],
                    task_usage.bytes[READ][BACKGROUND][CHARGER_OFF],
                    task_usage.bytes[WRITE][BACKGROUND][CHARGER_OFF],
                    task_usage.bytes[READ][FOREGROUND][CHARGER_ON],
                    task_usage.bytes[WRITE][FOREGROUND][CHARGER_ON],
                    task_usage.bytes[READ][BACKGROUND][CHARGER_ON],
                    task_usage.bytes[WRITE][BACKGROUND][CHARGER_ON]);
        }
    }
}

status_t StoragedService::dump(int fd, const Vector<String16>& args) {
    IPCThreadState* self = IPCThreadState::self();
    const int pid = self->getCallingPid();
    const int uid = self->getCallingUid();
    if ((uid != AID_SHELL) &&
        !PermissionCache::checkPermission(
                String16("android.permission.DUMP"), pid, uid)) {
        return PERMISSION_DENIED;
    }

    double hours = 0;
    int time_window = 0;
    uint64_t threshold = 0;
    bool force_report = false;
    bool debug = false;
    for (size_t i = 0; i < args.size(); i++) {
        const auto& arg = args[i];
        if (arg == String16("--hours")) {
            if (++i >= args.size())
                break;
            if(!ParseDouble(String8(args[i]).c_str(), &hours))
                return BAD_VALUE;
            continue;
        }
        if (arg == String16("--time_window")) {
            if (++i >= args.size())
                break;
            if(!ParseInt(String8(args[i]).c_str(), &time_window))
                return BAD_VALUE;
            continue;
        }
        if (arg == String16("--threshold")) {
            if (++i >= args.size())
                break;
            if(!ParseUint(String8(args[i]).c_str(), &threshold))
                return BAD_VALUE;
            continue;
        }
        if (arg == String16("--force")) {
            force_report = true;
            continue;
        }
        if (arg == String16("--debug")) {
            debug = true;
            continue;
        }
    }

    uint64_t last_ts = 0;
    map<uint64_t, struct uid_records> records =
                storaged_sp->get_uid_records(hours, threshold, force_report);
    for (const auto& it : records) {
        if (last_ts != it.second.start_ts) {
            dprintf(fd, "%" PRIu64, it.second.start_ts);
        }
        dprintf(fd, ",%" PRIu64 "\n", it.first);
        last_ts = it.first;

        if (!debug) {
            dumpUidRecords(fd, it.second.entries);
        } else {
            dumpUidRecordsDebug(fd, it.second.entries);
        }
    }

    if (time_window) {
        storaged_sp->update_uid_io_interval(time_window);
    }

    return OK;
}

binder::Status StoragedService::onUserStarted(int32_t userId) {
    storaged_sp->add_user_ce(userId);
    return binder::Status::ok();
}

binder::Status StoragedService::onUserStopped(int32_t userId) {
    storaged_sp->remove_user_ce(userId);
    return binder::Status::ok();
}

binder::Status StoragedService::getRecentPerf(int32_t* _aidl_return) {
    uint32_t recent_perf = storaged_sp->get_recent_perf();
    if (recent_perf > INT32_MAX) {
        *_aidl_return = INT32_MAX;
    } else {
        *_aidl_return = static_cast<int32_t>(recent_perf);
    }
    return binder::Status::ok();
}

status_t StoragedPrivateService::start() {
    return BinderService<StoragedPrivateService>::publish();
}

binder::Status StoragedPrivateService::dumpUids(
        vector<::android::os::storaged::UidInfo>* _aidl_return) {
    unordered_map<uint32_t, uid_info> uids_m = storaged_sp->get_uids();

    for (const auto& it : uids_m) {
        UidInfo uinfo;
        uinfo.uid = it.second.uid;
        uinfo.name = it.second.name;
        uinfo.tasks = it.second.tasks;
        memcpy(&uinfo.io, &it.second.io, sizeof(uinfo.io));
        _aidl_return->push_back(uinfo);
    }
    return binder::Status::ok();
}

binder::Status StoragedPrivateService::dumpPerfHistory(
        vector<int32_t>* _aidl_return) {
    *_aidl_return = storaged_sp->get_perf_history();
    return binder::Status::ok();
}

sp<IStoragedPrivate> get_storaged_pri_service() {
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == NULL) return NULL;

    sp<IBinder> binder = sm->getService(String16("storaged_pri"));
    if (binder == NULL) return NULL;

    return interface_cast<IStoragedPrivate>(binder);
}
