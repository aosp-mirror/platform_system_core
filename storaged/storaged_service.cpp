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
#include <storaged_service.h>

using namespace std;
using namespace android::base;

extern sp<storaged_t> storaged;

vector<struct uid_info> BpStoraged::dump_uids(const char* /*option*/) {
    Parcel data, reply;
    data.writeInterfaceToken(IStoraged::getInterfaceDescriptor());

    remote()->transact(DUMPUIDS, data, &reply);

    uint32_t res_size = reply.readInt32();
    vector<struct uid_info> res(res_size);
    for (auto&& uid : res) {
        uid.uid = reply.readInt32();
        uid.name = reply.readCString();
        reply.read(&uid.io, sizeof(uid.io));

        uint32_t tasks_size = reply.readInt32();
        for (uint32_t i = 0; i < tasks_size; i++) {
            struct task_info task;
            task.pid = reply.readInt32();
            task.comm = reply.readCString();
            reply.read(&task.io, sizeof(task.io));
            uid.tasks[task.pid] = task;
        }
    }
    return res;
}

vector<vector<uint32_t>> BpStoraged::dump_perf_history(const char* /*option*/) {
    Parcel data, reply;
    data.writeInterfaceToken(IStoraged::getInterfaceDescriptor());

    remote()->transact(DUMPPERF, data, &reply);

    vector<vector<uint32_t>> res(3);
    uint32_t size = reply.readUint32();
    res[0].resize(size);
    for (uint32_t i = 0; i < size; i++) {
        res[0][i] = reply.readUint32();
    }
    size = reply.readUint32();
    res[1].resize(size);
    for (uint32_t i = 0; i < size; i++) {
        res[1][i] = reply.readUint32();
    }
    size = reply.readUint32();
    res[2].resize(size);
    for (uint32_t i = 0; i < size; i++) {
        res[2][i] = reply.readUint32();
    }
    return res;
}

IMPLEMENT_META_INTERFACE(Storaged, "Storaged");

status_t BnStoraged::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    switch(code) {
        case DUMPUIDS: {
                if (!data.checkInterface(this))
                    return BAD_TYPE;
                vector<struct uid_info> res = dump_uids(NULL);
                reply->writeInt32(res.size());
                for (const auto& uid : res) {
                    reply->writeInt32(uid.uid);
                    reply->writeCString(uid.name.c_str());
                    reply->write(&uid.io, sizeof(uid.io));

                    reply->writeInt32(uid.tasks.size());
                    for (const auto& task_it : uid.tasks) {
                        reply->writeInt32(task_it.first);
                        reply->writeCString(task_it.second.comm.c_str());
                        reply->write(&task_it.second.io, sizeof(task_it.second.io));
                    }
                }
                return NO_ERROR;
            }
            break;
        case DUMPPERF: {
            if (!data.checkInterface(this))
                return BAD_TYPE;
            vector<vector<uint32_t>> res = dump_perf_history(NULL);
            reply->writeUint32(res[0].size());
            for (const auto& item : res[0]) {
                reply->writeUint32(item);
            }
            reply->writeUint32(res[1].size());
            for (const auto& item : res[1]) {
                reply->writeUint32(item);
            }
            reply->writeUint32(res[2].size());
            for (const auto& item : res[2]) {
                reply->writeUint32(item);
            }
            return NO_ERROR;
        }
        break;
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

vector<struct uid_info> Storaged::dump_uids(const char* /* option */) {
    vector<struct uid_info> uids_v;
    unordered_map<uint32_t, struct uid_info> uids_m = storaged->get_uids();

    for (const auto& it : uids_m) {
        uids_v.push_back(it.second);
    }
    return uids_v;
}

vector<vector<uint32_t>> Storaged::dump_perf_history(const char* /* option */) {
    return storaged->get_perf_history();
}

status_t Storaged::dump(int fd, const Vector<String16>& args) {
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
    const map<uint64_t, struct uid_records>& records =
                storaged->get_uid_records(hours, threshold, force_report);
    for (const auto& it : records) {
        if (last_ts != it.second.start_ts) {
            dprintf(fd, "%" PRIu64, it.second.start_ts);
        }
        dprintf(fd, ",%" PRIu64 "\n", it.first);
        last_ts = it.first;

        for (const auto& record : it.second.entries) {
            const struct io_usage& uid_usage = record.ios.uid_ios;
            dprintf(fd, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                    " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                record.name.c_str(),
                uid_usage.bytes[READ][FOREGROUND][CHARGER_OFF],
                uid_usage.bytes[WRITE][FOREGROUND][CHARGER_OFF],
                uid_usage.bytes[READ][BACKGROUND][CHARGER_OFF],
                uid_usage.bytes[WRITE][BACKGROUND][CHARGER_OFF],
                uid_usage.bytes[READ][FOREGROUND][CHARGER_ON],
                uid_usage.bytes[WRITE][FOREGROUND][CHARGER_ON],
                uid_usage.bytes[READ][BACKGROUND][CHARGER_ON],
                uid_usage.bytes[WRITE][BACKGROUND][CHARGER_ON]);
            if (debug) {
                for (const auto& task_it : record.ios.task_ios) {
                    const struct io_usage& task_usage = task_it.second;
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
    }

    if (time_window) {
        storaged->update_uid_io_interval(time_window);
    }

    return NO_ERROR;
}

sp<IStoraged> get_storaged_service() {
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == NULL) return NULL;

    sp<IBinder> binder = sm->getService(String16("storaged"));
    if (binder == NULL) return NULL;

    sp<IStoraged> storaged = interface_cast<IStoraged>(binder);

    return storaged;
}
