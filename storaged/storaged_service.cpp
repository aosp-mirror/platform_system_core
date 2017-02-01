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

#include <stdint.h>

#include <vector>

#include <binder/IBinder.h>
#include <binder/IInterface.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <private/android_filesystem_config.h>

#include <storaged.h>
#include <storaged_service.h>

extern storaged_t storaged;

std::vector<struct uid_info> BpStoraged::dump_uids(const char* /*option*/) {
    Parcel data, reply;
    data.writeInterfaceToken(IStoraged::getInterfaceDescriptor());

    remote()->transact(DUMPUIDS, data, &reply);

    uint32_t res_size = reply.readInt32();
    std::vector<struct uid_info> res(res_size);
    for (auto&& uid : res) {
        uid.uid = reply.readInt32();
        uid.name = reply.readCString();
        reply.read(&uid.io, sizeof(uid.io));
    }
    return res;
}
IMPLEMENT_META_INTERFACE(Storaged, "Storaged");

status_t BnStoraged::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    switch(code) {
        case DUMPUIDS: {
                if (!data.checkInterface(this))
                    return BAD_TYPE;
                std::vector<struct uid_info> res = dump_uids(NULL);
                reply->writeInt32(res.size());
                for (auto uid : res) {
                    reply->writeInt32(uid.uid);
                    reply->writeCString(uid.name.c_str());
                    reply->write(&uid.io, sizeof(uid.io));
                }
                return NO_ERROR;
            }
            break;
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

std::vector<struct uid_info> Storaged::dump_uids(const char* /* option */) {
    std::vector<struct uid_info> uids_v;
    std::unordered_map<uint32_t, struct uid_info> uids_m = storaged.get_uids();

    for (const auto& it : uids_m) {
        uids_v.push_back(it.second);
    }
    return uids_v;
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

    int hours = 0;
    for (size_t i = 0; i < args.size(); i++) {
        const auto& arg = args[i];
        if (arg == String16("--hours")) {
            if (++i >= args.size())
                break;
            hours = stoi(String16::std_string(args[i]));
            continue;
        }
    }

    const std::vector<struct uid_event>& events = storaged.get_uid_events(hours);
    for (const auto& event : events) {
        dprintf(fd, "%llu %s %llu %llu %llu %llu\n",
            (unsigned long long)event.ts,
            event.name.c_str(),
            (unsigned long long)event.fg_read_bytes,
            (unsigned long long)event.fg_write_bytes,
            (unsigned long long)event.bg_read_bytes,
            (unsigned long long)event.bg_write_bytes);
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
