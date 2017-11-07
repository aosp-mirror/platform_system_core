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

#define LOG_TAG "storaged"

#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <chrono>
#include <fstream>
#include <sstream>
#include <string>

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <batteryservice/BatteryServiceConstants.h>
#include <cutils/properties.h>
#include <hidl/HidlTransportSupport.h>
#include <hwbinder/IPCThreadState.h>
#include <log/log.h>

#include <storaged.h>
#include <storaged_utils.h>

using namespace android::base;
using namespace chrono;
using namespace google::protobuf::io;
using namespace storaged_proto;

namespace {

/*
 * The system user is the initial user that is implicitly created on first boot
 * and hosts most of the system services. Keep this in sync with
 * frameworks/base/core/java/android/os/UserManager.java
 */
constexpr int USER_SYSTEM = 0;

constexpr uint32_t benchmark_unit_size = 16 * 1024;  // 16KB

}  // namespace

const uint32_t storaged_t::crc_init = 0x5108A4ED; /* STORAGED */

using android::hardware::health::V1_0::BatteryStatus;
using android::hardware::health::V1_0::toString;
using android::hardware::health::V2_0::HealthInfo;
using android::hardware::health::V2_0::IHealth;
using android::hardware::health::V2_0::Result;
using android::hardware::interfacesEqual;
using android::hardware::Return;
using android::hidl::manager::V1_0::IServiceManager;

static sp<IHealth> get_health_service() {
    for (auto&& instanceName : {"default", "backup"}) {
        auto ret = IHealth::getService(instanceName);
        if (ret != nullptr) {
            return ret;
        }
        LOG_TO(SYSTEM, INFO) << "health: storaged: cannot get " << instanceName << " service";
    }
    return nullptr;
}

inline charger_stat_t is_charger_on(BatteryStatus prop) {
    return (prop == BatteryStatus::CHARGING || prop == BatteryStatus::FULL) ?
        CHARGER_ON : CHARGER_OFF;
}

Return<void> storaged_t::healthInfoChanged(const HealthInfo& props) {
    mUidm.set_charger_state(is_charger_on(props.legacy.batteryStatus));
    return android::hardware::Void();
}

void storaged_t::init_health_service() {
    if (!mUidm.enabled())
        return;

    health = get_health_service();
    if (health == NULL) {
        LOG_TO(SYSTEM, WARNING) << "health: failed to find IHealth service";
        return;
    }

    BatteryStatus status = BatteryStatus::UNKNOWN;
    auto ret = health->getChargeStatus([&](Result r, BatteryStatus v) {
        if (r != Result::SUCCESS) {
            LOG_TO(SYSTEM, WARNING)
                << "health: cannot get battery status " << toString(r);
            return;
        }
        if (v == BatteryStatus::UNKNOWN) {
            LOG_TO(SYSTEM, WARNING) << "health: invalid battery status";
        }
        status = v;
    });
    if (!ret.isOk()) {
        LOG_TO(SYSTEM, WARNING) << "health: get charge status transaction error "
            << ret.description();
    }

    mUidm.init(is_charger_on(status));
    // register listener after init uid_monitor
    health->registerCallback(this);
    health->linkToDeath(this, 0 /* cookie */);
}

void storaged_t::serviceDied(uint64_t cookie, const wp<::android::hidl::base::V1_0::IBase>& who) {
    if (health != NULL && interfacesEqual(health, who.promote())) {
        LOG_TO(SYSTEM, ERROR) << "health service died, exiting";
        android::hardware::IPCThreadState::self()->stopProcess();
        exit(1);
    } else {
        LOG_TO(SYSTEM, ERROR) << "unknown service died";
    }
}

void storaged_t::report_storage_info() {
    storage_info->report();
}

/* storaged_t */
storaged_t::storaged_t(void) {
    mConfig.periodic_chores_interval_unit =
        property_get_int32("ro.storaged.event.interval",
                           DEFAULT_PERIODIC_CHORES_INTERVAL_UNIT);

    mConfig.event_time_check_usec =
        property_get_int32("ro.storaged.event.perf_check", 0);

    mConfig.periodic_chores_interval_disk_stats_publish =
        property_get_int32("ro.storaged.disk_stats_pub",
                           DEFAULT_PERIODIC_CHORES_INTERVAL_DISK_STATS_PUBLISH);

    mConfig.periodic_chores_interval_uid_io =
        property_get_int32("ro.storaged.uid_io.interval",
                           DEFAULT_PERIODIC_CHORES_INTERVAL_UID_IO);

    mConfig.periodic_chores_interval_flush_proto =
        property_get_int32("ro.storaged.flush_proto.interval",
                           DEFAULT_PERIODIC_CHORES_INTERVAL_FLUSH_PROTO);

    storage_info.reset(storage_info_t::get_storage_info());

    mStarttime = time(NULL);
    mTimer = 0;
}

void storaged_t::add_user_ce(userid_t user_id) {
    Mutex::Autolock _l(proto_mutex);
    protos.insert({user_id, {}});
    load_proto_locked(user_id);
    protos[user_id].set_loaded(1);
}

void storaged_t::remove_user_ce(userid_t user_id) {
    Mutex::Autolock _l(proto_mutex);
    protos.erase(user_id);
    RemoveFileIfExists(proto_path(user_id), nullptr);
}

void storaged_t::load_proto_locked(userid_t user_id) {
    string proto_file = proto_path(user_id);
    ifstream in(proto_file, ofstream::in | ofstream::binary);

    if (!in.good()) return;

    stringstream ss;
    ss << in.rdbuf();
    StoragedProto* proto = &protos[user_id];
    proto->Clear();
    proto->ParseFromString(ss.str());

    uint32_t crc = proto->crc();
    proto->set_crc(crc_init);
    string proto_str = proto->SerializeAsString();
    uint32_t computed_crc = crc32(crc_init,
        reinterpret_cast<const Bytef*>(proto_str.c_str()),
        proto_str.size());

    if (crc != computed_crc) {
        LOG_TO(SYSTEM, WARNING) << "CRC mismatch in " << proto_file;
        proto->Clear();
        return;
    }

    mUidm.load_uid_io_proto(proto->uid_io_usage());

    if (user_id == USER_SYSTEM) {
        storage_info->load_perf_history_proto(proto->perf_history());
    }
}

void storaged_t:: prepare_proto(StoragedProto* proto, userid_t user_id) {
    proto->set_version(2);
    proto->set_crc(crc_init);

    if (user_id == USER_SYSTEM) {
        while (proto->ByteSize() < 128 * 1024) {
            proto->add_padding(0xFEEDBABE);
        }
    }

    string proto_str = proto->SerializeAsString();
    proto->set_crc(crc32(crc_init,
        reinterpret_cast<const Bytef*>(proto_str.c_str()),
        proto_str.size()));
}

void storaged_t::flush_proto_user_system_locked(StoragedProto* proto) {
    string proto_str = proto->SerializeAsString();
    const char* data = proto_str.data();
    uint32_t size = proto_str.size();
    ssize_t ret;
    time_point<steady_clock> start, end;

    string proto_file = proto_path(USER_SYSTEM);
    string tmp_file = proto_file + "_tmp";
    unique_fd fd(TEMP_FAILURE_RETRY(open(tmp_file.c_str(),
                O_DIRECT | O_SYNC | O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
                S_IRUSR | S_IWUSR)));
    if (fd == -1) {
        PLOG_TO(SYSTEM, ERROR) << "Faied to open tmp file: " << tmp_file;
        return;
    }

    uint32_t benchmark_size = 0;
    uint64_t benchmark_time_ns = 0;
    while (size > 0) {
        start = steady_clock::now();
        ret = write(fd, data, MIN(benchmark_unit_size, size));
        if (ret <= 0) {
            PLOG_TO(SYSTEM, ERROR) << "Faied to write tmp file: " << tmp_file;
            return;
        }
        end = steady_clock::now();
        /*
         * compute bandwidth after the first write and if write returns
         * exactly unit size.
         */
        if (size != proto_str.size() && ret == benchmark_unit_size) {
            benchmark_size += benchmark_unit_size;
            benchmark_time_ns += duration_cast<nanoseconds>(end - start).count();
        }
        size -= ret;
        data += ret;
    }

    if (benchmark_size) {
        int perf = benchmark_size * 1000000LLU / benchmark_time_ns;
        storage_info->update_perf_history(perf, system_clock::now());
    }

    fd.reset(-1);
    /* Atomically replace existing proto file to reduce chance of data loss. */
    rename(tmp_file.c_str(), proto_file.c_str());
}

void storaged_t::flush_proto_locked(userid_t user_id) {
    StoragedProto* proto = &protos[user_id];
    prepare_proto(proto, user_id);
    if (user_id == USER_SYSTEM) {
        flush_proto_user_system_locked(proto);
        return;
    }

    string proto_file = proto_path(user_id);
    string tmp_file = proto_file + "_tmp";
    if (!WriteStringToFile(proto->SerializeAsString(), tmp_file,
                           S_IRUSR | S_IWUSR)) {
        return;
    }

    /* Atomically replace existing proto file to reduce chance of data loss. */
    rename(tmp_file.c_str(), proto_file.c_str());
}

void storaged_t::flush_protos() {
    Mutex::Autolock _l(proto_mutex);
    for (const auto& it : protos) {
        /*
         * Don't flush proto if we haven't loaded it from file and combined
         * with data in memory.
         */
        if (it.second.loaded() != 1) {
            continue;
        }
        flush_proto_locked(it.first);
    }
}

void storaged_t::event(void) {
    if (mDsm.enabled()) {
        mDsm.update();
        if (!(mTimer % mConfig.periodic_chores_interval_disk_stats_publish)) {
            mDsm.publish();
        }
    }

    if (!(mTimer % mConfig.periodic_chores_interval_uid_io)) {
        Mutex::Autolock _l(proto_mutex);
        mUidm.report(&protos);
    }

    if (storage_info) {
        Mutex::Autolock _l(proto_mutex);
        storage_info->refresh(protos[USER_SYSTEM].mutable_perf_history());
    }

    if (!(mTimer % mConfig.periodic_chores_interval_flush_proto)) {
        flush_protos();
    }

    mTimer += mConfig.periodic_chores_interval_unit;
}

void storaged_t::event_checked(void) {
    struct timespec start_ts, end_ts;
    bool check_time = true;

    if (mConfig.event_time_check_usec &&
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_ts) < 0) {
        check_time = false;
        static time_t state_a;
        IF_ALOG_RATELIMIT_LOCAL(300, &state_a) {
            PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        }
    }

    event();

    if (mConfig.event_time_check_usec && check_time) {
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_ts) < 0) {
            static time_t state_b;
            IF_ALOG_RATELIMIT_LOCAL(300, &state_b) {
                PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
            }
            return;
        }
        int64_t cost = (end_ts.tv_sec - start_ts.tv_sec) * SEC_TO_USEC +
                       (end_ts.tv_nsec - start_ts.tv_nsec) / USEC_TO_NSEC;
        if (cost > mConfig.event_time_check_usec) {
            LOG_TO(SYSTEM, ERROR)
                << "event loop spent " << cost << " usec, threshold "
                << mConfig.event_time_check_usec << " usec";
        }
    }
}
