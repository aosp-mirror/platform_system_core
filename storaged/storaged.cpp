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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <batteryservice/BatteryServiceConstants.h>
#include <cutils/properties.h>
#include <healthhalutils/HealthHalUtils.h>
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

constexpr ssize_t benchmark_unit_size = 16 * 1024;  // 16KB

constexpr ssize_t min_benchmark_size = 128 * 1024;  // 128KB

}  // namespace

const uint32_t storaged_t::current_version = 4;

using android::hardware::interfacesEqual;
using android::hardware::Return;
using android::hardware::health::V1_0::BatteryStatus;
using android::hardware::health::V1_0::HealthInfo;
using android::hardware::health::V1_0::toString;
using android::hardware::health::V2_0::get_health_service;
using android::hardware::health::V2_0::IHealth;
using android::hardware::health::V2_0::Result;
using android::hidl::manager::V1_0::IServiceManager;


inline charger_stat_t is_charger_on(BatteryStatus prop) {
    return (prop == BatteryStatus::CHARGING || prop == BatteryStatus::FULL) ?
        CHARGER_ON : CHARGER_OFF;
}

Return<void> storaged_t::healthInfoChanged(const HealthInfo& props) {
    mUidm.set_charger_state(is_charger_on(props.batteryStatus));
    return android::hardware::Void();
}

void storaged_t::init() {
    init_health_service();
    mDsm = std::make_unique<disk_stats_monitor>(health);
    storage_info.reset(storage_info_t::get_storage_info(health));
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

    mStarttime = time(NULL);
    mTimer = 0;
}

void storaged_t::add_user_ce(userid_t user_id) {
    load_proto(user_id);
    proto_loaded[user_id] = true;
}

void storaged_t::remove_user_ce(userid_t user_id) {
    proto_loaded[user_id] = false;
    mUidm.clear_user_history(user_id);
    RemoveFileIfExists(proto_path(user_id), nullptr);
}

void storaged_t::load_proto(userid_t user_id) {
    string proto_file = proto_path(user_id);
    ifstream in(proto_file, ofstream::in | ofstream::binary);

    if (!in.good()) return;

    stringstream ss;
    ss << in.rdbuf();
    StoragedProto proto;
    proto.ParseFromString(ss.str());

    const UidIOUsage& uid_io_usage = proto.uid_io_usage();
    uint32_t computed_crc = crc32(current_version,
        reinterpret_cast<const Bytef*>(uid_io_usage.SerializeAsString().c_str()),
        uid_io_usage.ByteSize());
    if (proto.crc() != computed_crc) {
        LOG_TO(SYSTEM, WARNING) << "CRC mismatch in " << proto_file;
        return;
    }

    mUidm.load_uid_io_proto(proto.uid_io_usage());

    if (user_id == USER_SYSTEM) {
        storage_info->load_perf_history_proto(proto.perf_history());
    }
}

char* storaged_t:: prepare_proto(userid_t user_id, StoragedProto* proto) {
    proto->set_version(current_version);

    const UidIOUsage& uid_io_usage = proto->uid_io_usage();
    proto->set_crc(crc32(current_version,
        reinterpret_cast<const Bytef*>(uid_io_usage.SerializeAsString().c_str()),
        uid_io_usage.ByteSize()));

    uint32_t pagesize = sysconf(_SC_PAGESIZE);
    if (user_id == USER_SYSTEM) {
        proto->set_padding("", 1);
        vector<char> padding;
        ssize_t size = ROUND_UP(MAX(min_benchmark_size, proto->ByteSize()),
                                pagesize);
        padding = vector<char>(size - proto->ByteSize(), 0xFD);
        proto->set_padding(padding.data(), padding.size());
        while (!IS_ALIGNED(proto->ByteSize(), pagesize)) {
            padding.push_back(0xFD);
            proto->set_padding(padding.data(), padding.size());
        }
    }

    char* data = nullptr;
    if (posix_memalign(reinterpret_cast<void**>(&data),
                       pagesize, proto->ByteSize())) {
        PLOG_TO(SYSTEM, ERROR) << "Faied to alloc aligned buffer (size: "
                               << proto->ByteSize() << ")";
        return data;
    }

    proto->SerializeToArray(data, proto->ByteSize());
    return data;
}

void storaged_t::flush_proto_data(userid_t user_id,
                                  const char* data, ssize_t size) {
    string proto_file = proto_path(user_id);
    string tmp_file = proto_file + "_tmp";
    unique_fd fd(TEMP_FAILURE_RETRY(open(tmp_file.c_str(),
                 O_SYNC | O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC |
                    (user_id == USER_SYSTEM ? O_DIRECT : 0),
                 S_IRUSR | S_IWUSR)));
    if (fd == -1) {
        PLOG_TO(SYSTEM, ERROR) << "Faied to open tmp file: " << tmp_file;
        return;
    }

    if (user_id == USER_SYSTEM) {
        time_point<steady_clock> start, end;
        uint32_t benchmark_size = 0;
        uint64_t benchmark_time_ns = 0;
        ssize_t ret;
        bool first_write = true;

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
            if (!first_write && ret == benchmark_unit_size) {
                benchmark_size += benchmark_unit_size;
                benchmark_time_ns += duration_cast<nanoseconds>(end - start).count();
            }
            size -= ret;
            data += ret;
            first_write = false;
        }

        if (benchmark_size) {
            int perf = benchmark_size * 1000000LLU / benchmark_time_ns;
            storage_info->update_perf_history(perf, system_clock::now());
        }
    } else {
        if (!WriteFully(fd, data, size)) {
            PLOG_TO(SYSTEM, ERROR) << "Faied to write tmp file: " << tmp_file;
            return;
        }
    }

    fd.reset(-1);
    rename(tmp_file.c_str(), proto_file.c_str());
}

void storaged_t::flush_proto(userid_t user_id, StoragedProto* proto) {
    unique_ptr<char> proto_data(prepare_proto(user_id, proto));
    if (proto_data == nullptr) return;

    flush_proto_data(user_id, proto_data.get(), proto->ByteSize());
}

void storaged_t::flush_protos(unordered_map<int, StoragedProto>* protos) {
    for (auto& it : *protos) {
        /*
         * Don't flush proto if we haven't attempted to load it from file.
         */
        if (proto_loaded[it.first]) {
            flush_proto(it.first, &it.second);
        }
    }
}

void storaged_t::event(void) {
    unordered_map<int, StoragedProto> protos;

    if (mDsm->enabled()) {
        mDsm->update();
        if (!(mTimer % mConfig.periodic_chores_interval_disk_stats_publish)) {
            mDsm->publish();
        }
    }

    if (!(mTimer % mConfig.periodic_chores_interval_uid_io)) {
        mUidm.report(&protos);
    }

    if (storage_info) {
        storage_info->refresh(protos[USER_SYSTEM].mutable_perf_history());
    }

    if (!(mTimer % mConfig.periodic_chores_interval_flush_proto)) {
        flush_protos(&protos);
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
