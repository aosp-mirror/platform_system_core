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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <chrono>
#include <fstream>
#include <sstream>
#include <string>

#include <android-base/logging.h>
#include <batteryservice/BatteryServiceConstants.h>
#include <batteryservice/IBatteryPropertiesRegistrar.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>
#include <log/log.h>

#include <storaged.h>
#include <storaged_utils.h>

using namespace android::base;
using namespace chrono;
using namespace google::protobuf::io;
using namespace storaged_proto;

namespace {

const uint32_t benchmark_unit_size = 16 * 1024;  // 16KB

}

const uint32_t storaged_t::crc_init = 0x5108A4ED; /* STORAGED */
const std::string storaged_t::proto_file =
    "/data/misc/storaged/storaged.proto";

sp<IBatteryPropertiesRegistrar> get_battery_properties_service() {
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == NULL) return NULL;

    sp<IBinder> binder = sm->getService(String16("batteryproperties"));
    if (binder == NULL) return NULL;

    sp<IBatteryPropertiesRegistrar> battery_properties =
        interface_cast<IBatteryPropertiesRegistrar>(binder);

    return battery_properties;
}

inline charger_stat_t is_charger_on(int64_t prop) {
    return (prop == BATTERY_STATUS_CHARGING || prop == BATTERY_STATUS_FULL) ?
        CHARGER_ON : CHARGER_OFF;
}

void storaged_t::batteryPropertiesChanged(struct BatteryProperties props) {
    mUidm.set_charger_state(is_charger_on(props.batteryStatus));
}

void storaged_t::init_battery_service() {
    if (!mUidm.enabled())
        return;

    battery_properties = get_battery_properties_service();
    if (battery_properties == NULL) {
        LOG_TO(SYSTEM, WARNING) << "failed to find batteryproperties service";
        return;
    }

    struct BatteryProperty val;
    battery_properties->getProperty(BATTERY_PROP_BATTERY_STATUS, &val);
    mUidm.init(is_charger_on(val.valueInt64), proto.uid_io_usage());

    // register listener after init uid_monitor
    battery_properties->registerListener(this);
    IInterface::asBinder(battery_properties)->linkToDeath(this);
}

void storaged_t::binderDied(const wp<IBinder>& who) {
    if (battery_properties != NULL &&
        IInterface::asBinder(battery_properties) == who) {
        LOG_TO(SYSTEM, ERROR) << "batteryproperties service died, exiting";
        IPCThreadState::self()->stopProcess();
        exit(1);
    } else {
        LOG_TO(SYSTEM, ERROR) << "unknown service died";
    }
}

void storaged_t::report_storage_info() {
    storage_info->init(proto.perf_history());
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

void storaged_t::load_proto() {
    std::ifstream in(proto_file,
        std::ofstream::in | std::ofstream::binary);

    if (!in.good()) {
        PLOG_TO(SYSTEM, INFO) << "Open " << proto_file << " failed";
        return;
    }

    stringstream ss;
    ss << in.rdbuf();
    proto.ParseFromString(ss.str());

    uint32_t crc = proto.crc();
    proto.set_crc(crc_init);
    std::string proto_str = proto.SerializeAsString();
    uint32_t computed_crc = crc32(crc_init,
        reinterpret_cast<const Bytef*>(proto_str.c_str()),
        proto_str.size());

    if (crc != computed_crc) {
        LOG_TO(SYSTEM, WARNING) << "CRC mismatch in " << proto_file;
        proto.Clear();
    }
}

void storaged_t::flush_proto() {
    proto.set_version(1);
    proto.set_crc(crc_init);
    while (proto.ByteSize() < 128 * 1024) {
        proto.add_padding(0xFEEDBABE);
    }
    std::string proto_str = proto.SerializeAsString();
    proto.set_crc(crc32(crc_init,
        reinterpret_cast<const Bytef*>(proto_str.c_str()),
        proto_str.size()));
    proto_str = proto.SerializeAsString();

    const char* data = proto_str.data();
    uint32_t size = proto_str.size();
    ssize_t ret;
    time_point<steady_clock> start, end;

    std::string tmp_file = proto_file + "_tmp";
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

void storaged_t::event(void) {
    if (mDsm.enabled()) {
        mDsm.update();
        if (!(mTimer % mConfig.periodic_chores_interval_disk_stats_publish)) {
            mDsm.publish();
        }
    }

    if (mUidm.enabled() &&
        !(mTimer % mConfig.periodic_chores_interval_uid_io)) {
        mUidm.report(proto.mutable_uid_io_usage());
    }

    storage_info->refresh(proto.mutable_perf_history());

    if (!(mTimer % mConfig.periodic_chores_interval_flush_proto)) {
        flush_proto();
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
