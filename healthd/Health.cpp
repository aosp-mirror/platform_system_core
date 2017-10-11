#define LOG_TAG "Health"
#include <android-base/logging.h>

#include <health2/Health.h>

#include <hidl/HidlTransportSupport.h>

extern void healthd_battery_update_internal(bool);

namespace android {
namespace hardware {
namespace health {
namespace V2_0 {
namespace implementation {

Health::Health(struct healthd_config* c) {
    battery_monitor_ = std::make_unique<BatteryMonitor>();
    battery_monitor_->init(c);
}

// Methods from IHealth follow.
Return<Result> Health::registerCallback(const sp<IHealthInfoCallback>& callback) {
    if (callback == nullptr) {
        return Result::SUCCESS;
    }

    {
        std::lock_guard<std::mutex> _lock(callbacks_lock_);
        callbacks_.push_back(callback);
        // unlock
    }

    auto linkRet = callback->linkToDeath(this, 0u /* cookie */);
    if (!linkRet.withDefault(false)) {
        LOG(WARNING) << __func__ << "Cannot link to death: "
                     << (linkRet.isOk() ? "linkToDeath returns false" : linkRet.description());
        // ignore the error
    }

    return update();
}

bool Health::unregisterCallbackInternal(const sp<IBase>& callback) {
    if (callback == nullptr) return false;

    bool removed = false;
    std::lock_guard<std::mutex> _lock(callbacks_lock_);
    for (auto it = callbacks_.begin(); it != callbacks_.end();) {
        if (interfacesEqual(*it, callback)) {
            it = callbacks_.erase(it);
            removed = true;
        } else {
            ++it;
        }
    }
    (void)callback->unlinkToDeath(this).isOk();  // ignore errors
    return removed;
}

Return<Result> Health::unregisterCallback(const sp<IHealthInfoCallback>& callback) {
    return unregisterCallbackInternal(callback) ? Result::SUCCESS : Result::NOT_FOUND;
}

template<typename T>
void getProperty(const std::unique_ptr<BatteryMonitor>& monitor, int id, T defaultValue,
                 const std::function<void(Result, T)>& callback) {
    struct BatteryProperty prop;
    T ret = defaultValue;
    Result result = Result::SUCCESS;
    status_t err = monitor->getProperty(static_cast<int>(id), &prop);
    if (err != OK) {
        LOG(DEBUG) << "getProperty(" << id << ")" << " fails: (" << err << ") " << strerror(-err);
    } else {
        ret = static_cast<T>(prop.valueInt64);
    }
    switch (err) {
        case OK:             result = Result::SUCCESS; break;
        case NAME_NOT_FOUND: result = Result::NOT_SUPPORTED; break;
        default:             result = Result::UNKNOWN; break;
    }
    callback(result, static_cast<T>(ret));
}

Return<void> Health::getChargeCounter(getChargeCounter_cb _hidl_cb) {
    getProperty(battery_monitor_, BATTERY_PROP_CHARGE_COUNTER, INT32_MIN, _hidl_cb);
    return Void();
}

Return<void> Health::getCurrentNow(getCurrentNow_cb _hidl_cb) {
    getProperty(battery_monitor_, BATTERY_PROP_CURRENT_NOW, INT32_MIN, _hidl_cb);
    return Void();
}

Return<void> Health::getCurrentAverage(getCurrentAverage_cb _hidl_cb) {
    getProperty(battery_monitor_, BATTERY_PROP_CURRENT_AVG, INT32_MIN, _hidl_cb);
    return Void();
}

Return<void> Health::getCapacity(getCapacity_cb _hidl_cb) {
    getProperty(battery_monitor_, BATTERY_PROP_CAPACITY, INT32_MIN, _hidl_cb);
    return Void();
}

Return<void> Health::getEnergyCounter(getEnergyCounter_cb _hidl_cb) {
    getProperty(battery_monitor_, BATTERY_PROP_ENERGY_COUNTER, INT64_MIN, _hidl_cb);
    return Void();
}

Return<void> Health::getChargeStatus(getChargeStatus_cb _hidl_cb) {
    getProperty(battery_monitor_, BATTERY_PROP_BATTERY_STATUS, BatteryStatus::UNKNOWN, _hidl_cb);
    return Void();
}


Return<Result> Health::update() {
    if (!healthd_mode_ops || !healthd_mode_ops->battery_update) {
        LOG(WARNING) << "health@2.0: update: not initialized. "
                     << "update() should not be called in charger / recovery.";
        return Result::UNKNOWN;
    }

    // Retrieve all information and call healthd_mode_ops->battery_update, which calls
    // updateAndNotify.
    bool chargerOnline = battery_monitor_->update();

    // adjust uevent / wakealarm periods
    healthd_battery_update_internal(chargerOnline);

    return Result::SUCCESS;
}

void Health::updateAndNotify(HealthInfo* info) {
    // update 2.0 specific fields
    struct BatteryProperty prop;
    if (battery_monitor_->getProperty(BATTERY_PROP_CURRENT_AVG, &prop) == OK)
        info->batteryCurrentAverage = static_cast<int32_t>(prop.valueInt64);
    if (battery_monitor_->getProperty(BATTERY_PROP_CAPACITY, &prop) == OK)
        info->batteryCapacity = static_cast<int32_t>(prop.valueInt64);
    if (battery_monitor_->getProperty(BATTERY_PROP_ENERGY_COUNTER, &prop) == OK)
        info->energyCounter = prop.valueInt64;

    std::lock_guard<std::mutex> _lock(callbacks_lock_);
    for (auto it = callbacks_.begin(); it != callbacks_.end();) {
        auto ret = (*it)->healthInfoChanged(*info);
        if (!ret.isOk() && ret.isDeadObject()) {
            it = callbacks_.erase(it);
        } else {
            ++it;
        }
    }
}

Return<void> Health::debug(const hidl_handle& handle, const hidl_vec<hidl_string>&) {
    if (handle != nullptr && handle->numFds >= 1) {
        int fd = handle->data[0];
        battery_monitor_->dumpState(fd);
        fsync(fd);
    }
    return Void();
}

void Health::serviceDied(uint64_t /* cookie */, const wp<IBase>& who) {
    (void)unregisterCallbackInternal(who.promote());
}

// Methods from ::android::hidl::base::V1_0::IBase follow.

}  // namespace implementation
}  // namespace V2_0
}  // namespace health
}  // namespace hardware
}  // namespace android
