#ifndef ANDROID_HARDWARE_HEALTH_V2_0_HEALTH_H
#define ANDROID_HARDWARE_HEALTH_V2_0_HEALTH_H

#include <memory>
#include <vector>

#include <android/hardware/health/1.0/types.h>
#include <android/hardware/health/2.0/IHealth.h>
#include <healthd/BatteryMonitor.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace health {
namespace V2_0 {
namespace implementation {

using V1_0::BatteryStatus;
using V1_0::HealthInfo;

using ::android::hidl::base::V1_0::IBase;

struct Health : public IHealth, hidl_death_recipient {
  public:
    Health(struct healthd_config* c);

    // TODO(b/62229583): clean up and hide these functions.
    void notifyListeners(const HealthInfo& info);

    // Methods from IHealth follow.
    Return<Result> registerCallback(const sp<IHealthInfoCallback>& callback) override;
    Return<Result> unregisterCallback(const sp<IHealthInfoCallback>& callback) override;
    Return<Result> update() override;
    Return<void> getChargeCounter(getChargeCounter_cb _hidl_cb) override;
    Return<void> getCurrentNow(getCurrentNow_cb _hidl_cb) override;
    Return<void> getCurrentAverage(getCurrentAverage_cb _hidl_cb) override;
    Return<void> getCapacity(getCapacity_cb _hidl_cb) override;
    Return<void> getEnergyCounter(getEnergyCounter_cb _hidl_cb) override;
    Return<void> getChargeStatus(getChargeStatus_cb _hidl_cb) override;

    // Methods from ::android::hidl::base::V1_0::IBase follow.
    Return<void> debug(const hidl_handle& fd, const hidl_vec<hidl_string>& args) override;

    void serviceDied(uint64_t cookie, const wp<IBase>& /* who */) override;

  private:
    std::mutex callbacks_lock_;
    std::vector<sp<IHealthInfoCallback>> callbacks_;
    std::unique_ptr<BatteryMonitor> battery_monitor_;

    bool unregisterCallbackInternal(const sp<IBase>& cb);

};

}  // namespace implementation
}  // namespace V2_0
}  // namespace health
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_HEALTH_V2_0_HEALTH_H
