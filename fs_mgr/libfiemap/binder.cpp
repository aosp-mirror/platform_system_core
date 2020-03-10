//
// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#if !defined(__ANDROID_RECOVERY__)
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/gsi/BnProgressCallback.h>
#include <android/gsi/IGsiService.h>
#include <binder/IServiceManager.h>
#include <libfiemap/image_manager.h>
#include <libgsi/libgsi.h>

namespace android {
namespace fiemap {

using namespace android::gsi;
using namespace std::chrono_literals;

class ProgressCallback final : public BnProgressCallback {
  public:
    ProgressCallback(std::function<bool(uint64_t, uint64_t)>&& callback)
        : callback_(std::move(callback)) {
        CHECK(callback_);
    }
    android::binder::Status onProgress(int64_t current, int64_t total) {
        if (callback_(static_cast<uint64_t>(current), static_cast<uint64_t>(total))) {
            return android::binder::Status::ok();
        }
        return android::binder::Status::fromServiceSpecificError(UNKNOWN_ERROR,
                                                                 "Progress callback failed");
    }

  private:
    std::function<bool(uint64_t, uint64_t)> callback_;
};

class ImageManagerBinder final : public IImageManager {
  public:
    ImageManagerBinder(android::sp<IGsiService>&& service, android::sp<IImageService>&& manager);
    FiemapStatus CreateBackingImage(const std::string& name, uint64_t size, int flags,
                                    std::function<bool(uint64_t, uint64_t)>&& on_progress) override;
    bool DeleteBackingImage(const std::string& name) override;
    bool MapImageDevice(const std::string& name, const std::chrono::milliseconds& timeout_ms,
                        std::string* path) override;
    bool UnmapImageDevice(const std::string& name) override;
    bool BackingImageExists(const std::string& name) override;
    bool IsImageMapped(const std::string& name) override;
    bool MapImageWithDeviceMapper(const IPartitionOpener& opener, const std::string& name,
                                  std::string* dev) override;
    FiemapStatus ZeroFillNewImage(const std::string& name, uint64_t bytes) override;
    bool RemoveAllImages() override;
    bool DisableImage(const std::string& name) override;
    bool RemoveDisabledImages() override;
    bool GetMappedImageDevice(const std::string& name, std::string* device) override;
    bool MapAllImages(const std::function<bool(std::set<std::string>)>& init) override;

    std::vector<std::string> GetAllBackingImages() override;

  private:
    android::sp<IGsiService> service_;
    android::sp<IImageService> manager_;
};

static FiemapStatus ToFiemapStatus(const char* func, const binder::Status& status) {
    if (!status.isOk()) {
        LOG(ERROR) << func << " binder returned: " << status.toString8().string();
        if (status.serviceSpecificErrorCode() != 0) {
            return FiemapStatus::FromErrorCode(status.serviceSpecificErrorCode());
        } else {
            return FiemapStatus::Error();
        }
    }
    return FiemapStatus::Ok();
}

ImageManagerBinder::ImageManagerBinder(android::sp<IGsiService>&& service,
                                       android::sp<IImageService>&& manager)
    : service_(std::move(service)), manager_(std::move(manager)) {}

FiemapStatus ImageManagerBinder::CreateBackingImage(
        const std::string& name, uint64_t size, int flags,
        std::function<bool(uint64_t, uint64_t)>&& on_progress) {
    sp<IProgressCallback> callback = nullptr;
    if (on_progress) {
        callback = new ProgressCallback(std::move(on_progress));
    }
    auto status = manager_->createBackingImage(name, size, flags, callback);
    return ToFiemapStatus(__PRETTY_FUNCTION__, status);
}

bool ImageManagerBinder::DeleteBackingImage(const std::string& name) {
    auto status = manager_->deleteBackingImage(name);
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    return true;
}

bool ImageManagerBinder::MapImageDevice(const std::string& name,
                                        const std::chrono::milliseconds& timeout_ms,
                                        std::string* path) {
    int32_t timeout_ms_count =
            static_cast<int32_t>(std::clamp<typename std::chrono::milliseconds::rep>(
                    timeout_ms.count(), INT32_MIN, INT32_MAX));
    MappedImage map;
    auto status = manager_->mapImageDevice(name, timeout_ms_count, &map);
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    *path = map.path;
    return true;
}

bool ImageManagerBinder::UnmapImageDevice(const std::string& name) {
    auto status = manager_->unmapImageDevice(name);
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    return true;
}

bool ImageManagerBinder::BackingImageExists(const std::string& name) {
    bool retval;
    auto status = manager_->backingImageExists(name, &retval);
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    return retval;
}

bool ImageManagerBinder::IsImageMapped(const std::string& name) {
    bool retval;
    auto status = manager_->isImageMapped(name, &retval);
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    return retval;
}

bool ImageManagerBinder::MapImageWithDeviceMapper(const IPartitionOpener& opener,
                                                  const std::string& name, std::string* dev) {
    (void)opener;
    (void)name;
    (void)dev;
    LOG(ERROR) << "MapImageWithDeviceMapper is not available over binder.";
    return false;
}

std::vector<std::string> ImageManagerBinder::GetAllBackingImages() {
    std::vector<std::string> retval;
    auto status = manager_->getAllBackingImages(&retval);
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
    }
    return retval;
}

FiemapStatus ImageManagerBinder::ZeroFillNewImage(const std::string& name, uint64_t bytes) {
    auto status = manager_->zeroFillNewImage(name, bytes);
    return ToFiemapStatus(__PRETTY_FUNCTION__, status);
}

bool ImageManagerBinder::RemoveAllImages() {
    auto status = manager_->removeAllImages();
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    return true;
}

bool ImageManagerBinder::DisableImage(const std::string&) {
    LOG(ERROR) << __PRETTY_FUNCTION__ << " is not available over binder";
    return false;
}

bool ImageManagerBinder::RemoveDisabledImages() {
    auto status = manager_->removeDisabledImages();
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    return true;
}

bool ImageManagerBinder::GetMappedImageDevice(const std::string& name, std::string* device) {
    auto status = manager_->getMappedImageDevice(name, device);
    if (!status.isOk()) {
        LOG(ERROR) << __PRETTY_FUNCTION__
                   << " binder returned: " << status.exceptionMessage().string();
        return false;
    }
    return !device->empty();
}

bool ImageManagerBinder::MapAllImages(const std::function<bool(std::set<std::string>)>&) {
    LOG(ERROR) << __PRETTY_FUNCTION__ << " not available over binder";
    return false;
}

static sp<IGsiService> GetGsiService() {
    auto sm = android::defaultServiceManager();
    auto name = android::String16(kGsiServiceName);
    android::sp<android::IBinder> res = sm->waitForService(name);
    if (res) {
        return android::interface_cast<IGsiService>(res);
    }
    return nullptr;
}

std::unique_ptr<IImageManager> IImageManager::Open(
        const std::string& dir, const std::chrono::milliseconds& /*timeout_ms*/) {
    android::sp<IGsiService> service = GetGsiService();
    android::sp<IImageService> manager;

    auto status = service->openImageService(dir, &manager);
    if (!status.isOk() || !manager) {
        LOG(ERROR) << "Could not acquire IImageManager: " << status.exceptionMessage().string();
        return nullptr;
    }
    return std::make_unique<ImageManagerBinder>(std::move(service), std::move(manager));
}

}  // namespace fiemap
}  // namespace android

#endif  // __ANDROID_RECOVERY__
