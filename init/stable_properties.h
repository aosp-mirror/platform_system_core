/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef _INIT_STABLE_PROPERTIES_H
#define _INIT_STABLE_PROPERTIES_H

#include <set>
#include <string>

namespace android {
namespace init {

static constexpr const char* kPartnerPrefixes[] = {
    "init.svc.vendor.", "ro.vendor.", "persist.vendor.", "vendor.", "init.svc.odm.", "ro.odm.",
    "persist.odm.",     "odm.",       "ro.boot.",
};

static const std::set<std::string> kExportedActionableProperties = {
    "dev.bootcomplete",
    "init.svc.console",
    "init.svc.mediadrm",
    "init.svc.surfaceflinger",
    "init.svc.zygote",
    "persist.bluetooth.btsnoopenable",
    "persist.sys.crash_rcu",
    "persist.sys.zram_enabled",
    "ro.board.platform",
    "ro.bootmode",
    "ro.build.type",
    "ro.crypto.state",
    "ro.crypto.type",
    "ro.debuggable",
    "sys.boot_completed",
    "sys.boot_from_charger_mode",
    "sys.retaildemo.enabled",
    "sys.shutdown.requested",
    "sys.usb.config",
    "sys.usb.configfs",
    "sys.usb.ffs.mtp.ready",
    "sys.usb.ffs.ready",
    "sys.user.0.ce_available",
    "sys.vdso",
    "vold.decrypt",
    "vold.post_fs_data_done",
    "vts.native_server.on",
    "wlan.driver.status",
};

}  // namespace init
}  // namespace android

#endif
