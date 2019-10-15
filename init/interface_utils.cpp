/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "interface_utils.h"

#include <fstream>
#include <sstream>

#include <android-base/strings.h>
#include <hidl-util/FqInstance.h>

using android::FqInstance;
using android::FQName;
using android::base::Error;

namespace android {
namespace init {

namespace {

std::string FQNamesToString(const std::set<FQName>& fqnames) {
    std::set<std::string> fqname_strings;
    for (const FQName& fqname : fqnames) {
        fqname_strings.insert(fqname.string());
    }
    return android::base::Join(fqname_strings, " ");
}

}  // namespace

Result<void> CheckInterfaceInheritanceHierarchy(const std::set<std::string>& instances,
                                                const InterfaceInheritanceHierarchyMap& hierarchy) {
    std::set<FQName> interface_fqnames;
    for (const std::string& instance : instances) {
        // There is insufficient build-time information on AIDL interfaces to check them here
        // TODO(b/139307527): Rework how services store interfaces to avoid excess string parsing
        if (base::Split(instance, "/")[0] == "aidl") {
            continue;
        }

        FqInstance fqinstance;
        if (!fqinstance.setTo(instance)) {
            return Error() << "Unable to parse interface instance '" << instance << "'";
        }
        interface_fqnames.insert(fqinstance.getFqName());
    }
    return CheckInterfaceInheritanceHierarchy(interface_fqnames, hierarchy);
}

Result<void> CheckInterfaceInheritanceHierarchy(const std::set<FQName>& interfaces,
                                                const InterfaceInheritanceHierarchyMap& hierarchy) {
    std::ostringstream error_stream;
    for (const FQName& intf : interfaces) {
        if (hierarchy.count(intf) == 0) {
            error_stream << "\nInterface is not in the known set of hidl_interfaces: '"
                         << intf.string()
                         << "'. Please ensure the interface is spelled correctly and built "
                         << "by a hidl_interface target.";
            continue;
        }
        const std::set<FQName>& required_interfaces = hierarchy.at(intf);
        std::set<FQName> diff;
        std::set_difference(required_interfaces.begin(), required_interfaces.end(),
                            interfaces.begin(), interfaces.end(),
                            std::inserter(diff, diff.begin()));
        if (!diff.empty()) {
            error_stream << "\nInterface '" << intf.string() << "' requires its full inheritance "
                         << "hierarchy to be listed in this init_rc file. Missing "
                         << "interfaces: [" << FQNamesToString(diff) << "]";
        }
    }
    const std::string& errors = error_stream.str();
    if (!errors.empty()) {
        return Error() << errors;
    }

    return {};
}

std::optional<std::set<FQName>> known_interfaces;

void SetKnownInterfaces(const InterfaceInheritanceHierarchyMap& hierarchy) {
    known_interfaces = std::set<FQName>();
    for (const auto& [intf, inherited_interfaces] : hierarchy) {
        known_interfaces->insert(intf);
    }
}

Result<void> IsKnownInterface(const std::string& instance) {
    FqInstance fqinstance;
    if (!fqinstance.setTo(instance)) {
        return Error() << "Unable to parse interface instance '" << instance << "'";
    }
    return IsKnownInterface(fqinstance.getFqName());
}

Result<void> IsKnownInterface(const FQName& intf) {
    if (!known_interfaces) {
        return Error() << "No known interfaces have been loaded.";
    }
    if (known_interfaces->count(intf) == 0) {
        return Error() << "Interface is not in the known set of hidl_interfaces: '" << intf.string()
                       << "'. Please ensure the interface is spelled correctly and built "
                       << "by a hidl_interface target.";
    }
    return {};
}

}  // namespace init
}  // namespace android
