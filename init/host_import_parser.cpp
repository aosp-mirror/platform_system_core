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

#include "host_import_parser.h"

#include <android-base/strings.h>

using android::base::StartsWith;

namespace android {
namespace init {

Result<Success> HostImportParser::ParseSection(std::vector<std::string>&& args, const std::string&,
                                               int) {
    if (args.size() != 2) {
        return Error() << "single argument needed for import\n";
    }

    return Success();
}

Result<Success> HostImportParser::ParseLineSection(std::vector<std::string>&&, int) {
    return Error() << "Unexpected line found after import statement";
}

}  // namespace init
}  // namespace android
