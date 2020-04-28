/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "import_parser.h"

#include <android-base/logging.h>

#include "util.h"

namespace android {
namespace init {

Result<Success> ImportParser::ParseSection(std::vector<std::string>&& args,
                                           const std::string& filename, int line) {
    if (args.size() != 2) {
        return Error() << "single argument needed for import\n";
    }

    std::string conf_file;
    bool ret = expand_props(args[1], &conf_file);
    if (!ret) {
        return Error() << "error while expanding import";
    }

    LOG(INFO) << "Added '" << conf_file << "' to import list";
    if (filename_.empty()) filename_ = filename;
    imports_.emplace_back(std::move(conf_file), line);
    return Success();
}

Result<Success> ImportParser::ParseLineSection(std::vector<std::string>&&, int) {
    return Error() << "Unexpected line found after import statement";
}

void ImportParser::EndFile() {
    auto current_imports = std::move(imports_);
    imports_.clear();
    for (const auto& [import, line_num] : current_imports) {
        parser_->ParseConfig(import);
    }
}

}  // namespace init
}  // namespace android
