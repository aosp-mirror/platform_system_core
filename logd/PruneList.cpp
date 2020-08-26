/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "PruneList.h"

#include <ctype.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

bool Prune::Matches(LogBufferElement* element) const {
    return (uid_ == UID_ALL || uid_ == element->uid()) &&
           (pid_ == PID_ALL || pid_ == element->pid());
}

std::string Prune::Format() const {
    if (uid_ != UID_ALL) {
        if (pid_ != PID_ALL) {
            return android::base::StringPrintf("%u/%u", uid_, pid_);
        }
        return android::base::StringPrintf("%u", uid_);
    }
    if (pid_ != PID_ALL) {
        return android::base::StringPrintf("/%u", pid_);
    }
    // NB: pid_ == PID_ALL can not happen if uid_ == UID_ALL
    return std::string("/");
}

PruneList::PruneList() {
    Init(nullptr);
}

bool PruneList::Init(const char* str) {
    high_priority_prune_.clear();
    low_priority_prune_.clear();

    // default here means take ro.logd.filter, persist.logd.filter then internal default in order.
    if (str && !strcmp(str, "default")) {
        str = nullptr;
    }
    if (str && !strcmp(str, "disable")) {
        str = "";
    }

    std::string filter;

    if (str) {
        filter = str;
    } else {
        filter = android::base::GetProperty("ro.logd.filter", "default");
        auto persist_filter = android::base::GetProperty("persist.logd.filter", "default");
        // default here means take ro.logd.filter
        if (persist_filter != "default") {
            filter = persist_filter;
        }
    }

    // default here means take internal default.
    if (filter == "default") {
        filter = "~! ~1000/!";
    }
    if (filter == "disable") {
        filter = "";
    }

    worst_uid_enabled_ = false;
    worst_pid_of_system_enabled_ = false;

    for (str = filter.c_str(); *str; ++str) {
        if (isspace(*str)) {
            continue;
        }

        std::list<Prune>* list;
        if (*str == '~' || *str == '!') {  // ~ supported, ! undocumented
            ++str;
            // special case, prune the worst UID of those using at least 1/8th of the buffer.
            if (*str == '!') {
                worst_uid_enabled_ = true;
                ++str;
                if (!*str) {
                    break;
                }
                if (!isspace(*str)) {
                    LOG(ERROR) << "Nothing expected after '~!', but found '" << str << "'";
                    return false;
                }
                continue;
            }
            // special case, translated to worst PID of System at priority
            static const char WORST_SYSTEM_PID[] = "1000/!";
            if (!strncmp(str, WORST_SYSTEM_PID, sizeof(WORST_SYSTEM_PID) - 1)) {
                worst_pid_of_system_enabled_ = true;
                str += sizeof(WORST_SYSTEM_PID) - 1;
                if (!*str) {
                    break;
                }
                if (!isspace(*str)) {
                    LOG(ERROR) << "Nothing expected after '~1000/!', but found '" << str << "'";
                    return false;
                }
                continue;
            }
            if (!*str) {
                LOG(ERROR) << "Expected UID or PID after '~', but found nothing";
                return false;
            }
            list = &high_priority_prune_;
        } else {
            list = &low_priority_prune_;
        }

        uid_t uid = Prune::UID_ALL;
        if (isdigit(*str)) {
            uid = 0;
            do {
                uid = uid * 10 + *str++ - '0';
            } while (isdigit(*str));
        }

        pid_t pid = Prune::PID_ALL;
        if (*str == '/') {
            ++str;
            if (isdigit(*str)) {
                pid = 0;
                do {
                    pid = pid * 10 + *str++ - '0';
                } while (isdigit(*str));
            }
        }

        if (uid == Prune::UID_ALL && pid == Prune::PID_ALL) {
            LOG(ERROR) << "Expected UID/PID combination, but found none";
            return false;
        }

        if (*str && !isspace(*str)) {
            LOG(ERROR) << "Nothing expected after UID/PID combination, but found '" << str << "'";
            return false;
        }

        list->emplace_back(uid, pid);
        if (!*str) {
            break;
        }
    }

    return true;
}

std::string PruneList::Format() const {
    std::vector<std::string> prune_rules;

    if (worst_uid_enabled_) {
        prune_rules.emplace_back("~!");
    }
    if (worst_pid_of_system_enabled_) {
        prune_rules.emplace_back("~1000/!");
    }
    for (const auto& rule : low_priority_prune_) {
        prune_rules.emplace_back(rule.Format());
    }
    for (const auto& rule : high_priority_prune_) {
        prune_rules.emplace_back("~" + rule.Format());
    }
    return android::base::Join(prune_rules, " ");
}

bool PruneList::IsHighPriority(LogBufferElement* element) const {
    for (const auto& rule : high_priority_prune_) {
        if (rule.Matches(element)) {
            return true;
        }
    }
    return false;
}

bool PruneList::IsLowPriority(LogBufferElement* element) const {
    for (const auto& rule : low_priority_prune_) {
        if (rule.Matches(element)) {
            return true;
        }
    }
    return false;
}
