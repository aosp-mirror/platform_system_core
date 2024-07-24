// Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <poll.h>

#include <string>
#include <vector>

#include "user-space-merge/snapuserd_server.h"

namespace android {
namespace snapshot {

class Daemon {
    // The Daemon class is a singleton to avoid
    // instantiating more than once
  public:
    Daemon() {}

    static Daemon& Instance() {
        static Daemon instance;
        return instance;
    }

    bool StartServerForUserspaceSnapshots(int arg_start, int argc, char** argv);
    void Interrupt();
    void ReceivedSocketSignal();
    bool IsUserspaceSnapshotsEnabled();
    bool StartDaemon(int argc, char** argv);

  private:
    // Signal mask used with ppoll()
    sigset_t signal_mask_;

    Daemon(Daemon const&) = delete;
    void operator=(Daemon const&) = delete;

    UserSnapshotServer user_server_;
    void MaskAllSignalsExceptIntAndTerm();
    void MaskAllSignals();
    static void SignalHandler(int signal);
};

}  // namespace snapshot
}  // namespace android
