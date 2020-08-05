/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#pragma once

#include <sysutils/FrameworkCommand.h>
#include <sysutils/FrameworkListener.h>

#include "LogBuffer.h"
#include "LogListener.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "PruneList.h"

class CommandListener : public FrameworkListener {
  public:
    CommandListener(LogBuffer* buf, LogTags* tags, PruneList* prune, LogStatistics* log_statistics);
    virtual ~CommandListener() {}

  private:
    static int getLogSocket();

    LogBuffer* buf_;
    LogTags* tags_;
    PruneList* prune_;
    LogStatistics* stats_;

#define LogCmd(name, command_string)                                \
    class name##Cmd : public FrameworkCommand {                     \
      public:                                                       \
        explicit name##Cmd(CommandListener* parent)                 \
            : FrameworkCommand(#command_string), parent_(parent) {} \
        virtual ~name##Cmd() {}                                     \
        int runCommand(SocketClient* c, int argc, char** argv);     \
                                                                    \
      private:                                                      \
        LogBuffer* buf() const { return parent_->buf_; }            \
        LogTags* tags() const { return parent_->tags_; }            \
        PruneList* prune() const { return parent_->prune_; }        \
        LogStatistics* stats() const { return parent_->stats_; }    \
        CommandListener* parent_;                                   \
    }

    LogCmd(Clear, clear);
    LogCmd(GetBufSize, getLogSize);
    LogCmd(SetBufSize, setLogSize);
    LogCmd(GetBufSizeReadable, getLogSizeReadable);
    LogCmd(GetBufSizeUsed, getLogSizeUsed);
    LogCmd(GetStatistics, getStatistics);
    LogCmd(GetPruneList, getPruneList);
    LogCmd(SetPruneList, setPruneList);
    LogCmd(GetEventTag, getEventTag);
    LogCmd(Reinit, reinit);
    LogCmd(Exit, EXIT);
#undef LogCmd
};
