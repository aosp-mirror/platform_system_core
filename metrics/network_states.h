// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A table of network states, to be included when building tabular things.
//
// This file is used to construct two things: an enumerated type in
// metrics_daemon.h, and a table of structures with state names in
// metrics_daemon.cc.  Including this file ensures that the two tables are
// always in sync (and saves typing).  I don't know of other ways of achieving
// the same result in C/C++, but it doesn't mean there isn't one.

// Before you include this file, define STATE to do something useful, or else
// if will be a no-op.  STATE will be undefined on exit.  Don't worry about
// collisions for the STATE macro (as long as it's a macro) because the
// compiler will flag them---in that case, just change the name.  If someone is
// misguided enough to use STATE for something other than a macro, the error
// messages will be slightly more complicated.


#ifndef STATE
#define STATE(name, capname)
#endif

STATE(association, Association)
STATE(configuration, Configuration)
STATE(disconnect, Disconnect)
STATE(failure, Failure)
STATE(idle, Idle)
STATE(offline, Offline)
STATE(online, Online)
STATE(ready, Ready)

#undef STATE
