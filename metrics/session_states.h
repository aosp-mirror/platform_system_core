// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A table of user session states, to be included when building tabular things.
//
// See network_states.h for details.


#ifndef STATE
#define STATE(name, capname)
#endif

STATE(started, Started)
STATE(stopped, Stopped)

#undef STATE
