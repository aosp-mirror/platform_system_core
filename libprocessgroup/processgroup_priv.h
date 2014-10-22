/*
 *  Copyright 2014 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef _PROCESSGROUP_PRIV_H_
#define _PROCESSGROUP_PRIV_H_

#define PROCESSGROUP_CGROUP_PATH "/acct"
#define PROCESSGROUP_UID_PREFIX "uid_"
#define PROCESSGROUP_PID_PREFIX "pid_"
#define PROCESSGROUP_CGROUP_PROCS_FILE "/cgroup.procs"
#define PROCESSGROUP_MAX_UID_LEN 11
#define PROCESSGROUP_MAX_PID_LEN 11
#define PROCESSGROUP_MAX_PATH_LEN \
        (sizeof(PROCESSGROUP_CGROUP_PATH) + \
         sizeof(PROCESSGROUP_UID_PREFIX) + 1 + \
         PROCESSGROUP_MAX_UID_LEN + \
         sizeof(PROCESSGROUP_PID_PREFIX) + 1 + \
         PROCESSGROUP_MAX_PID_LEN + \
         sizeof(PROCESSGROUP_CGROUP_PROCS_FILE) + \
         1)

#endif
