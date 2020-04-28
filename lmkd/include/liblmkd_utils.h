/*
 *  Copyright 2018 Google, Inc
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

#ifndef _LIBLMKD_UTILS_H_
#define _LIBLMKD_UTILS_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <lmkd.h>

__BEGIN_DECLS

/*
 * Connects to lmkd process and returns socket handle.
 * On success returns socket handle.
 * On error, -1 is returned, and errno is set appropriately.
 */
int lmkd_connect();

/*
 * Registers a process with lmkd and sets its oomadj score.
 * On success returns 0.
 * On error, -1 is returned.
 * In the case of error errno is set appropriately.
 */
int lmkd_register_proc(int sock, struct lmk_procprio *params);

/*
 * Creates memcg directory for given process.
 * On success returns 0.
 * -1 is returned if path creation failed.
 * -2 is returned if tasks file open operation failed.
 * -3 is returned if tasks file write operation failed.
 * In the case of error errno is set appropriately.
 */
int create_memcg(uid_t uid, pid_t pid);

__END_DECLS

#endif /* _LIBLMKD_UTILS_H_ */
