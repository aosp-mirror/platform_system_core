/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* NOTICE: This is a clean room re-implementation of libnl */

#include "netlink-types.h"

void nl_object_put(struct nl_object *obj)
{
	obj->ce_refcnt--;
	if (!obj->ce_refcnt)
		nl_object_free(obj);
}

void nl_object_free(struct nl_object *obj)
{
	nl_cache_remove(obj);
}


