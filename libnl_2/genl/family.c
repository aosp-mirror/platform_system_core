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

static struct genl_family *genl_family_find_byname(const char *name)
{
	return NULL;
}

/* Release reference and none outstanding  */
void genl_family_put(struct genl_family *family)
{
	family->ce_refcnt--;
	if (family->ce_refcnt <= 0)
		free(family);
}

unsigned int genl_family_get_id(struct genl_family *family)
{
	const int NO_FAMILY_ID = 0;

	if (!family)
		return NO_FAMILY_ID;
	else
		return family->gf_id;

}

