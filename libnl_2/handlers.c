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

#include <malloc.h>
#include "netlink-types.h"
#include "netlink/handlers.h"

/* Allocate a new callback handle. */
struct nl_cb *nl_cb_alloc(enum nl_cb_kind kind)
{
	struct nl_cb *cb;

	cb = (struct nl_cb *) malloc(sizeof(struct nl_cb));
	if (cb == NULL)
		goto fail;
	memset(cb, 0, sizeof(*cb));

	return nl_cb_get(cb);
fail:
	return NULL;
}

/* Clone an existing callback handle */
struct nl_cb *nl_cb_clone(struct nl_cb *orig)
{
	struct nl_cb *new_cb;
	int new_refcnt;

	new_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (new_cb == NULL)
		goto fail;

	/* Preserve reference count and copy original */
	new_refcnt = new_cb->cb_refcnt;
	memcpy(new_cb, orig, sizeof(*orig));
	new_cb->cb_refcnt = new_refcnt;

	return new_cb;
fail:
	return NULL;
}

/* Set up a callback. */
int nl_cb_set(struct nl_cb *cb, enum nl_cb_type type, enum nl_cb_kind kind, \
	nl_recvmsg_msg_cb_t func, void *arg)
{
	cb->cb_set[type] = func;
	cb->cb_args[type] = arg;
	return 0;
}



/* Set up an error callback. */
int nl_cb_err(struct nl_cb *cb, enum nl_cb_kind kind, \
	nl_recvmsg_err_cb_t func, void *arg)
{
	cb->cb_err = func;
	cb->cb_err_arg = arg;
	return 0;

}

struct nl_cb *nl_cb_get(struct nl_cb *cb)
{
	cb->cb_refcnt++;
	return cb;
}

void nl_cb_put(struct nl_cb *cb)
{
	cb->cb_refcnt--;
	if (cb->cb_refcnt <= 0)
		free(cb);

}

