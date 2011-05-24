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
#include <unistd.h>
#include <linux/netlink.h>
#include "netlink-types.h"

/* Allocate a new netlink message with the default maximum payload size. */
struct nl_msg *nlmsg_alloc(void)
{
	/* Whole page will store nl_msg + nlmsghdr + genlmsghdr + payload */
	const int page_sz = getpagesize();
	struct nl_msg *nm;
	struct nlmsghdr *nlh;

	/* Netlink message */
	nm = (struct nl_msg *) malloc(page_sz);
	if (!nm)
		goto fail;

	/* Netlink message header pointer */
	nlh = (struct nlmsghdr *) ((char *) nm + sizeof(struct nl_msg));

	/* Initialize */
	memset(nm, 0, page_sz);
	nm->nm_size = page_sz;

	nm->nm_src.nl_family = AF_NETLINK;
	nm->nm_src.nl_pid = getpid();

	nm->nm_dst.nl_family = AF_NETLINK;
	nm->nm_dst.nl_pid = 0; /* Kernel */

	/* Initialize and add to netlink message */
	nlh->nlmsg_len = NLMSG_HDRLEN;
	nm->nm_nlh = nlh;

	/* Add to reference count and return nl_msg */
	nlmsg_get(nm);
	return nm;
fail:
	return NULL;
}

/* Return pointer to message payload. */
void *nlmsg_data(const struct nlmsghdr *nlh)
{
	return (char *) nlh + NLMSG_HDRLEN;
}

/* Add reference count to nl_msg */
void nlmsg_get(struct nl_msg *nm)
{
	nm->nm_refcnt++;
}

/* Release a reference from an netlink message. */
void nlmsg_free(struct nl_msg *nm)
{
	if (nm) {
		nm->nm_refcnt--;
		if (nm->nm_refcnt <= 0)
			free(nm);
	}

}

/* Return actual netlink message. */
struct nlmsghdr *nlmsg_hdr(struct nl_msg *n)
{
	return n->nm_nlh;
}

/* Return head of attributes data / payload section */
struct nlattr *nlmsg_attrdata(const struct nlmsghdr *nlh, int hdrlen)
{
	unsigned char *data = nlmsg_data(nlh);
	return (struct nlattr *) (data + NLMSG_ALIGN(hdrlen));
}

/* Returns pointer to end of netlink message */
void *nlmsg_tail(const struct nlmsghdr *nlh)
{
	return (void *)((char *) nlh + nlh->nlmsg_len);
}

/* Next netlink message in message stream */
struct nlmsghdr *nlmsg_next(struct nlmsghdr *nlh, int *remaining)
{
	struct nlmsghdr *next_nlh = NULL;
	if (*remaining > 0 &&
		nlmsg_len(nlh) <= *remaining &&
		nlmsg_len(nlh) >= (int) sizeof(struct nlmsghdr)) {
		next_nlh = (struct nlmsghdr *) \
			((char *) nlh + nlmsg_len(nlh));

		if (next_nlh && nlmsg_len(nlh) <= *remaining) {
			*remaining -= nlmsg_len(nlh);
			next_nlh = (struct nlmsghdr *) \
				((char *) nlh + nlmsg_len(nlh));
		}
	}

	return next_nlh;
}

/* Length of attributes data */
int nlmsg_attrlen(const struct nlmsghdr *nlh, int hdrlen)
{
	return nlmsg_len(nlh) - NLMSG_HDRLEN - hdrlen;
}

/* Length of netlink message */
int nlmsg_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len;
}

/* Check if the netlink message fits into the remaining bytes */
int nlmsg_ok(const struct nlmsghdr *nlh, int rem)
{
	return rem >= (int)sizeof(struct nlmsghdr) &&
		rem >= nlmsg_len(nlh) &&
		nlmsg_len(nlh) >= (int) sizeof(struct nlmsghdr) &&
		nlmsg_len(nlh) <= (rem);
}

int nlmsg_padlen(int payload)
{
	return NLMSG_ALIGN(payload) - payload;
}

int nlmsg_datalen(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_HDRLEN;
}

