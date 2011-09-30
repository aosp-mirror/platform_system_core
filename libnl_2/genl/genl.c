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

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include "netlink-types.h"

/* Get head of attribute data. */
struct nlattr *genlmsg_attrdata(const struct genlmsghdr *gnlh, int hdrlen)
{
	return (struct nlattr *) \
		((char *) gnlh + GENL_HDRLEN + NLMSG_ALIGN(hdrlen));

}

/* Get length of attribute data. */
int genlmsg_attrlen(const struct genlmsghdr *gnlh, int hdrlen)
{
	struct nlattr *nla;
	struct nlmsghdr *nlh;

	nla = genlmsg_attrdata(gnlh, hdrlen);
	nlh = (struct nlmsghdr *) ((char *) gnlh - NLMSG_HDRLEN);
	return (char *) nlmsg_tail(nlh) - (char *) nla;
}

/* Add generic netlink header to netlink message. */
void *genlmsg_put(struct nl_msg *msg, uint32_t pid, uint32_t seq, int family,
		int hdrlen, int flags, uint8_t cmd, uint8_t version)
{
	int new_size;
	struct nlmsghdr *nlh;
	struct timeval tv;
	struct genlmsghdr *gmh;

	/* Make sure nl_msg has enough space */
	new_size = NLMSG_HDRLEN + GENL_HDRLEN + hdrlen;
	if ((sizeof(struct nl_msg) + new_size) > msg->nm_size)
		goto fail;

	/* Fill in netlink header */
	nlh = msg->nm_nlh;
	nlh->nlmsg_len = new_size;
	nlh->nlmsg_type = family;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = flags | NLM_F_REQUEST | NLM_F_ACK;

	/* Get current time for sequence number */
	if (gettimeofday(&tv, NULL))
		nlh->nlmsg_seq = 1;
	else
		nlh->nlmsg_seq = (int) tv.tv_sec;

	/* Setup genlmsghdr in new message */
	gmh = (struct genlmsghdr *) ((char *)nlh + NLMSG_HDRLEN);
	gmh->cmd = (__u8) cmd;
	gmh->version = version;

	return gmh;
fail:
	return NULL;

}

/* Socket has already been alloced to connect it to kernel? */
int genl_connect(struct nl_sock *sk)
{
	return nl_connect(sk, NETLINK_GENERIC);

}

int genl_ctrl_alloc_cache(struct nl_sock *sock, struct nl_cache **result)
{
	int rc = -1;
	int nl80211_genl_id = -1;
	char sendbuf[sizeof(struct nlmsghdr)+sizeof(struct genlmsghdr)];
	struct nlmsghdr nlmhdr;
	struct genlmsghdr gmhhdr;
	struct iovec sendmsg_iov;
	struct msghdr msg;
	int num_char;
	const int RECV_BUF_SIZE = getpagesize();
	char *recvbuf;
	struct iovec recvmsg_iov;
	int nl80211_flag = 0, nlm_f_multi = 0, nlmsg_done = 0;
	struct nlmsghdr *nlh;

	/* REQUEST GENERIC NETLINK FAMILY ID */
	/* Message buffer */
	nlmhdr.nlmsg_len = sizeof(sendbuf);
	nlmhdr.nlmsg_type = NETLINK_GENERIC;
	nlmhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	nlmhdr.nlmsg_seq = sock->s_seq_next;
	nlmhdr.nlmsg_pid = sock->s_local.nl_pid;

	/* Generic netlink header */
	memset(&gmhhdr, 0, sizeof(gmhhdr));
	gmhhdr.cmd = CTRL_CMD_GETFAMILY;
	gmhhdr.version = CTRL_ATTR_FAMILY_ID;

	/* Combine netlink and generic netlink headers */
	memcpy(&sendbuf[0], &nlmhdr, sizeof(nlmhdr));
	memcpy(&sendbuf[0]+sizeof(nlmhdr), &gmhhdr, sizeof(gmhhdr));

	/* Create IO vector with Netlink message */
	sendmsg_iov.iov_base = &sendbuf;
	sendmsg_iov.iov_len = sizeof(sendbuf);

	/* Socket message */
	msg.msg_name = (void *) &sock->s_peer;
	msg.msg_namelen = sizeof(sock->s_peer);
	msg.msg_iov = &sendmsg_iov;
	msg.msg_iovlen = 1; /* Only sending one iov */
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	/* Send message and verify sent */
	num_char = sendmsg(sock->s_fd, &msg, 0);
	if (num_char == -1)
		return -errno;

	/* RECEIVE GENL CMD RESPONSE */

	/* Create receive iov buffer */
	recvbuf = (char *) malloc(RECV_BUF_SIZE);

	/* Attach to iov */
	recvmsg_iov.iov_base = recvbuf;
	recvmsg_iov.iov_len = RECV_BUF_SIZE;

	msg.msg_iov = &recvmsg_iov;
	msg.msg_iovlen = 1;

	/***************************************************************/
	/* Receive message. If multipart message, keep receiving until */
	/* message type is NLMSG_DONE				       */
	/***************************************************************/

	do {

		int recvmsg_len, nlmsg_rem;

		/* Receive message */
		memset(recvbuf, 0, RECV_BUF_SIZE);
		recvmsg_len = recvmsg(sock->s_fd, &msg, 0);

		/* Make sure receive successful */
		if (recvmsg_len < 0) {
			rc = -errno;
			goto error_recvbuf;
		}

		/* Parse nlmsghdr */
		nlmsg_for_each_msg(nlh, (struct nlmsghdr *) recvbuf, \
				recvmsg_len, nlmsg_rem) {
			struct nlattr *nla;
			int nla_rem;

			/* Check type */
			switch (nlh->nlmsg_type) {
			case NLMSG_DONE:
				goto return_genl_id;
				break;
			case NLMSG_ERROR:

				/* Should check nlmsgerr struct received */
				fprintf(stderr, "Receive message error\n");
				goto error_recvbuf;
			case NLMSG_OVERRUN:
				fprintf(stderr, "Receive data partly lost\n");
				goto error_recvbuf;
			case NLMSG_MIN_TYPE:
			case NLMSG_NOOP:
				break;
			default:
				break;
			}



			/* Check flags */
			if (nlh->nlmsg_flags & NLM_F_MULTI)
				nlm_f_multi = 1;
			else
				nlm_f_multi = 0;

			if (nlh->nlmsg_type & NLMSG_DONE)
				nlmsg_done = 1;
			else
				nlmsg_done = 0;

			/* Iteratve over attributes */
			nla_for_each_attr(nla,
					nlmsg_attrdata(nlh, GENL_HDRLEN),
					nlmsg_attrlen(nlh, GENL_HDRLEN),
					nla_rem){

				/* If this family is nl80211 */
				if (nla->nla_type == CTRL_ATTR_FAMILY_NAME &&
					!strcmp((char *)nla_data(nla),
						"nl80211"))
					nl80211_flag = 1;

				/* Save the family id */
				else if (nl80211_flag &&
					nla->nla_type == CTRL_ATTR_FAMILY_ID) {
					nl80211_genl_id =
						*((int *)nla_data(nla));
					nl80211_flag = 0;
				}

			}

		}

	} while (nlm_f_multi && !nlmsg_done);

return_genl_id:
	/* Return family id as cache pointer */
	*result = (struct nl_cache *) nl80211_genl_id;
	rc = 0;
error_recvbuf:
	free(recvbuf);
error:
	return rc;
}

/* Checks the netlink cache to find family reference by name string */
/* NOTE: Caller needs to call genl_family_put() when done with *
 * returned object */
struct genl_family *genl_ctrl_search_by_name(struct nl_cache *cache, \
					const char *name)
{
	/* TODO: When will we release this memory ? */
	struct genl_family *gf = (struct genl_family *) \
		malloc(sizeof(struct genl_family));
	if (!gf)
		goto fail;
	memset(gf, 0, sizeof(*gf));

	/* Add ref */
	gf->ce_refcnt++;

	/* Overriding cache pointer as family id for now */
	gf->gf_id = (uint16_t) ((uint32_t) cache);
	strcpy(gf->gf_name, "nl80211");

	return gf;
fail:
	return NULL;

}

int genl_ctrl_resolve(struct nl_sock *sk, const char *name)
{
	/* Hack to support wpa_supplicant */
	if (strcmp(name, "nlctrl") == 0)
		return NETLINK_GENERIC;
	else {
		int errsv = errno;
		fprintf(stderr, \
			"Only nlctrl supported by genl_ctrl_resolve!\n");
		return -errsv;
	}

}

