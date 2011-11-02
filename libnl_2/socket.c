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
#include <malloc.h>
#include <sys/time.h>
#include <sys/socket.h>
#include "netlink-types.h"

/* Join group */
int nl_socket_add_membership(struct nl_sock *sk, int group)
{
	return setsockopt(sk->s_fd, SOL_NETLINK,
			NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
}

/* Allocate new netlink socket. */
static struct nl_sock *_nl_socket_alloc(void)
{
	struct nl_sock *sk;
	struct timeval tv;
	struct nl_cb *cb;

	sk = (struct nl_sock *) malloc(sizeof(struct nl_sock));
	if (!sk)
		return NULL;
	memset(sk, 0, sizeof(*sk));

	/* Get current time */

	if (gettimeofday(&tv, NULL))
		goto fail;
	else
		sk->s_seq_next = (int) tv.tv_sec;

	/* Create local socket */
	sk->s_local.nl_family = AF_NETLINK;
	sk->s_local.nl_pid = 0; /* Kernel fills in pid */
	sk->s_local.nl_groups = 0; /* No groups */

	/* Create peer socket */
	sk->s_peer.nl_family = AF_NETLINK;
	sk->s_peer.nl_pid = 0; /* Kernel */
	sk->s_peer.nl_groups = 0; /* No groups */

	return sk;
fail:
	free(sk);
	return NULL;
}

/* Allocate new netlink socket. */
struct nl_sock *nl_socket_alloc(void)
{
	struct nl_sock *sk = _nl_socket_alloc();
	struct nl_cb *cb;

	if (!sk)
		return NULL;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto cb_fail;
	sk->s_cb = cb;
	return sk;
cb_fail:
	free(sk);
	return NULL;
}

/* Allocate new socket with custom callbacks. */
struct nl_sock *nl_socket_alloc_cb(struct nl_cb *cb)
{
	struct nl_sock *sk = _nl_socket_alloc();

	if (!sk)
		return NULL;

	sk->s_cb = cb;
	nl_cb_get(cb);

	return sk;
}

/* Free a netlink socket. */
void nl_socket_free(struct nl_sock *sk)
{
	nl_cb_put(sk->s_cb);
	close(sk->s_fd);
	free(sk);
}

/* Sets socket buffer size of netlink socket */
int nl_socket_set_buffer_size(struct nl_sock *sk, int rxbuf, int txbuf)
{
	if (setsockopt(sk->s_fd, SOL_SOCKET, SO_SNDBUF, \
			&rxbuf, (socklen_t) sizeof(rxbuf)))
		goto error;

	if (setsockopt(sk->s_fd, SOL_SOCKET, SO_RCVBUF, \
			&txbuf, (socklen_t) sizeof(txbuf)))
		goto error;

	return 0;
error:
	return -errno;

}

int nl_socket_get_fd(struct nl_sock *sk)
{
	return sk->s_fd;
}
