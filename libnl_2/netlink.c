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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "netlink-types.h"

#define NL_BUFFER_SZ (32768U)

/* Checks message for completeness and sends it out */
int nl_send_auto_complete(struct nl_sock *sk, struct nl_msg *msg)
{
	struct nlmsghdr *nlh = msg->nm_nlh;
	struct timeval tv;

	if (!nlh) {
		int errsv = errno;
		fprintf(stderr, "Netlink message header is NULL!\n");
		return -errsv;
	}

	/* Complete the nl_msg header */
	if (gettimeofday(&tv, NULL))
		nlh->nlmsg_seq = 1;
	else
		nlh->nlmsg_seq = (int) tv.tv_sec;
	nlh->nlmsg_pid = sk->s_local.nl_pid;
	nlh->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;

	return nl_send(sk, msg);
}

/* Receives a netlink message, allocates a buffer in *buf and stores
 * the message content. The peer's netlink address is stored in
 * *nla. The caller is responsible for freeing the buffer allocated in
 * *buf if a positive value is returned. Interrupted system calls are
 * handled by repeating the read. The input buffer size is determined
 * by peeking before the actual read is done */
int nl_recv(struct nl_sock *sk, struct sockaddr_nl *nla, \
	unsigned char **buf, struct ucred **creds)
{
	int rc = -1;
	int sk_flags;
	int RECV_BUF_SIZE;
	int errsv;
	struct iovec recvmsg_iov;
	struct msghdr msg;

	/* Allocate buffer */
	RECV_BUF_SIZE = getpagesize();
	*buf = (unsigned char *) malloc(RECV_BUF_SIZE);
	if (!buf) {
		rc = -ENOMEM;
		goto fail;
	}

	/* Prepare to receive message */
	recvmsg_iov.iov_base = *buf;
	recvmsg_iov.iov_len = RECV_BUF_SIZE;

	msg.msg_name = (void *) &sk->s_peer;
	msg.msg_namelen = sizeof(sk->s_peer);
	msg.msg_iov = &recvmsg_iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	/* Make non blocking and then restore previous setting */
	sk_flags = fcntl(sk->s_fd, F_GETFL, 0);
	fcntl(sk->s_fd, F_SETFL, O_NONBLOCK);
	rc = recvmsg(sk->s_fd, &msg, 0);
	errsv = errno;
	fcntl(sk->s_fd, F_SETFL, sk_flags);

	if (rc < 0)
		rc = -errsv;

fail:
	return rc;
}

/* Receive a set of messages from a netlink socket */
/* NOTE: Does not currently support callback replacements!!! */
int nl_recvmsgs(struct nl_sock *sk, struct nl_cb *cb)
{
	struct sockaddr_nl nla;
	struct ucred *creds;

	int rc, cb_rc = NL_OK, done = 0;

	do {

		unsigned char *buf;
		int i, rem, flags;
		struct nlmsghdr *nlh;
		struct nlmsgerr *nlme;
		struct nl_msg *msg;

		done = 0;
		rc = nl_recv(sk, &nla, &buf, &creds);
		if (rc < 0)
			break;

		nlmsg_for_each_msg(nlh, (struct nlmsghdr *) buf, rc, rem) {

			if (rc <= 0 || cb_rc == NL_STOP)
				break;

			/* Check for callbacks */

			msg = (struct nl_msg *)malloc(sizeof(struct nl_msg));
			memset(msg, 0, sizeof(*msg));
			msg->nm_nlh = nlh;

			/* Check netlink message type */

			switch (msg->nm_nlh->nlmsg_type) {
			case NLMSG_ERROR:	  /* Used for ACK too */
				/* Certainly we should be doing some
				 * checking here to make sure this
				 * message is intended for us */
				nlme = nlmsg_data(msg->nm_nlh);
				if (nlme->error == 0)
					msg->nm_nlh->nlmsg_flags |= NLM_F_ACK;

				rc = nlme->error;
				cb_rc = cb->cb_err(&nla, nlme, cb->cb_err_arg);
				nlme = NULL;
				break;

			case NLMSG_DONE:
				done = 1;

			case NLMSG_OVERRUN:
			case NLMSG_NOOP:
			default:
				break;
			};

			for (i = 0; i <= NL_CB_TYPE_MAX; i++) {

				if (cb->cb_set[i]) {
					switch (i) {
					case NL_CB_VALID:
						if (rc > 0)
							cb_rc = cb->cb_set[i](msg, cb->cb_args[i]);
						break;

					case NL_CB_FINISH:
						if ((msg->nm_nlh->nlmsg_flags & NLM_F_MULTI) &&
							(msg->nm_nlh->nlmsg_type & NLMSG_DONE))
							cb_rc = cb->cb_set[i](msg, cb->cb_args[i]);

						break;

					case NL_CB_ACK:
						if (msg->nm_nlh->nlmsg_flags & NLM_F_ACK)
							cb_rc = cb->cb_set[i](msg, cb->cb_args[i]);

						break;
					default:
						break;
					}
				}
			}

			free(msg);
			if (done)
				break;
		}

		free(buf);
		buf = NULL;

		if (done)
			break;
	} while (rc > 0 && cb_rc != NL_STOP);

success:
fail:
	return	rc;
}

/* Send raw data over netlink socket */
int nl_send(struct nl_sock *sk, struct nl_msg *msg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct iovec msg_iov;

	/* Create IO vector with Netlink message */
	msg_iov.iov_base = nlh;
	msg_iov.iov_len = nlh->nlmsg_len;

	return nl_send_iovec(sk, msg, &msg_iov, 1);
}

/* Send netlink message */
int nl_send_iovec(struct nl_sock *sk, struct nl_msg *msg,
		   struct iovec *iov, unsigned iovlen)
{
	int rc;

	/* Socket message */
	struct msghdr mh = {
		.msg_name = (void *) &sk->s_peer,
		.msg_namelen = sizeof(sk->s_peer),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0
	};

	/* Send message and verify sent */
	rc = nl_sendmsg(sk, (struct nl_msg *) &mh, 0);
	if (rc < 0)
		fprintf(stderr, "Error sending netlink message: %d\n", errno);
	return rc;

}

/* Send netlink message with control over sendmsg() message header */
int nl_sendmsg(struct nl_sock *sk, struct nl_msg *msg, struct msghdr *hdr)
{
	return sendmsg(sk->s_fd, (struct msghdr *) msg, (int) hdr);
}

/* Create and connect netlink socket */
int nl_connect(struct nl_sock *sk, int protocol)
{
	struct sockaddr addr;
	socklen_t addrlen;
	int rc;

	/* Create RX socket */
	sk->s_fd = socket(PF_NETLINK, SOCK_RAW, protocol);
	if (sk->s_fd < 0)
		return -errno;

	/* Set size of RX and TX buffers */
	if (nl_socket_set_buffer_size(sk, NL_BUFFER_SZ, NL_BUFFER_SZ) < 0)
		return -errno;

	/* Bind RX socket */
	rc = bind(sk->s_fd, (struct sockaddr *)&sk->s_local, \
		sizeof(sk->s_local));
	if (rc < 0)
		return -errno;
	addrlen = sizeof(addr);
	getsockname(sk->s_fd, &addr, &addrlen);

	return 0;

}
