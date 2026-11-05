/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include "smartdns/lib/nftset.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"

#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <memory.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#ifdef NFNL_SUBSYS_NFTABLES
#include <linux/netfilter/nf_tables.h>

struct nlmsgreq {
	struct nlmsghdr h;
	struct nfgenmsg m;
};

enum { PAYLOAD_MAX = 2048 };

/* result of the element lookup; UNKNOWN when the kernel did not answer in time */
enum { NFTSET_IP_NOT_EXIST = 0, NFTSET_IP_EXIST, NFTSET_IP_UNKNOWN };

enum { NFTSET_SOCKET_POOL_SIZE = 2 };

struct nftset_socket_slot {
	int fd;
	pthread_mutex_t lock;
};

#define NFTSET_SOCKET_SLOT_INITIALIZER { .fd = -1, .lock = PTHREAD_MUTEX_INITIALIZER }
static struct nftset_socket_slot nftset_socket_pool[NFTSET_SOCKET_POOL_SIZE] = {
	NFTSET_SOCKET_SLOT_INITIALIZER,
	NFTSET_SOCKET_SLOT_INITIALIZER,
};
#undef NFTSET_SOCKET_SLOT_INITIALIZER

static atomic_t nftset_socket_cursor = ATOMIC_INIT(0);
static atomic_t nftset_sequence = ATOMIC_INIT(0);

/* Lock one socket slot for the complete request/response exchange. */
static struct nftset_socket_slot *_nftset_socket_acquire(void)
{
	unsigned int first = (unsigned int)atomic_inc_return(&nftset_socket_cursor) % NFTSET_SOCKET_POOL_SIZE;

	for (unsigned int i = 0; i < NFTSET_SOCKET_POOL_SIZE; i++) {
		struct nftset_socket_slot *slot = &nftset_socket_pool[(first + i) % NFTSET_SOCKET_POOL_SIZE];
		if (pthread_mutex_trylock(&slot->lock) == 0) {
			return slot;
		}
	}

	struct nftset_socket_slot *slot = &nftset_socket_pool[first];
	pthread_mutex_lock(&slot->lock);
	return slot;
}

static uint32_t _nftset_assign_sequence(void *msg, int msg_len)
{
	uint32_t seq = (uint32_t)atomic_inc_return(&nftset_sequence);
	if (seq == 0) {
		seq = (uint32_t)atomic_inc_return(&nftset_sequence);
	}

	int remaining = msg_len;
	struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
	while (NLMSG_OK(nlh, remaining)) {
		nlh->nlmsg_seq = seq;
		nlh = NLMSG_NEXT(nlh, remaining);
	}

	return seq;
}

static int _nftset_get_nffamily_from_str(const char *family)
{
	if (strncmp(family, "inet", sizeof("inet")) == 0) {
		return NFPROTO_INET;
	} else if (strncmp(family, "ip", sizeof("ip")) == 0) {
		return NFPROTO_IPV4;
	} else if (strncmp(family, "ip6", sizeof("ip6")) == 0) {
		return NFPROTO_IPV6;
	} else if (strncmp(family, "arp", sizeof("arp")) == 0) {
		return NFPROTO_ARP;
	} else if (strncmp(family, "netdev", sizeof("netdev")) == 0) {
		return NFPROTO_NETDEV;
	} else if (strncmp(family, "bridge", sizeof("bridge")) == 0) {
		return NFPROTO_BRIDGE;
	} else if (strncmp(family, "decnet", sizeof("decnet")) == 0) {
		return NFPROTO_DECNET;
	} else {
		return NFPROTO_UNSPEC;
	}
}

static struct rtattr *_nftset_nlmsg_tail(struct nlmsghdr *n)
{
	return (struct rtattr *)((uint8_t *)n + NLMSG_ALIGN(n->nlmsg_len));
}

static int _nftset_addattr(struct nlmsghdr *n, int maxlen, __u16 type, const void *data, __u16 alen)
{
	const __u16 len = RTA_LENGTH(alen);
	const ssize_t newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	if (newlen > maxlen) {
		errno = ENOSPC;
		return -1;
	}

	struct rtattr *attr = _nftset_nlmsg_tail(n);
	attr->rta_len = len;
	attr->rta_type = type;

	void *rta_data = RTA_DATA(attr);

	if ((data != NULL) && (alen > 0)) {
		memcpy(rta_data, data, alen);
	}
	memset((uint8_t *)rta_data + alen, 0, RTA_ALIGN(len) - len);

	n->nlmsg_len = newlen;

	return 0;
}

static int _nftset_addattr_string(struct nlmsghdr *n, int maxlen, __u16 type, const char *s)
{
	return _nftset_addattr(n, maxlen, type, s, strlen(s) + 1);
}

static int __attribute__((unused)) _nftset_addattr_uint32(struct nlmsghdr *n, int maxlen, __u16 type, const uint32_t v)
{
	return _nftset_addattr(n, maxlen, type, &v, sizeof(uint32_t));
}

static int __attribute__((unused)) _nftset_addattr_uint16(struct nlmsghdr *n, int maxlen, __u16 type, const uint16_t v)
{
	return _nftset_addattr(n, maxlen, type, &v, sizeof(uint16_t));
}

static int __attribute__((unused)) _nftset_addattr_uint8(struct nlmsghdr *n, int maxlen, __u16 type, const uint8_t v)
{
	return _nftset_addattr(n, maxlen, type, &v, sizeof(uint8_t));
}

static struct rtattr *_nftset_addattr_nest(struct nlmsghdr *n, int maxlen, __u16 type)
{
	struct rtattr *attr = _nftset_nlmsg_tail(n);

	if (-1 == _nftset_addattr(n, maxlen, type, NULL, 0)) {
		return NULL;
	}

	return attr;
}

static void _nftset_addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	const void *tail = _nftset_nlmsg_tail(n);
	nest->rta_len = (uint8_t *)tail - (uint8_t *)nest;
}

static int _nftset_start_batch(void *buf, void **nextbuf)
{
	struct nlmsgreq *req = (struct nlmsgreq *)buf;
	memset(buf, 0, sizeof(struct nlmsgreq));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req->h.nlmsg_flags = NLM_F_REQUEST;
	req->h.nlmsg_type = NFNL_MSG_BATCH_BEGIN;
	req->h.nlmsg_seq = time(NULL);

	req->m.res_id = htons(NFNL_SUBSYS_NFTABLES);

	if (nextbuf) {
		*nextbuf = (uint8_t *)buf + req->h.nlmsg_len;
	}
	return 0;
}

static int _nftset_end_batch(void *buf, void **nextbuf)
{
	struct nlmsgreq *req = (struct nlmsgreq *)buf;
	memset(buf, 0, sizeof(struct nlmsgreq));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req->h.nlmsg_flags = NLM_F_REQUEST;
	req->h.nlmsg_type = NFNL_MSG_BATCH_END;
	req->h.nlmsg_seq = time(NULL);

	req->m.res_id = htons(NFNL_SUBSYS_NFTABLES);

	if (nextbuf) {
		*nextbuf = (uint8_t *)buf + req->h.nlmsg_len;
	}

	return 0;
}

static int _nftset_socket_init(struct nftset_socket_slot *slot)
{
	struct sockaddr_nl addr = {0};
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	int fd = -1;

	if (slot->fd >= 0) {
		return 0;
	}

	fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
	if (fd < 0) {
		return -1;
	}

	if (bind(fd, (struct sockaddr *)(&addr), sizeof(addr)) < 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -2;
	}

	slot->fd = fd;
	return 0;
}

static int _nftset_socket_request(void *msg, int msg_len, void *ret_msg, int ret_msg_len)
{
	int ret = -1;
	int saved_errno = 0;
	int len = 0;
	int do_recv = 0;
	int retry_count = 0;
	int stale_msg_count = 0;
	int wait_for_data = 1;
	const int max_retries = 3;
	struct pollfd pfds;
	struct timespec deadline;
	struct nftset_socket_slot *slot = NULL;
	uint8_t recv_buff[PAYLOAD_MAX];
	uint8_t matching_buff[PAYLOAD_MAX];
	uint32_t seq = 0;

	if (msg == NULL || msg_len < (int)sizeof(struct nlmsghdr) ||
		(ret_msg != NULL && ret_msg_len <= 0)) {
		errno = EINVAL;
		return -1;
	}

	slot = _nftset_socket_acquire();
	if (_nftset_socket_init(slot) != 0) {
		if (dns_conf.nftset_debug_enable) {
			tlog(TLOG_DEBUG, "nftset socket init failed, errno=%d", errno);
		}
		goto out;
	}

	/* All messages in a batch use one unique sequence number. */
	seq = _nftset_assign_sequence(msg, msg_len);

	/* Clear replies left by a previous completed or timed-out request on this slot. */
	for (;;) {
		ret = recv(slot->fd, recv_buff, sizeof(recv_buff), MSG_DONTWAIT);
		if (ret < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && dns_conf.nftset_debug_enable) {
				tlog(TLOG_DEBUG, "nftset clear pending msg error, errno=%d", errno);
			}
			break;
		}
	}

	/* Send message with retry. */
	while (retry_count < max_retries) {
		len = send(slot->fd, msg, msg_len, 0);
		if (len == msg_len) {
			break;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			retry_count++;
			struct timespec waiter = {.tv_sec = 0, .tv_nsec = 10000 * retry_count};
			nanosleep(&waiter, NULL);
			continue;
		}

		if (dns_conf.nftset_debug_enable) {
			tlog(TLOG_DEBUG, "nftset send msg failed, errno=%d, retries=%d", errno, retry_count);
		}
		goto out;
	}

	if (retry_count >= max_retries) {
		if (dns_conf.nftset_debug_enable) {
			tlog(TLOG_DEBUG, "nftset send msg failed after max retries");
		}
		goto out;
	}

	if (ret_msg == NULL || ret_msg_len <= 0) {
		ret = 0;
		goto out;
	}

	pfds.fd = slot->fd;
	pfds.events = POLLIN;
	pfds.revents = 0;
	memset(ret_msg, 0, ret_msg_len);
	len = 0;
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		goto out;
	}
	deadline.tv_nsec += 100000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}

	for (;;) {
		if (wait_for_data) {
			struct timespec now;
			if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
				goto out;
			}
			long long remaining_ns = ((long long)deadline.tv_sec - now.tv_sec) * 1000000000LL +
								 deadline.tv_nsec - now.tv_nsec;
			if (remaining_ns <= 0) {
				if (do_recv) {
					ret = 0;
					break;
				}
				errno = ETIMEDOUT;
				goto out;
			}

			int timeout_ms = (int)((remaining_ns + 999999LL) / 1000000LL);
			pfds.revents = 0;
			ret = poll(&pfds, 1, timeout_ms);
			if (ret < 0 && errno == EINTR) {
				continue;
			}
			if (ret <= 0) {
				if (ret == 0 && do_recv) {
					ret = 0;
					break;
				}
				if (ret == 0) {
					errno = ETIMEDOUT;
				}
				if (dns_conf.nftset_debug_enable) {
					tlog(TLOG_DEBUG, "nftset poll timeout or error, ret=%d, errno=%d", ret, errno);
				}
				goto out;
			}

			if ((pfds.revents & POLLIN) == 0) {
				if (dns_conf.nftset_debug_enable) {
					tlog(TLOG_DEBUG, "nftset poll no data, revents=0x%x", pfds.revents);
				}
				errno = EIO;
				goto out;
			}
		}

		wait_for_data = 0;
		ret = recv(slot->fd, recv_buff, sizeof(recv_buff), MSG_DONTWAIT);
		if (ret < 0) {
			if ((errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) && do_recv) {
				ret = 0;
				break;
			}
			if ((errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) && stale_msg_count > 0) {
				wait_for_data = 1;
				continue;
			}
			if (dns_conf.nftset_debug_enable) {
				tlog(TLOG_DEBUG, "nftset recv msg failed, errno=%d", errno);
			}
			goto out;
		}

		int remaining = ret;
		int matched_len = 0;
		struct nlmsghdr *response = (struct nlmsghdr *)recv_buff;
		while (NLMSG_OK(response, remaining)) {
			int copy_len = NLMSG_ALIGN(response->nlmsg_len);
			if (copy_len > remaining) {
				copy_len = response->nlmsg_len;
			}
			if (response->nlmsg_seq == seq) {
				if (matched_len + copy_len > (int)sizeof(recv_buff)) {
					errno = ENOSPC;
					goto out;
				}
				memcpy(matching_buff + matched_len, response, copy_len);
				matched_len += copy_len;
			}
			response = NLMSG_NEXT(response, remaining);
		}

		if (matched_len > 0) {
			memcpy(recv_buff, matching_buff, matched_len);
		}
		if (matched_len == 0) {
			if (++stale_msg_count > 32) {
				errno = ETIMEDOUT;
				goto out;
			}
			wait_for_data = 1;
			continue;
		}

		if (matched_len > ret_msg_len - len) {
			errno = ENOSPC;
			goto out;
		}
		memcpy((uint8_t *)ret_msg + len, recv_buff, matched_len);
		do_recv = 1;
		len += matched_len;

		struct nlmsghdr *nlh = (struct nlmsghdr *)ret_msg;
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
				errno = EBADMSG;
				goto out;
			}
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
			if (err->error != 0) {
				errno = -err->error;
				if (dns_conf.nftset_debug_enable) {
					tlog(TLOG_DEBUG, "nftset recv error msg, error=%d", err->error);
				}
				goto out;
			}
			continue;
		}

		/* Correctly handle the NFT_MSG_GETSETELEM response. */
		if (nlh->nlmsg_type == (NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSETELEM)) {
			ret = 0;
			break;
		}

		if (nlh->nlmsg_type == (NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETSETELEM)) {
			wait_for_data = 1;
			continue;
		}

		if (nlh->nlmsg_type & (NFNL_SUBSYS_NFTABLES << 8)) {
			if (nlh->nlmsg_type & NLMSG_DONE) {
				ret = 0;
				break;
			}
		}

		errno = ENOTSUP;
		if (dns_conf.nftset_debug_enable) {
			tlog(TLOG_DEBUG, "nftset unsupported msg type, type=0x%x", nlh->nlmsg_type);
		}
		goto out;
	}

	ret = 0;
out:
	saved_errno = errno;
	pthread_mutex_unlock(&slot->lock);
	errno = saved_errno;
	return ret;
}

static int _nftset_socket_send(void *msg, int msg_len)
{
	char recvbuff[1024];

	if (dns_conf.nftset_debug_enable == 0) {
		return _nftset_socket_request(msg, msg_len, NULL, 0);
	}

	return _nftset_socket_request(msg, msg_len, recvbuff, sizeof(recvbuff));
}

static int _nftset_get_nftset(int nffamily, const char *table_name, const char *setname, void *buf, void **nextbuf)
{
	struct nlmsgreq *req = (struct nlmsgreq *)buf;
	memset(buf, 0, sizeof(struct nlmsgreq));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req->h.nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETSET;
	req->h.nlmsg_seq = time(NULL);

	req->m.nfgen_family = nffamily;
	req->m.res_id = htons(NFNL_SUBSYS_NFTABLES);
	req->m.version = 0;

	struct nlmsghdr *n = &req->h;

	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_SET, setname);
	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_TABLE, table_name);

	if (nextbuf) {
		*nextbuf = (uint8_t *)buf + req->h.nlmsg_len;
	}

	return 0;
}

static int _nftset_get_flags(int nffamily, const char *tablename, const char *setname, uint32_t *flags)
{
	uint8_t buf[PAYLOAD_MAX];
	uint8_t result[PAYLOAD_MAX];
	void *next = buf;
	int buffer_len = 0;

	if (flags == NULL) {
		return -1;
	}

	_nftset_get_nftset(nffamily, tablename, setname, next, &next);
	buffer_len = (uint8_t *)next - buf;
	int ret = _nftset_socket_request(buf, buffer_len, result, sizeof(result));
	if (ret < 0) {
		return -1;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)result;
	struct nfgenmsg *nfmsg = (struct nfgenmsg *)NLMSG_DATA(nlh);
	struct nfattr *nfa = (struct nfattr *)NFM_NFA(nfmsg);
	*flags = 0;
	for (; NFA_OK(nfa, nlh->nlmsg_len); nfa = NFA_NEXT(nfa, nlh->nlmsg_len)) {
		if (nfa->nfa_type == NFTA_SET_FLAGS) {
			*flags = ntohl(*(uint32_t *)NFA_DATA(nfa));
			break;
		}
	}

	return 0;
}

static int _nftset_del_element(int nffamily, const char *table_name, const char *setname, const void *data,
							   int data_len, const void *data_interval, int data_interval_len, void *buf,
							   void **nextbuf)
{
	struct nlmsgreq *req = (struct nlmsgreq *)buf;
	memset(buf, 0, sizeof(struct nlmsgreq));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req->h.nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELSETELEM;
	req->h.nlmsg_seq = time(NULL);

	if (dns_conf.nftset_debug_enable) {
		req->h.nlmsg_flags |= NLM_F_ACK;
	}

	req->m.nfgen_family = nffamily;

	struct nlmsghdr *n = &req->h;

	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_TABLE, table_name);
	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_SET, setname);
	struct rtattr *nest_list = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_LIST_ELEMENTS);
	struct rtattr *nest_elem = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED);

	struct rtattr *nest_elem_key = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_KEY);
	_nftset_addattr(n, PAYLOAD_MAX, NFTA_DATA_VALUE, data, data_len);
	_nftset_addattr_nest_end(n, nest_elem_key);
	_nftset_addattr_nest_end(n, nest_elem);

	/* interval attribute */
	if (data_interval && data_interval_len > 0) {
		struct rtattr *nest_interval_end = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_LIST_ELEM);
		_nftset_addattr_uint32(n, PAYLOAD_MAX, NFTA_SET_ELEM_FLAGS, htonl(NFT_SET_ELEM_INTERVAL_END));
		struct rtattr *nest_elem_interval_key = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_KEY);

		_nftset_addattr(n, PAYLOAD_MAX, NFTA_DATA_VALUE, data_interval, data_interval_len);
		_nftset_addattr_nest_end(n, nest_elem_interval_key);
		_nftset_addattr_nest_end(n, nest_interval_end);
	}

	_nftset_addattr_nest_end(n, nest_list);

	if (nextbuf) {
		*nextbuf = (uint8_t *)buf + req->h.nlmsg_len;
	}

	return 0;
}

static int _nftset_add_element(int nffamily, const char *table_name, const char *setname, const void *data,
							   int data_len, const void *data_interval, int data_interval_len, unsigned long timeout,
							   void *buf, void **nextbuf)
{
	struct nlmsgreq *req = (struct nlmsgreq *)buf;
	memset(buf, 0, sizeof(struct nlmsgreq));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req->h.nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSETELEM;
	req->h.nlmsg_seq = time(NULL);

	if (dns_conf.nftset_debug_enable) {
		req->h.nlmsg_flags |= NLM_F_ACK;
	}

	req->m.nfgen_family = nffamily;

	struct nlmsghdr *n = &req->h;

	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_TABLE, table_name);
	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_SET, setname);
	struct rtattr *nest_list = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_LIST_ELEMENTS);

	struct rtattr *nest_elem = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_LIST_ELEM);
	struct rtattr *nest_elem_key = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_KEY);
	_nftset_addattr(n, PAYLOAD_MAX, NFTA_DATA_VALUE, data, data_len);
	_nftset_addattr_nest_end(n, nest_elem_key);
	if (timeout > 0) {
		uint64_t timeout_value = htobe64(timeout * 1000);
		_nftset_addattr(n, PAYLOAD_MAX, NFTA_SET_ELEM_TIMEOUT, &timeout_value, sizeof(timeout_value));
	}
	_nftset_addattr_nest_end(n, nest_elem);

	/* interval attribute */
	if (data_interval && data_interval_len > 0) {
		struct rtattr *nest_interval_end = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_LIST_ELEM);
		_nftset_addattr_uint32(n, PAYLOAD_MAX, NFTA_SET_ELEM_FLAGS, htonl(NFT_SET_ELEM_INTERVAL_END));
		struct rtattr *nest_elem_interval_key = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_KEY);

		_nftset_addattr(n, PAYLOAD_MAX, NFTA_DATA_VALUE, data_interval, data_interval_len);
		_nftset_addattr_nest_end(n, nest_elem_interval_key);
		_nftset_addattr_nest_end(n, nest_interval_end);
	}

	_nftset_addattr_nest_end(n, nest_list);

	if (nextbuf) {
		*nextbuf = (uint8_t *)buf + req->h.nlmsg_len;
	}

	return 0;
}

static int _nftset_process_setflags(uint32_t flags, const unsigned char addr[], int addr_len, unsigned long *timeout,
									uint8_t **interval_addr, int *interval_addr_len)
{
	uint8_t *addr_end = *interval_addr;

	if ((flags & NFT_SET_TIMEOUT) == 0 && timeout != NULL) {
		*timeout = 0;
	}

	if ((flags & NFT_SET_INTERVAL) && addr_end != NULL && (addr_len == 4 || addr_len == 16)) {
		/* interval end is addr + 1, carried across bytes (x.x.x.255 -> x.x.(x+1).0) */
		int i = addr_len - 1;
		memcpy(addr_end, addr, addr_len);
		while (i >= 0 && ++addr_end[i] == 0) {
			i--;
		}
		if (i < 0) {
			/* the last address of the family has no end */
			return -1;
		}
		*interval_addr_len = addr_len;
	} else {
		*interval_addr = NULL;
		*interval_addr_len = 0;
	}

	return 0;
}

/* Check whether the IP address already exists in the nftables collection */
static int _nftset_test_ip_exists(int nffamily, const char *tablename, const char *setname, const unsigned char addr[],
								  int addr_len)
{
	uint8_t buf[PAYLOAD_MAX];
	uint8_t result[PAYLOAD_MAX];
	void *next = buf;
	int buffer_len = 0;

	/* Initialize test message */
	struct nlmsgreq *req = (struct nlmsgreq *)next;
	memset(next, 0, sizeof(struct nlmsgreq));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	req->h.nlmsg_flags = NLM_F_REQUEST;
	req->h.nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETSETELEM;
	req->h.nlmsg_seq = time(NULL);
	req->m.nfgen_family = nffamily;
	req->m.res_id = htons(NFNL_SUBSYS_NFTABLES);
	req->m.version = 0;

	struct nlmsghdr *n = &req->h;

	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_TABLE, tablename);
	_nftset_addattr_string(n, PAYLOAD_MAX, NFTA_SET_ELEM_LIST_SET, setname);

	struct rtattr *nest_list = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_LIST_ELEMENTS);
	struct rtattr *nest_elem = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_LIST_ELEM);
	struct rtattr *nest_elem_key = _nftset_addattr_nest(n, PAYLOAD_MAX, NLA_F_NESTED | NFTA_SET_ELEM_KEY);
	_nftset_addattr(n, PAYLOAD_MAX, NFTA_DATA_VALUE, addr, addr_len);
	_nftset_addattr_nest_end(n, nest_elem_key);
	_nftset_addattr_nest_end(n, nest_elem);
	_nftset_addattr_nest_end(n, nest_list);

	next = (uint8_t *)next + req->h.nlmsg_len;
	buffer_len = (uint8_t *)next - buf;

	if (dns_conf.nftset_debug_enable) {
		char ip_str[INET6_ADDRSTRLEN];
		if (addr_len == 4) {
			inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
		} else if (addr_len == 16) {
			inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
		} else {
			snprintf(ip_str, sizeof(ip_str), "unknown");
		}
		tlog(TLOG_DEBUG, "nftset test ip: family=%d, table=%s, set=%s, ip=%s", nffamily, tablename, setname, ip_str);
	}

	/* Send a test message and receive a response */
	int ret = _nftset_socket_request(buf, buffer_len, result, sizeof(result));

	if (ret < 0) {
		/* errorno=-2 */
		if (errno == ENOENT) {
			if (dns_conf.nftset_debug_enable) {
				tlog(TLOG_DEBUG, "nftset test ip: table/set not found, assuming ip not exists");
			}
			return 0;
		}
		/* errorno=11 */
		else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (dns_conf.nftset_debug_enable) {
				tlog(TLOG_DEBUG, "nftset test ip: EAGAIN error, existence unknown");
			}
			return NFTSET_IP_UNKNOWN;
		}

		if (dns_conf.nftset_debug_enable) {
			char ip_str[INET6_ADDRSTRLEN];
			if (addr_len == 4) {
				inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
			} else if (addr_len == 16) {
				inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
			} else {
				snprintf(ip_str, sizeof(ip_str), "unknown");
			}
			tlog(TLOG_DEBUG,
				 "nftset test ip communication failed, assuming ip not exists: family=%d, table=%s, set=%s, ip=%s, "
				 "errorno:%d",
				 nffamily, tablename, setname, ip_str, errno);
		}
		return 0;
	}

	int ip_exists = NFTSET_IP_NOT_EXIST;

	struct nlmsghdr *nlh = (struct nlmsghdr *)result;

	/* If a successful response is received, it indicates that the IP already exists */
	if (nlh->nlmsg_type == (NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSETELEM)) {
		ip_exists = NFTSET_IP_EXIST;
	}

	/* Received an error message */
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		if (err->error == -ENOENT) {
			ip_exists = NFTSET_IP_NOT_EXIST;
		} else if (dns_conf.nftset_debug_enable) {
			tlog(TLOG_DEBUG, "nftset test ip error: family=%d, table=%s, set=%s, error=%d", nffamily, tablename,
				 setname, -err->error);
		}
	}

	if (dns_conf.nftset_debug_enable) {
		char ip_str[INET6_ADDRSTRLEN];
		if (addr_len == 4) {
			inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
		} else if (addr_len == 16) {
			inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
		} else {
			snprintf(ip_str, sizeof(ip_str), "unknown");
		}
		tlog(TLOG_DEBUG, "nftset test ip result: family=%d, table=%s, set=%s, ip=%s, exists=%d", nffamily, tablename,
			 setname, ip_str, ip_exists);
	}

	return ip_exists;
}

static int _nftset_del(int nffamily, const char *tablename, const char *setname, const unsigned char addr[],
					   int addr_len, const unsigned char addr_end[], int addr_end_len)
{
	uint8_t buf[PAYLOAD_MAX];
	void *next = buf;
	int buffer_len = 0;

	_nftset_start_batch(next, &next);
	_nftset_del_element(nffamily, tablename, setname, addr, addr_len, addr_end, addr_end_len, next, &next);
	_nftset_end_batch(next, &next);
	buffer_len = (uint8_t *)next - buf;
	return _nftset_socket_send(buf, buffer_len);
}

int nftset_del(const char *familyname, const char *tablename, const char *setname, const unsigned char addr[],
			   int addr_len)
{
	int nffamily = _nftset_get_nffamily_from_str(familyname);

	uint8_t addr_end_buff[16] = {0};
	uint8_t *addr_end = addr_end_buff;
	uint32_t flags = 0;
	int addr_end_len = 0;
	int ret = -1;

	ret = _nftset_get_flags(nffamily, tablename, setname, &flags);
	if (ret == 0) {
		ret = _nftset_process_setflags(flags, addr, addr_len, NULL, &addr_end, &addr_end_len);
		if (ret != 0) {
			return -1;
		}
	} else {
		addr_end = NULL;
		addr_end_len = 0;
	}

	ret = _nftset_del(nffamily, tablename, setname, addr, addr_len, addr_end, addr_end_len);
	if (ret != 0 && errno != ENOENT) {
		tlog(TLOG_ERROR, "nftset delete failed, family:%s, table:%s, set:%s, error:%s", familyname, tablename, setname,
			 strerror(errno));
	}

	return ret;
}

int nftset_add(const char *familyname, const char *tablename, const char *setname, const unsigned char addr[],
			   int addr_len, unsigned long timeout)
{
	int nffamily = _nftset_get_nffamily_from_str(familyname);
	uint8_t buf[PAYLOAD_MAX];
	uint8_t addr_end_buff[16] = {0};
	uint8_t *addr_end = addr_end_buff;
	uint32_t flags = 0;
	int addr_end_len = 0;
	void *next = buf;
	int buffer_len = 0;
	int ret = -1;

	ret = _nftset_get_flags(nffamily, tablename, setname, &flags);
	if (ret == 0) {
		ret = _nftset_process_setflags(flags, addr, addr_len, &timeout, &addr_end, &addr_end_len);
		if (ret != 0) {
			char ip_str[INET6_ADDRSTRLEN];
			if (addr_len == 4) {
				inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
			} else if (addr_len == 16) {
				inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
			} else {
				snprintf(ip_str, sizeof(ip_str), "unknown");
			}

			if (dns_conf.nftset_debug_enable) {
				tlog(TLOG_ERROR, "nftset setflags failed, family:%s, table:%s, set:%s, ip:%s, error:%s", familyname,
					 tablename, setname, ip_str, "ip is invalid");
			}
			return -1;
		}
	} else {
		addr_end = NULL;
		addr_end_len = 0;
	}

	int ip_exists = _nftset_test_ip_exists(nffamily, tablename, setname, addr, addr_len);
	if (ip_exists == NFTSET_IP_EXIST && timeout == 0) {
		if (dns_conf.nftset_debug_enable) {
			char ip_str[INET6_ADDRSTRLEN];
			if (addr_len == 4) {
				inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
			} else if (addr_len == 16) {
				inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
			} else {
				snprintf(ip_str, sizeof(ip_str), "unknown");
			}
			tlog(TLOG_DEBUG, "nftset skip adding existing ip: family=%d, table=%s, set=%s, ip=%s", nffamily, tablename,
				 setname, ip_str);
		}
		return 0;
	}

	if (ip_exists != NFTSET_IP_EXIST && timeout > 0) {
		/*
		 * An element that timed out but is not garbage collected yet is not found, but can still block the
		 * add on some kernels. Delete it in its own message: the element may not exist at all, which would
		 * reject a combined batch.
		 */
		_nftset_del(nffamily, tablename, setname, addr, addr_len, addr_end, addr_end_len);
	}

	_nftset_start_batch(next, &next);
	if (ip_exists == NFTSET_IP_EXIST) {
		/*
		 * Refresh the timeout: delete and add in one batch (one transaction), so the address never
		 * leaves the set. If it is only covered by a wider range the delete fails and the batch is
		 * rejected as a whole, leaving the range untouched.
		 */
		_nftset_del_element(nffamily, tablename, setname, addr, addr_len, addr_end, addr_end_len, next, &next);
	}
	_nftset_add_element(nffamily, tablename, setname, addr, addr_len, addr_end, addr_end_len, timeout, next, &next);
	_nftset_end_batch(next, &next);
	buffer_len = (uint8_t *)next - buf;

	ret = _nftset_socket_send(buf, buffer_len);
	if (ret != 0) {
		char ip_str[INET6_ADDRSTRLEN];
		if (addr_len == 4) {
			inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
		} else if (addr_len == 16) {
			inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
		} else {
			snprintf(ip_str, sizeof(ip_str), "unknown");
		}

		tlog(TLOG_ERROR, "nftset add failed, family:%s, table:%s, set:%s, ip:%s, error:%s", familyname, tablename,
			 setname, ip_str, strerror(errno));
	} else {
		if (dns_conf.nftset_debug_enable) {
			char ip_str[INET6_ADDRSTRLEN];
			if (addr_len == 4) {
				inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
			} else if (addr_len == 16) {
				inet_ntop(AF_INET6, addr, ip_str, sizeof(ip_str));
			} else {
				snprintf(ip_str, sizeof(ip_str), "unknown");
			}

			if (timeout > 0) {
				tlog(TLOG_DEBUG, "nftset add success, family:%s, table:%s, set:%s, ip:%s, timeout:%lu", familyname,
					 tablename, setname, ip_str, timeout);
			} else {
				tlog(TLOG_DEBUG, "nftset add success, family:%s, table:%s, set:%s, ip:%s", familyname, tablename,
					 setname, ip_str);
			}
		}
	}

	return ret;
}

#else

int nftset_add(const char *familyname, const char *tablename, const char *setname, const unsigned char addr[],
			   int addr_len, unsigned long timeout)
{
	return 0;
}

int nftset_del(const char *familyname, const char *tablename, const char *setname, const unsigned char addr[],
			   int addr_len)
{
	return 0;
}

#endif