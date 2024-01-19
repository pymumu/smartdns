/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "nftset.h"
#include "../dns_conf.h"
#include "../tlog.h"
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <memory.h>
#include <poll.h>
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

static int nftset_fd;

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

	req->m.res_id = NFNL_SUBSYS_NFTABLES;

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

	req->m.res_id = NFNL_SUBSYS_NFTABLES;

	if (nextbuf) {
		*nextbuf = (uint8_t *)buf + req->h.nlmsg_len;
	}

	return 0;
}

static int _nftset_socket_init(void)
{
	struct sockaddr_nl addr = {0};
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	int fd = 0;

	if (nftset_fd > 0) {
		return 0;
	}

	fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
	if (fd < 0) {
		return -1;
	}

	if (bind(fd, (struct sockaddr *)(&addr), sizeof(addr)) < 0) {
		close(fd);
		return -2;
	}

	nftset_fd = fd;

	return 0;
}

static int _nftset_socket_request(void *msg, int msg_len, void *ret_msg, int ret_msg_len)
{
	int ret = -1;
	struct pollfd pfds;
	int do_recv = 0;
	int len = 0;

	if (_nftset_socket_init() != 0) {
		return -1;
	}

	/* clear pending error message*/
	for (;;) {
		uint8_t buff[1024];
		ret = recv(nftset_fd, buff, sizeof(buff), MSG_DONTWAIT);
		if (ret < 0) {
			break;
		}
	}

	for (;;) {
		len = send(nftset_fd, msg, msg_len, 0);
		if (len == msg_len) {
			break;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			struct timespec waiter;
			waiter.tv_sec = 0;
			waiter.tv_nsec = 10000;
			nanosleep(&waiter, NULL);
			continue;
		}

		return -1;
	}

	if (ret_msg == NULL || ret_msg_len <= 0) {
		return 0;
	}

	pfds.fd = nftset_fd;
	pfds.events = POLLIN;
	pfds.revents = 0;
	ret = poll(&pfds, 1, 100);
	if (ret <= 0) {
		return -1;
	}

	if ((pfds.revents & POLLIN) == 0) {
		return -1;
	}

	memset(ret_msg, 0, ret_msg_len);
	len = 0;
	for (;;) {
		ret = recv(nftset_fd, ret_msg + len, ret_msg_len - len, 0);
		if (ret < 0) {
			if (errno == EAGAIN && do_recv == 1) {
				break;
			}

			return -1;
		}

		do_recv = 1;
		len += ret;

		struct nlmsghdr *nlh = (struct nlmsghdr *)ret_msg;
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
			if (err->error != 0) {
				errno = -err->error;
				return -1;
			}

			continue;
		}

		if (nlh->nlmsg_type & (NFNL_SUBSYS_NFTABLES << 8)) {
			if (nlh->nlmsg_type & NLMSG_DONE) {
				break;
			}
		}

		errno = ENOTSUP;
		return -1;
	}

	return 0;
}

static int _nftset_socket_send(void *msg, int msg_len)
{
	char recvbuff[1024];

	if (dns_conf_nftset_debug_enable == 0) {
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
	req->m.res_id = NFNL_SUBSYS_NFTABLES;
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

	if (dns_conf_nftset_debug_enable) {
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

	if (dns_conf_nftset_debug_enable) {
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

	if ((flags & NFT_SET_INTERVAL) && addr_end != NULL) {
		if (addr_len == 4) {
			addr_end[0] = addr[0];
			addr_end[1] = addr[1];
			addr_end[2] = addr[2];
			addr_end[3] = addr[3] + 1;
			if (addr_end[3] == 0) {
				return -1;
			}

			*interval_addr_len = 4;
		} else if (addr_len == 16) {
			memcpy(addr_end, addr, 16);
			addr_end[15] = addr[15] + 1;
			if (addr_end[15] == 0) {
				return -1;
			}
			*interval_addr_len = 16;
		}
	} else {
		*interval_addr = NULL;
		*interval_addr_len = 0;
	}

	return 0;
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
		ret = _nftset_process_setflags(flags, addr, addr_len, 0, &addr_end, &addr_end_len);
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
	uint8_t buf[PAYLOAD_MAX];
	uint8_t addr_end_buff[16] = {0};
	uint8_t *addr_end = addr_end_buff;
	uint32_t flags = 0;
	int addr_end_len = 0;
	void *next = buf;
	int buffer_len = 0;
	int ret = -1;
	int nffamily = _nftset_get_nffamily_from_str(familyname);

	ret = _nftset_get_flags(nffamily, tablename, setname, &flags);
	if (ret == 0) {
		ret = _nftset_process_setflags(flags, addr, addr_len, &timeout, &addr_end, &addr_end_len);
		if (ret != 0) {
			if (dns_conf_nftset_debug_enable) {
				tlog(TLOG_ERROR, "nftset add failed, family:%s, table:%s, set:%s, error:%s", familyname, tablename,
					 setname, "ip is invalid");
			}
			return -1;
		}
	} else {
		addr_end = NULL;
		addr_end_len = 0;
	}

	if (timeout > 0) {
		_nftset_del(nffamily, tablename, setname, addr, addr_len, addr_end, addr_end_len);
	}

	_nftset_start_batch(next, &next);
	_nftset_add_element(nffamily, tablename, setname, addr, addr_len, addr_end, addr_end_len, timeout, next, &next);
	_nftset_end_batch(next, &next);
	buffer_len = (uint8_t *)next - buf;

	ret = _nftset_socket_send(buf, buffer_len);
	if (ret != 0) {
		tlog(TLOG_ERROR, "nftset add failed, family:%s, table:%s, set:%s, error:%s", familyname, tablename, setname,
			 strerror(errno));
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