/*
 * Copyright (c) 1999-2000
 * 
 * The Regents of the University of Michigan ("The Regents") and
 * Merit Network, Inc. All rights reserved.  Redistribution and use
 * in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above 
 * copyright notice, this list of conditions and the 
 * following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above 
 * copyright notice, this list of conditions and the 
 * following disclaimer in the documentation and/or other 
 * materials provided with the distribution.
 * 
 * 3. All advertising materials mentioning features or use of 
 * this software must display the following acknowledgement:
 * 
 *   This product includes software developed by the University of
 *   Michigan, Merit Network, Inc., and their contributors.
 * 
 * 4. Neither the name of the University, Merit Network, nor the
 * names of their contributors may be used to endorse or 
 * promote products derived from this software without 
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL TH E REGENTS
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HO WEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Portions Copyright (c) 2004,2005 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: radix.h,v 1.9 2007/10/24 06:03:08 djm Exp $ */

#ifndef _RADIX_H
#define _RADIX_H

#if defined(_MSC_VER)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif

#if defined(_MSC_VER)
# define snprintf _snprintf
typedef unsigned __int8		u_int8_t;
typedef unsigned __int16	u_int16_t;
typedef unsigned __int32	u_int32_t;
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

/*
 * Originally from MRT include/mrt.h
 * $MRTId: mrt.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */
typedef struct _prefix_t {
	u_int family;			/* AF_INET | AF_INET6 */
	u_int bitlen;			/* same as mask? */
	int ref_count;			/* reference count */
	union {
		struct in_addr sin;
		struct in6_addr sin6;
	} add;
} prefix_t;

void Deref_Prefix(prefix_t *prefix);

/*
 * Originally from MRT include/radix.h
 * $MRTId: radix.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */
typedef struct _radix_node_t {
	u_int bit;			/* flag if this node used */
	prefix_t *prefix;		/* who we are in radix tree */
	struct _radix_node_t *l, *r;	/* left and right children */
	struct _radix_node_t *parent;	/* may be used */
	void *data;			/* pointer to data */
} radix_node_t;

typedef struct _radix_tree_t {
	radix_node_t *head;
	u_int maxbits;			/* for IP, 32 bit addresses */
	int num_active_node;		/* for debug purpose */
} radix_tree_t;

/* Type of callback function */
typedef void (*rdx_cb_t)(radix_node_t *, void *);

radix_tree_t *New_Radix(void);
void Destroy_Radix(radix_tree_t *radix, rdx_cb_t func, void *cbctx);
radix_node_t *radix_lookup(radix_tree_t *radix, prefix_t *prefix);
void radix_remove(radix_tree_t *radix, radix_node_t *node);
radix_node_t *radix_search_exact(radix_tree_t *radix, prefix_t *prefix);
radix_node_t *radix_search_best(radix_tree_t *radix, prefix_t *prefix);
void radix_process(radix_tree_t *radix, rdx_cb_t func, void *cbctx);

#define RADIX_MAXBITS 128

#define RADIX_WALK(Xhead, Xnode) \
	do { \
		radix_node_t *Xstack[RADIX_MAXBITS+1]; \
		radix_node_t **Xsp = Xstack; \
		radix_node_t *Xrn = (Xhead); \
		while ((Xnode = Xrn)) { \
			if (Xnode->prefix)

#define RADIX_WALK_END \
			if (Xrn->l) { \
				if (Xrn->r) { \
					*Xsp++ = Xrn->r; \
				} \
				Xrn = Xrn->l; \
			} else if (Xrn->r) { \
				Xrn = Xrn->r; \
			} else if (Xsp != Xstack) { \
				Xrn = *(--Xsp); \
			} else { \
				Xrn = (radix_node_t *) 0; \
			} \
		} \
	} while (0)

/* Local additions */

prefix_t *prefix_pton(const char *string, long len, prefix_t *prefix, const char **errmsg);
prefix_t *prefix_from_blob(unsigned char *blob, int len, int prefixlen, prefix_t *prefix);
const char *prefix_addr_ntop(prefix_t *prefix, char *buf, size_t len);
const char *prefix_ntop(prefix_t *prefix, char *buf, size_t len);

#endif /* _RADIX_H */

