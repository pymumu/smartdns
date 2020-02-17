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

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "radix.h"

/* $Id: radix.c,v 1.17 2007/10/24 06:04:31 djm Exp $ */

/*
 * Originally from MRT include/defs.h
 * $MRTId: defs.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */
#define BIT_TEST(f, b)  ((f) & (b))

/*
 * Originally from MRT include/mrt.h
 * $MRTId: mrt.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */
#define prefix_tochar(prefix)		((char *)&(prefix)->add)
#define prefix_touchar(prefix)		((unsigned char *)&(prefix)->add)

/*
 * Originally from MRT lib/mrt/prefix.c
 * $MRTId: prefix.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

static int
comp_with_mask(unsigned char *addr, unsigned char *dest, unsigned int mask)
{
	if (memcmp(addr, dest, mask / 8) == 0) {
		unsigned int n = mask / 8;
		unsigned int m = ((~0) << (8 - (mask % 8)));

		if (mask % 8 == 0 || (addr[n] & m) == (dest[n] & m))
			return (1);
	}
	return (0);
}

static prefix_t 
*New_Prefix2(int family, void *dest, int bitlen, prefix_t *prefix)
{
	int dynamic_allocated = 0;
	int default_bitlen = 32;

	if (family == AF_INET6) {
		default_bitlen = 128;
		if (prefix == NULL) {
			if ((prefix = malloc(sizeof(*prefix))) == NULL)
				return (NULL);
			memset(prefix, '\0', sizeof(*prefix));
			dynamic_allocated++;
		}
		memcpy(&prefix->add.sin6, dest, 16);
	} else if (family == AF_INET) {
		if (prefix == NULL) {
			if ((prefix = malloc(sizeof(*prefix))) == NULL)
				return (NULL);
			memset(prefix, '\0', sizeof(*prefix));
			dynamic_allocated++;
		}
		memcpy(&prefix->add.sin, dest, 4);
	} else
		return (NULL);

	prefix->bitlen = (bitlen >= 0) ? bitlen : default_bitlen;
	prefix->family = family;
	prefix->ref_count = 0;
	if (dynamic_allocated)
		prefix->ref_count++;
	return (prefix);
}


static prefix_t 
*Ref_Prefix(prefix_t *prefix)
{
	if (prefix == NULL)
		return (NULL);
	if (prefix->ref_count == 0) {
		/* make a copy in case of a static prefix */
		return (New_Prefix2(prefix->family, &prefix->add,
		    prefix->bitlen, NULL));
	}
	prefix->ref_count++;
	return (prefix);
}


void
Deref_Prefix(prefix_t *prefix)
{
	if (prefix == NULL)
		return;
	prefix->ref_count--;
	if (prefix->ref_count <= 0) {
		free(prefix);
		return;
	}
}

/*
 * Originally from MRT lib/radix/radix.c
 * $MRTId: radix.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

/* these routines support continuous mask only */

radix_tree_t
*New_Radix(void)
{
	radix_tree_t *radix;

	if ((radix = malloc(sizeof(*radix))) == NULL)
		return (NULL);
	memset(radix, '\0', sizeof(*radix));

	radix->maxbits = 128;
	radix->head = NULL;
	radix->num_active_node = 0;
	return (radix);
}

/*
 * if func is supplied, it will be called as func(node->data)
 * before deleting the node
 */
static void
Clear_Radix(radix_tree_t *radix, rdx_cb_t func, void *cbctx)
{
	if (radix->head) {
		radix_node_t *Xstack[RADIX_MAXBITS + 1];
		radix_node_t **Xsp = Xstack;
		radix_node_t *Xrn = radix->head;

		while (Xrn) {
			radix_node_t *l = Xrn->l;
			radix_node_t *r = Xrn->r;

			if (Xrn->prefix) {
				Deref_Prefix(Xrn->prefix);
				if (Xrn->data && func)
					func(Xrn, cbctx);
			}
			free(Xrn);
			radix->num_active_node--;

			if (l) {
				if (r)
					*Xsp++ = r;
				Xrn = l;
			} else if (r) {
				Xrn = r;
			} else if (Xsp != Xstack) {
				Xrn = *(--Xsp);
			} else {
				Xrn = (radix_node_t *) 0;
			}
		}
	}
}

void
Destroy_Radix(radix_tree_t *radix, rdx_cb_t func, void *cbctx)
{
	if (radix == NULL) {
		return;
	}
	Clear_Radix(radix, func, cbctx);
	free(radix);
}

/*
 * if func is supplied, it will be called as func(node->prefix, node->data)
 */
void
radix_process(radix_tree_t *radix, rdx_cb_t func, void *cbctx)
{
	radix_node_t *node;

	RADIX_WALK(radix->head, node) {
		func(node, cbctx);
	} RADIX_WALK_END;
}

radix_node_t
*radix_search_exact(radix_tree_t *radix, prefix_t *prefix)
{
	radix_node_t *node;
	unsigned char *addr;
	unsigned int bitlen;

	if (radix->head == NULL)
		return (NULL);

	node = radix->head;
	addr = prefix_touchar(prefix);
	bitlen = prefix->bitlen;

	while (node->bit < bitlen) {
		if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
			node = node->r;
		else
			node = node->l;

		if (node == NULL)
			return (NULL);
	}

	if (node->bit > bitlen || node->prefix == NULL)
		return (NULL);

	if (comp_with_mask(prefix_touchar(node->prefix),
	    prefix_touchar(prefix), bitlen))
		return (node);

	return (NULL);
}


/* if inclusive != 0, "best" may be the given prefix itself */
static radix_node_t
*radix_search_best2(radix_tree_t *radix, prefix_t *prefix, int inclusive)
{
	radix_node_t *node;
	radix_node_t *stack[RADIX_MAXBITS + 1] = {0};
	unsigned char *addr;
	unsigned int bitlen;
	int cnt = 0;

	if (radix->head == NULL)
		return (NULL);

	node = radix->head;
	addr = prefix_touchar(prefix);
	bitlen = prefix->bitlen;

	while (node->bit < bitlen) {
		if (node->prefix)
			stack[cnt++] = node;
		if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
			node = node->r;
		else
			node = node->l;

		if (node == NULL)
			break;
	}

	if (inclusive && node && node->prefix)
		stack[cnt++] = node;


	if (cnt <= 0)
		return (NULL);

	while (--cnt >= 0) {
		node = stack[cnt];
		if (comp_with_mask(prefix_touchar(node->prefix),
		    prefix_touchar(prefix), node->prefix->bitlen))
			return (node);
	}
	return (NULL);
}


radix_node_t
*radix_search_best(radix_tree_t *radix, prefix_t *prefix)
{
	return (radix_search_best2(radix, prefix, 1));
}


radix_node_t
*radix_lookup(radix_tree_t *radix, prefix_t *prefix)
{
	radix_node_t *node, *new_node, *parent, *glue;
	unsigned char *addr, *test_addr;
	unsigned int bitlen, check_bit, differ_bit;
	unsigned int i, j, r;

	if (radix->head == NULL) {
		if ((node = malloc(sizeof(*node))) == NULL)
			return (NULL);
		memset(node, '\0', sizeof(*node));
		node->bit = prefix->bitlen;
		node->prefix = Ref_Prefix(prefix);
		node->parent = NULL;
		node->l = node->r = NULL;
		node->data = NULL;
		radix->head = node;
		radix->num_active_node++;
		return (node);
	}
	addr = prefix_touchar(prefix);
	bitlen = prefix->bitlen;
	node = radix->head;

	while (node->bit < bitlen || node->prefix == NULL) {
		if (node->bit < radix->maxbits && BIT_TEST(addr[node->bit >> 3],
		    0x80 >> (node->bit & 0x07))) {
			if (node->r == NULL)
				break;
			node = node->r;
		} else {
			if (node->l == NULL)
				break;
			node = node->l;
		}
	}

	test_addr = prefix_touchar(node->prefix);
	/* find the first bit different */
	check_bit = (node->bit < bitlen) ? node->bit : bitlen;
	differ_bit = 0;
	for (i = 0; i * 8 < check_bit; i++) {
		if ((r = (addr[i] ^ test_addr[i])) == 0) {
			differ_bit = (i + 1) * 8;
			continue;
		}
		/* I know the better way, but for now */
		for (j = 0; j < 8; j++) {
			if (BIT_TEST(r, (0x80 >> j)))
				break;
		}
		/* must be found */
		differ_bit = i * 8 + j;
		break;
	}
	if (differ_bit > check_bit)
		differ_bit = check_bit;

	parent = node->parent;
	while (parent && parent->bit >= differ_bit) {
		node = parent;
		parent = node->parent;
	}

	if (differ_bit == bitlen && node->bit == bitlen) {
		if (node->prefix == NULL)
			node->prefix = Ref_Prefix(prefix);
		return (node);
	}
	if ((new_node = malloc(sizeof(*new_node))) == NULL)
		return (NULL);
	memset(new_node, '\0', sizeof(*new_node));
	new_node->bit = prefix->bitlen;
	new_node->prefix = Ref_Prefix(prefix);
	new_node->parent = NULL;
	new_node->l = new_node->r = NULL;
	new_node->data = NULL;
	radix->num_active_node++;

	if (node->bit == differ_bit) {
		new_node->parent = node;
		if (node->bit < radix->maxbits && BIT_TEST(addr[node->bit >> 3],
		    0x80 >> (node->bit & 0x07)))
			node->r = new_node;
		else
			node->l = new_node;

		return (new_node);
	}
	if (bitlen == differ_bit) {
		if (bitlen < radix->maxbits && BIT_TEST(test_addr[bitlen >> 3],
		    0x80 >> (bitlen & 0x07)))
			new_node->r = node;
		else
			new_node->l = node;

		new_node->parent = node->parent;
		if (node->parent == NULL)
			radix->head = new_node;
		else if (node->parent->r == node)
			node->parent->r = new_node;
		else
			node->parent->l = new_node;

		node->parent = new_node;
	} else {
		if ((glue = malloc(sizeof(*glue))) == NULL)
			return (NULL);
		memset(glue, '\0', sizeof(*glue));
		glue->bit = differ_bit;
		glue->prefix = NULL;
		glue->parent = node->parent;
		glue->data = NULL;
		radix->num_active_node++;
		if (differ_bit < radix->maxbits &&
		    BIT_TEST(addr[differ_bit >> 3],
		    0x80 >> (differ_bit & 0x07))) {
			glue->r = new_node;
			glue->l = node;
		} else {
			glue->r = node;
			glue->l = new_node;
		}
		new_node->parent = glue;

		if (node->parent == NULL)
			radix->head = glue;
		else if (node->parent->r == node)
			node->parent->r = glue;
		else
			node->parent->l = glue;

		node->parent = glue;
	}
	return (new_node);
}


void
radix_remove(radix_tree_t *radix, radix_node_t *node)
{
	radix_node_t *parent, *child;

	if (node->r && node->l) {
		/*
		 * this might be a placeholder node -- have to check and make
		 * sure there is a prefix aossciated with it !
		 */
		if (node->prefix != NULL)
			Deref_Prefix(node->prefix);
		node->prefix = NULL;
		/* Also I needed to clear data pointer -- masaki */
		node->data = NULL;
		return;
	}
	if (node->r == NULL && node->l == NULL) {
		parent = node->parent;
		Deref_Prefix(node->prefix);
		free(node);
		radix->num_active_node--;

		if (parent == NULL) {
			radix->head = NULL;
			return;
		}
		if (parent->r == node) {
			parent->r = NULL;
			child = parent->l;
		} else {
			parent->l = NULL;
			child = parent->r;
		}

		if (parent->prefix)
			return;

		/* we need to remove parent too */
		if (parent->parent == NULL)
			radix->head = child;
		else if (parent->parent->r == parent)
			parent->parent->r = child;
		else
			parent->parent->l = child;

		child->parent = parent->parent;
		free(parent);
		radix->num_active_node--;
		return;
	}
	if (node->r)
		child = node->r;
	else
		child = node->l;

	parent = node->parent;
	child->parent = parent;

	Deref_Prefix(node->prefix);
	free(node);
	radix->num_active_node--;

	if (parent == NULL) {
		radix->head = child;
		return;
	}
	if (parent->r == node)
		parent->r = child;
	else
		parent->l = child;
}

/* Local additions */
static void
sanitise_mask(unsigned char *addr, unsigned int masklen, unsigned int maskbits)
{
	unsigned int i = masklen / 8;
	unsigned int j = masklen % 8;

	if (j != 0) {
		addr[i] &= (~0) << (8 - j);
		i++;
	}
	for (; i < maskbits / 8; i++)
		addr[i] = 0;
}

prefix_t
*prefix_pton(const char *string, long len, prefix_t *prefix, const char **errmsg)
{
	char save[256], *cp, *ep;
	struct addrinfo hints, *ai;
	void *addr;
	prefix_t *ret;
	size_t slen;
	int r;

	ret = NULL;

	/* Copy the string to parse, because we modify it */
	if ((slen = strlen(string) + 1) > sizeof(save)) {
		*errmsg = "string too long";
		return (NULL);
	}
	memcpy(save, string, slen);

	if ((cp = strchr(save, '/')) != NULL) {
		if (len != -1 ) {
			*errmsg = "masklen specified twice";
			return (NULL);
		}
		*cp++ = '\0';
		len = strtol(cp, &ep, 10);
		if (*cp == '\0' || *ep != '\0' || len < 0) {
			*errmsg = "could not parse masklen";
			return (NULL);
		}
		/* More checks below */
	}
	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	if ((r = getaddrinfo(save, NULL, &hints, &ai)) != 0) {
		snprintf(save, sizeof(save), "getaddrinfo: %s:",
		    gai_strerror(r));
		*errmsg = save;
		return NULL;
	}
	if (ai == NULL || ai->ai_addr == NULL) {
		*errmsg = "getaddrinfo returned no result";
		goto out;
	}
	switch (ai->ai_addr->sa_family) {
	case AF_INET:
		if (len == -1)
			len = 32;
		else if (len < 0 || len > 32)
			goto out;
		addr = &((struct sockaddr_in *) ai->ai_addr)->sin_addr;
		sanitise_mask(addr, len, 32);
		break;
	case AF_INET6:
		if (len == -1)
			len = 128;
		else if (len < 0 || len > 128)
			goto out;
		addr = &((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr;
		sanitise_mask(addr, len, 128);
		break;
	default:
		goto out;
	}

	ret = New_Prefix2(ai->ai_addr->sa_family, addr, len, prefix);
	if (ret == NULL)
		*errmsg = "New_Prefix2 failed";
out:
	freeaddrinfo(ai);
	return (ret);
}

prefix_t
*prefix_from_blob(unsigned char *blob, int len, int prefixlen, prefix_t *prefix)
{
	int family, maxprefix;

	switch (len) {
	case 4:
		/* Assume AF_INET */
		family = AF_INET;
		maxprefix = 32;
		break;
	case 16:
		/* Assume AF_INET6 */
		family = AF_INET6;
		maxprefix = 128;
		break;
	default:
		/* Who knows? */
		return NULL;
	}
	if (prefixlen == -1)
		prefixlen = maxprefix;
	if (prefixlen < 0 || prefixlen > maxprefix)
		return NULL;
	return (New_Prefix2(family, blob, prefixlen, prefix));
}

const char *
prefix_addr_ntop(prefix_t *prefix, char *buf, size_t len)
{
	return (inet_ntop(prefix->family, &prefix->add, buf, len));
}

const char *
prefix_ntop(prefix_t *prefix, char *buf, size_t len)
{
	char addrbuf[128];

	if (prefix_addr_ntop(prefix, addrbuf, sizeof(addrbuf)) == NULL)
		return (NULL);
	snprintf(buf, len, "%s/%d", addrbuf, prefix->bitlen);

	return (buf);
}
