#ifndef _GENERIC_CACHE_H

#include "list.h"
#include "hashtable.h"

struct cache_node {
	struct hlist_node list;
};

struct cache_head;

struct cache_head *cache_new(int hashsize, void (*item_free)(struct cache_head *head, struct cache_node *node));

int cache_add(struct cache_head *head, struct cache_node *node, void *key, int key_len);

int cache_del(struct cache_node *node);

struct cache_node *cache_lookup(struct cache_head *head, void *key, int key_len);

int cache_update(struct cache_head *head, void *key, int key_len);

void cache_free(struct cache_head *head);

#endif // !_GENERIC_CACHE_H
