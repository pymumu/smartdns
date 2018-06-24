#include "cache.h"
#include <pthread.h>

struct cache_head {
	struct hlist_head hash_head;
	int hash_size;
	pthread_rwlock_t *rwlock;
};

struct cache_head *cache_new(int hashsize, void (*item_free)(struct cache_head *head, struct cache_node *node))
{
	return NULL;
}

int cache_add(struct cache_head *head, struct cache_node *node, void *key, int key_len)
{
	return 0;
}

int cache_del(struct cache_node *node)
{
	return 0;
}

struct cache_node *cache_lookup(struct cache_head *head, void *key, int key_len)
{
	return 0;
}

int cache_update(struct cache_head *head, void *key, int key_len)
{
	return 0;
}

void cache_free(struct cache_head *head)
{
	return 
}