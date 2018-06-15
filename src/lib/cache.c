#include "cache.h"
#include <pthread.h>

struct cache_head {
	struct hlist_head hash_head;
	int hash_size;
	pthread_rwlock_t *rwlock;
};
