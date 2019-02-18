#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>

#include "cache_policy.h"

cache_policy* cache_policy_init(int count)
{
	cache_policy *item = (cache_policy *)calloc(1, sizeof(cache_policy));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = 0;
	item->searchers = 0;
	item->policy = (int *)malloc(item->capacity * sizeof(int));
	item->strategy = (int *)malloc(item->capacity * sizeof(int));
	item->audit = (int *)malloc(item->capacity * sizeof(int));
	item->block = (int *)malloc(item->capacity * sizeof(int));
	if (item->policy == NULL || item->strategy == NULL || item->audit == NULL || item->block == NULL)
	{
		return NULL;
	}

	return item;
}

cache_policy* cache_policy_init_ex(int *policyl, int *strategy, int *audit, int *block, int count)
{
	cache_policy *item = (cache_policy *)calloc(1, sizeof(cache_policy));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = count;
	item->searchers = 0;
	item->policy = policyl;
	item->strategy = strategy;
	item->audit = audit;
	item->block = block;
	if (item->policy == NULL || item->strategy == NULL || item->audit == NULL || item->block == NULL)
	{
		return NULL;
	}

	return item;
}

void cache_policy_destroy(cache_policy *cache)
{
	if (cache == NULL)
		return;

	while (cache->searchers > 0)
	{
		usleep(50000);
	}

	if (cache->policy != NULL)
	{
		free(cache->policy);
		cache->policy = NULL;
	}
	if (cache->strategy != NULL)
	{
		free(cache->strategy);
		cache->strategy = NULL;
	}
	if (cache->audit != NULL)
	{
		free(cache->audit);
		cache->audit = NULL;
	}
	if (cache->block != NULL)
	{
		free(cache->block);
		cache->block = NULL;
	}
}

int cache_policy_add(cache_policy* cache, int policy_id, int strategy, int audit, int block)
{
	if (cache == NULL)
		return -1;

	if (cache->index >= cache->capacity)
		return -1;

	cache->policy[cache->index] = policy_id;
	cache->strategy[cache->index] = strategy;
	cache->audit[cache->index] = audit;
	cache->block[cache->index] = block;
	cache->index++;

	return 0;
}

int cache_policy_contains(cache_policy* cache, int policy_id, policy *item)
{
	if (cache == NULL)
		return -1;

	cache->searchers++;
	int result = 0;
	int position = cache->index;

	while (--position >= 0)
	{
		if (cache->policy[position] == policy_id)
		{
			item->strategy = cache->strategy[position];
			item->audit = cache->audit[position];
			item->block = cache->block[position];
			result = 1;
			break;
		}
	}

	cache->searchers--;
	return result;
}