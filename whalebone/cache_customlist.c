#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>      
#include <unistd.h>

#include "cache_customlist.h"

cache_customlist* cache_customlist_init(int count)
{
	cache_customlist *item = (cache_customlist *)calloc(1, sizeof(cache_customlist));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = 0;
	item->searchers = 0;
	item->identity = (char **)malloc(item->capacity * sizeof(char *));
	item->whitelist = (cache_domain **)malloc(item->capacity * sizeof(cache_domain *));
	item->blacklist = (cache_domain **)malloc(item->capacity * sizeof(cache_domain *));
	item->policyid = (int **)malloc(item->capacity * sizeof(int *));
	if (item->identity == NULL || item->whitelist == NULL || item->blacklist == NULL || item->policyid == NULL)
	{
		return NULL;
	}

	return item;
}

cache_customlist* cache_customlist_init_ex(char ** identity, struct cache_domain **whitelist, struct cache_domain **blacklist, int ** policyid, int count)
{
	cache_customlist *item = (cache_customlist *)calloc(1, sizeof(cache_customlist));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = count;
	item->searchers = 0;
	item->identity = identity;
	item->whitelist = whitelist;
	item->blacklist = blacklist;
	item->policyid = policyid;
	if (item->identity == NULL || item->whitelist == NULL || item->blacklist == NULL || item->policyid == NULL)
	{
		return NULL;
	}

	return item;
}

void cache_customlist_destroy(cache_customlist *cache)
{
	if (cache == NULL)
		return;

	while (cache->searchers > 0)
	{
		usleep(50000);
	}

	int position = cache->index;
	while (--position >= 0)
	{
		if (cache->identity[position] != NULL)
		{
			free(cache->identity[position]);
			cache->identity[position] = NULL;
		}

		if (cache->whitelist[position] != NULL)
		{
			cache_domain_destroy(cache->whitelist[position]);
			free(cache->whitelist[position]);
			cache->whitelist[position] = NULL;
		}

		if (cache->blacklist[position] != NULL)
		{
			cache_domain_destroy(cache->blacklist[position]);
			free(cache->blacklist[position]);
			cache->blacklist[position] = NULL;
		}

		if (cache->policyid[position] != NULL)
		{
			free(cache->policyid[position]);
			cache->policyid[position] = NULL;
		}
	}

	if (cache->identity != NULL)
	{
		free(cache->identity);
		cache->identity = NULL;
	}
	if (cache->whitelist != NULL)
	{
		free(cache->whitelist);
		cache->whitelist = NULL;
	}
	if (cache->blacklist != NULL)
	{
		free(cache->blacklist);
		cache->blacklist = NULL;
	}
	if (cache->policyid != NULL)
	{
		free(cache->policyid);
		cache->policyid = NULL;
	}
}

int cache_customlist_add(cache_customlist* cache, char *identity, cache_domain *whitelist, cache_domain *blacklist, int *policyid)
{
	if (cache == NULL)
	{
		return -1;
	}

	if (cache->index >= cache->capacity)
		return -1;

	cache_domain *xwhitelist = cache_domain_init(whitelist->capacity);
	cache_domain *xblacklist = cache_domain_init(blacklist->capacity);
	if (xwhitelist == NULL || xblacklist == NULL)
	{
		return -1;
	}

	char* xidentity = (char *)calloc(strlen(identity) + 1, sizeof(char));
	if (xidentity == NULL)
	{
		return -1;
	}

	int* xpolicy = (int *)calloc(1, sizeof(int));
	if (xpolicy == NULL)
	{
		return -1;
	}

	memcpy(xwhitelist->base, whitelist->base, whitelist->index * sizeof(unsigned long long));
	memcpy(xblacklist->base, blacklist->base, blacklist->index * sizeof(unsigned long long));
	
	memcpy(xidentity, identity, strlen(identity));
	memcpy(xpolicy, policyid, sizeof(int));

	xwhitelist->index = whitelist->index;
	xblacklist->index = blacklist->index;

	cache->identity[cache->index] = xidentity;
	cache->whitelist[cache->index] = xwhitelist;
	cache->blacklist[cache->index] = xblacklist;
	cache->policyid[cache->index] = xpolicy;

	cache->index++;

	return 0;
}

int cache_customlist_whitelist_contains(cache_customlist* cache, char *identity, unsigned long long crc)
{
	if (cache == NULL)
	{
		return 0;
	}

	cache->searchers++;
	int result = 0;
	int position = cache->index;

	while (--position >= 0)
	{
		if (strcmp(cache->identity[position], identity) == 0)
		{
			domain item;
			if ((result = cache_domain_contains(cache->whitelist[position], crc, &item, 1)) == 1)
			{
				break;
			}
		}
	}

	cache->searchers--;
	return result;
}

int cache_customlist_blacklist_contains(cache_customlist* cache, char *identity, unsigned long long crc)
{
	if (cache == NULL)
	{
		return 0;
	}

	cache->searchers++;
	int result = 0;
	int position = cache->index;

	while (--position >= 0)
	{
		if (strcmp(cache->identity[position], identity) == 0)
		{
			domain item;
			if ((result = cache_domain_contains(cache->blacklist[position], crc, &item, 1)) == 1)
			{
				break;
			}
		}
	}

	cache->searchers--;
	return result;
}