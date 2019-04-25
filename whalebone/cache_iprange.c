#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>      
#include <unistd.h>

#include "crc64.h"
#include "iprange.h"
#include "cache_iprange.h"
#include "log.h"

cache_iprange* cache_iprange_init(int count)
{
	cache_iprange *item = (cache_iprange *)calloc(1, sizeof(cache_iprange));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = 0;
	item->searchers = 0;
	item->base = (unsigned long long *)malloc(item->capacity * sizeof(unsigned long long));
	item->low = (struct ip_addr **)malloc(item->capacity * sizeof(struct ip_addr *));
	item->high = (struct ip_addr **)malloc(item->capacity * sizeof(struct ip_addr *));
	item->identity = (char **)malloc(item->capacity * sizeof(char *));
	item->policy_id = (int *)malloc(item->capacity * sizeof(int));
	if (item->base == NULL || item->low == NULL || item->high == NULL || item->identity == NULL || item->policy_id == NULL)
	{
		return NULL;
	}

	return item;
}

cache_iprange* cache_iprange_init_ex(struct ip_addr ** low, struct ip_addr ** high, char ** identity, int * policy_id, int count)
{
	cache_iprange *item = (cache_iprange *)calloc(1, sizeof(cache_iprange));
	if (item == NULL)
	{
		return NULL;
	}

	item->capacity = count;
	item->index = count;
	item->searchers = 0;
	item->base = (unsigned long long *)malloc(count * sizeof(unsigned long long));
	item->low = low;
	item->high = high;
	item->identity = identity;
	item->policy_id = policy_id;
	if (item->base == NULL || item->low == NULL || item->high == NULL || item->identity == NULL || item->policy_id == NULL)
	{
		return NULL;
	}

	for (int i = count - 1; i >= 0; i--)
	{
		char ipaddr[20] = {0};
		unsigned char *addr = (unsigned char *)&(item->low[i]->ipv4_sin_addr);

		sprintf(&ipaddr, "%d.%d.%d.%d", addr[3], addr[2], addr[1], addr[0]);
		uint64_t crc = crc64(0, (const char *)&ipaddr, strlen(ipaddr));
		item->base[i] = crc;
		//debugLog("\"method\":\"cache_iprange_init_ex\",\"ipaddr\":\"%s\",\"crc\":\"%llx\"", ipaddr, crc);
	}

	return item;
}


void cache_iprange_destroy(cache_iprange *cache)
{
	if (cache == NULL)
	{
		return;
	}

	while (cache->searchers > 0)
	{
		usleep(50000);
	}

	int position = cache->index;
	while (--position >= 0)
	{
		if (cache->low[position] != NULL)
		{
			free(cache->low[position]);
			cache->low[position] = NULL;
		}
		if (cache->high[position] != NULL)
		{
			free(cache->high[position]);
			cache->high[position] = NULL;
		}
		if (cache->identity[position] != NULL)
		{
			free(cache->identity[position]);
			cache->identity[position] = NULL;
		}
		//    if (cache->policy_id[position] != NULL)
		//  	{
		//  		free(cache->policy_id[position]);
		//  	}
	}

	if (cache->base != NULL)
	{
		free(cache->base);
		cache->base = NULL;
	}
	if (cache->low != NULL)
	{
		free(cache->low);
		cache->low = NULL;
	}
	if (cache->high != NULL)
	{
		free(cache->high);
		cache->high = NULL;
	}
	if (cache->identity != NULL)
	{
		free(cache->identity);
		cache->identity = NULL;
	}
	if (cache->policy_id != NULL)
	{
		free(cache->policy_id);
		cache->policy_id = NULL;
	}


	//if (cache != NULL)
	//{
	//  free(cache);
	//} 
}


int cache_iprange_add(cache_iprange* cache, struct ip_addr *low, struct ip_addr *high, char *identity, int policy_id)
{
	if (cache == NULL)
		return -1;

	if (cache->index >= cache->capacity)
		return -1;

	struct ip_addr* xlow = (struct ip_addr*)malloc(sizeof(struct ip_addr));
	struct ip_addr* xhigh = (struct ip_addr*)malloc(sizeof(struct ip_addr));
	char* xidentity = (char *)calloc(strlen(identity)+1, sizeof(char));
	//int* xpolicy_id = (int *)malloc(sizeof(int));
	if (xlow == NULL || xhigh == NULL || xidentity == NULL/* || xpolicy_id == NULL*/)
	{
		return -1;
	}

	memcpy(xlow, low, sizeof(struct ip_addr));
	memcpy(xhigh, high, sizeof(struct ip_addr));
	memcpy(xidentity, identity, strlen(identity));
	//memcpy(xpolicy_id, policy_id, sizeof(int));
	cache->low[cache->index] = xlow;
	cache->high[cache->index] = xhigh;
	cache->identity[cache->index] = xidentity;
	cache->policy_id[cache->index] = policy_id;
	cache->index++;

	return 0;
}

int cache_iprange_contains(cache_iprange* cache, const struct ip_addr * ip, const char * ipaddr, iprange *item)
{
	if (cache == NULL)
	{
		return 0;
	}

	cache->searchers++;
	int lowerbound = 0;
	int upperbound = cache->index;
	int position;
	unsigned long long value = crc64(0, ipaddr, strlen(ipaddr));

	position = (lowerbound + upperbound) / 2;

	while ((cache->base[position] != value) && (lowerbound <= upperbound))
	{
		if (cache->base[position] > value)
		{
			upperbound = position - 1;
		}
		else
		{
			lowerbound = position + 1;
		}
		position = (lowerbound + upperbound) / 2;
	}

	if (lowerbound <= upperbound)
	{
		item->identity = cache->identity[position];
		item->policy_id = cache->policy_id[position];
	}

	cache->searchers--;
	return (lowerbound <= upperbound);
}

int cache_iprange_contains_old(cache_iprange* cache, const struct ip_addr * ip, iprange *item)
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
		//printf(" checking %d\n", position);
		if ((result = is_ip_in_range(
			ip,
			(const struct ip_addr *)cache->low[position],
			(const struct ip_addr *)cache->high[position]
		)) == 1)
		{
			item->identity = cache->identity[position];
			item->policy_id = cache->policy_id[position];
			break;
		}
	}

	cache->searchers--;
	return result;
}