#pragma once

#ifndef CACHE_IPRANGE_H
#define CACHE_IPRANGE_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>

#include "iprange.h"

typedef struct
{
	int capacity;
	int index;
	_Atomic int searchers;
	struct ip_addr **low;
	struct ip_addr **high;
	char **identity;
	int *policy_id;
} cache_iprange;

typedef struct
{
	char *identity;
	int policy_id;
} iprange;

cache_iprange* cache_iprange_init(int count);
cache_iprange* cache_iprange_init_ex(struct ip_addr ** low, struct ip_addr ** high, char ** identity, int * policy_id, int count);
void cache_iprange_destroy(cache_iprange *cache);
int cache_iprange_add(cache_iprange* cache, struct ip_addr *low, struct ip_addr *high, char *identity, int policy_id);
int cache_iprange_contains(cache_iprange* cache, const struct ip_addr * ip, iprange *item);

#endif