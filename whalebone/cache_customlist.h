#pragma once

#ifndef CACHE_CUSTOMLIST_H
#define CACHE_CUSTOMLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>

#include "cache_domains.h"

typedef struct
{
	int capacity;
	int index;
	_Atomic int searchers;
	char **identity;
	cache_domain **whitelist;
	cache_domain **blacklist;
	int **policyid;
} cache_customlist;

cache_customlist* cache_customlist_init(int count);
cache_customlist* cache_customlist_init_ex(char ** identity, cache_domain **whitelist, cache_domain **blacklist, int * policyid, int count);
void cache_customlist_destroy(cache_customlist *cache);
int cache_customlist_add(cache_customlist* cache, char *identity, cache_domain *whitelist, cache_domain *blacklist, int * policyid);
int cache_customlist_whitelist_contains(cache_customlist* cache, char *identity, unsigned long long crc);
int cache_customlist_blacklist_contains(cache_customlist* cache, char *identity, unsigned long long crc);

#endif