#pragma once

#ifndef CACHE_POLICY_H
#define CACHE_POLICY_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>

typedef struct
{
	int capacity;
	int index;
	_Atomic int searchers;
	int *policy;
    int *strategy;
	int *audit;
    int *block;
} cache_policy;

typedef struct
{
  int strategy;
  int audit;
  int block;
} policy;

cache_policy* cache_policy_init(int count);
cache_policy* cache_policy_init_ex(int *policy, int *strategy, int *audit, int *block, int count);
void cache_policy_destroy(cache_policy *cache);
int cache_policy_add(cache_policy* cache, int policy_id, int strategy, int audit, int block);
int cache_policy_contains(cache_policy* cache, int policy_id, policy *item);

#endif