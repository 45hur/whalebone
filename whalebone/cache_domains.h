#pragma once

#ifndef CACHE_DOMAINS_H
#define CACHE_DOMAINS_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>
#include <lmdb.h>

struct cache_domain
{
	int capacity;
	int index;
	_Atomic int searchers;
	unsigned long long *base;
	short *accuracy;
	unsigned long long *flags;
};
typedef struct cache_domain cache_domain;

struct domain 
{
  unsigned long long  crc;
	short accuracy;
	unsigned long long flags;
};
typedef struct domain domain;

struct lmdbdomain 
{
	short accuracy;
	unsigned long long flags;
};
typedef struct lmdbdomain lmdbdomain;

enum 
{
  flags_none = 0,
  flags_accuracy = 1,
  flags_blacklist = 2, 
  flags_whitelist = 4, 
  flags_drop = 8,
  flags_audit = 16,
  flags_content = 32,
  flags_legal = 64
} flags;


unsigned char cache_domain_get_flags(unsigned long long flags, int n);
int cache_domain_compare(const void * a, const void * b);
cache_domain* cache_domain_init(int count);
cache_domain* cache_domain_init_ex(unsigned long long *domains, short *accuracy, unsigned long long *flags, int count);
cache_domain* cache_domain_init_ex2(unsigned long long *domains, int count);
void cache_domain_destroy(cache_domain *cache);
int cache_domain_add(cache_domain* cache, unsigned long long value, short accuracy, unsigned long long flags);
int cache_domain_update(cache_domain* cache, unsigned long long value, short accuracy, unsigned long long flags);
void cache_domain_sort(cache_domain* cache);
int cache_domain_contains(MDB_env *env, unsigned long long value, domain *citem, int iscustom);

#endif