#pragma once

#ifndef CACHE_CUSTOMLIST_H
#define CACHE_CUSTOMLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>

#include "cache_domains.h"

struct lmdbcustomlist 
{
	unsigned char customlisttypes : 8;
};
typedef struct lmdbcustomlist lmdbcustomlist;

enum  
{
	CL_NONE = 0,
	CL_BLACKLIST = 0x01,
	CL_WHITELIST = 0x02,
	CL_BYPASS = 0x04
} CustomListTypes;

int cache_customlist_contains(MDB_env *env, char *domain, const char *identity, lmdbcustomlist *item);
int cache_custom_exploded_contains(MDB_env *env, char *domain, const char *identity, lmdbcustomlist *item);

#endif