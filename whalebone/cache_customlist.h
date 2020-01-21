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
	NONE = 0,
	BLACKLIST = 0x01,
	WHITELIST = 0x02,
	BYPASS = 0x04
} CustomListTypes;

int cache_customlist_contains(MDB_env *env, unsigned long long value, lmdbcustomlist *item);

#endif