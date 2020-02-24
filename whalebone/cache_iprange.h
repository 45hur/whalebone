#pragma once

#ifndef CACHE_IPRANGE_H
#define CACHE_IPRANGE_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>
#include <lmdb.h>

#include "ipranger.h"
#include "thread_shared.h"

typedef struct
{
	char identity[IPRANGER_MAX_IDENTITY_LENGTH];
} iprange;

int cache_iprange_contains(MDB_env *env, const struct ip_addr * ip, const char * ipaddr, iprange *item);

#endif