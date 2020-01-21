#pragma once

#ifndef CACHE_POLICY_H
#define CACHE_POLICY_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>
#include <lmdb.h>

struct lmdbpolicy
{
	unsigned char audit_accuracy : 8;
  unsigned char block_accuracy : 8;
  unsigned long threatTypes : 32;
	unsigned long long contentTypes : 64;
};
typedef struct lmdbpolicy lmdbpolicy;

int cache_policy_contains(MDB_env *env, char *identity, lmdbpolicy *item);

#endif