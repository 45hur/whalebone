#pragma once

#ifndef CACHE_MATRIX_H
#define CACHE_MATRIX_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>
#include <lmdb.h>

#include "cache_policy.h"
#include "cache_domains.h"

struct lmdbmatrixkey
{
  unsigned char accuracyAudit;
  unsigned char accuracyBlock;
  unsigned char content;
  unsigned char advertisement;
  unsigned char legal;
  unsigned char whitelist;
  unsigned char blacklist;
};
typedef struct lmdbmatrixkey lmdbmatrixkey;

struct lmdbmatrixvalue
{
  unsigned char action;
  unsigned char sinkhole;
  unsigned char logThreat;
  unsigned char logContent;
  unsigned int padding;
  char answer[16];
};
typedef struct lmdbmatrixvalue lmdbmatrixvalue;


int cache_matrix_contains(MDB_env *env, lmdbmatrixkey *key, lmdbmatrixvalue *item);
void cache_matrix_calculate(lmdbdomain *domain, lmdbpolicy *policy, lmdbmatrixkey *key);

#endif