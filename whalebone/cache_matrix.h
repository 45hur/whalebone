#pragma once

#ifndef CACHE_MATRIX_H
#define CACHE_MATRIX_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>
#include <lmdb.h>

#include "cache_domains.h"
#include "cache_customlist.h"
#include "cache_policy.h"

struct lmdbmatrixkey
{
  unsigned char accuracyAudit: 8;
  unsigned char accuracyBlock: 8;
  unsigned char content: 8;
  unsigned char advertisement: 8;
  unsigned char legal: 8;
  unsigned char whitelist: 8;
  unsigned char blacklist: 8;
  unsigned char bypass: 8;
};
typedef struct lmdbmatrixkey lmdbmatrixkey;

struct lmdbmatrixvalue
{
  unsigned char action: 8;
  unsigned char sinkhole: 8;
  unsigned char logThreat: 8;
  unsigned char logContent: 8;
  unsigned long padding: 32;
  char answer[16];
};
typedef struct lmdbmatrixvalue lmdbmatrixvalue;

enum 
{
  MAT_ALLOW = 0x01,
  MAT_BLOCK = 0x02
} MatrixActions;

enum 
{
  MST_CONTENT = 0x01,
  MST_LEGAL = 0x02,
  MST_BLACKLIST = 0x04,
  MST_ACCURACY = 0x08
} MatrixSinkholeTypes;

int cache_matrix_contains(MDB_env *env, lmdbmatrixkey *key, lmdbmatrixvalue *item);
void cache_matrix_calculate(lmdbdomain *domain, lmdbpolicy *policy, lmdbcustomlist *customlist, lmdbmatrixkey *key);

#endif