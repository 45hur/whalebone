#pragma once

#include <fcntl.h> 

#include "cache_iprange.h"
#include "cache_policy.h"
#include "cache_customlist.h"
#include "cache_domains.h"

#ifndef PROGRAM_H
#define PROGRAM_H

static cache_domain* cached_domain = NULL;
static cache_iprange* cached_iprange = NULL;
static cache_policy* cached_policy = NULL;
static cache_customlist* cached_customlist = NULL;
//static cache_iprange* cached_iprange_slovakia = NULL;

static unsigned long long *swapdomain_crc;
static unsigned long long swapdomain_crc_len = 0;
static short *swapdomain_accuracy;
static unsigned long long swapdomain_accuracy_len = 0;
static unsigned long long *swapdomain_flags;
static unsigned long long swapdomain_flags_len = 0;

static struct ip_addr **swapiprange_low;
static unsigned long long swapiprange_low_len = 0;
static struct ip_addr **swapiprange_high;
static unsigned long long swapiprange_high_len = 0;
static char **swapiprange_identity;
static unsigned long long swapiprange_identity_len = 0;
static int *swapiprange_policy_id;
static unsigned long long swapiprange_policy_id_len = 0;

static int * swappolicy_policy_id;
static unsigned long long swappolicy_policy_id_len = 0;
static int * swappolicy_strategy;
static unsigned long long swappolicy_strategy_len = 0;
static int * swappolicy_audit;
static unsigned long long swappolicy_audit_len = 0;
static int * swappolicy_block;
static unsigned long long swappolicy_block_len = 0;

static char **swapcustomlist_identity;
static unsigned long long swapcustomlist_identity_len = 0;
static struct cache_domain **swapcustomlist_whitelist;
static unsigned long long swapcustomlist_whitelist_len = 0;
static struct cache_domain **swapcustomlist_blacklist;
static unsigned long long swapcustomlist_blacklist_len = 0;
static int * swapcustomlist_policyid;
static unsigned long long swapcustomlist_policyid_len = 0;

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();
int search(const char * querieddomain, struct ip_addr * origin, char * req_addr, int rrtype, char * originaldomain, char * logmessage);
int explode(char * domain, struct ip_addr * origin, char * req_addr, int rrtype);

void* threadproc(void *arg);

#endif