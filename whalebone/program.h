#pragma once

#include <fcntl.h> 

#include "cache_iprange.h"
#include "cache_policy.h"
#include "cache_customlist.h"
#include "cache_domains.h"

#ifndef PROGRAM_H
#define PROGRAM_H

cache_domain* cached_domain;
cache_iprange* cached_iprange;
cache_policy* cached_policy;
cache_customlist* cached_customlist;
cache_customlist* temp_customlist;
cache_iprange* cached_iprange_slovakia;

unsigned long long *swapdomain_crc;
unsigned long long swapdomain_crc_len;
short *swapdomain_accuracy;
unsigned long long swapdomain_accuracy_len;
unsigned long long *swapdomain_flags;
unsigned long long swapdomain_flags_len;

struct ip_addr **swapiprange_low;
unsigned long long swapiprange_low_len;
struct ip_addr **swapiprange_high;
unsigned long long swapiprange_high_len;
char **swapiprange_identity;
unsigned long long swapiprange_identity_len;
int *swapiprange_policy_id;
unsigned long long swapiprange_policy_id_len;

int * swappolicy_policy_id;
unsigned long long swappolicy_policy_id_len;;
int * swappolicy_strategy;
unsigned long long swappolicy_strategy_len;
int * swappolicy_audit;
unsigned long long swappolicy_audit_len;
int * swappolicy_block;
unsigned long long swappolicy_block_len;

unsigned long long swapcustomlist_identity_count;
char *swapcustomlist_identity;
unsigned long long swapcustomlist_identity_len;
struct cache_domain *swapcustomlist_whitelist;
unsigned long long swapcustomlist_whitelist_len;
struct cache_domain *swapcustomlist_blacklist;
unsigned long long swapcustomlist_blacklist_len;
int *swapcustomlist_policyid;
unsigned long long swapcustomlist_policyid_len;

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();
int load_last_modified_dat();
int search(const char * querieddomain, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype, char * originaldomain, char * logmessage);
int explode(char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype);

void* threadproc(void *arg);

#endif