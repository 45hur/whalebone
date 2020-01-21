#pragma once

#include <fcntl.h> 

#include "cache_iprange.h"
#include "cache_policy.h"
#include "cache_customlist.h"
#include "cache_domains.h"
#include "cache_matrix.h"

#ifndef PROGRAM_H
#define PROGRAM_H

MDB_env *env_domains;
MDB_env *env_ipranges;
MDB_env *env_policies;
MDB_env *env_matrix;

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();
int search(const char * querieddomain, struct ip_addr * userIpAddress, const char * userIpAddressString, const char * userIpAddressStringUntruncated, int rrtype, char * originaldomain, char * logmessage);
int explode(char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, const char * userIpAddressStringUntruncated, int rrtype);

void* threadproc(void *arg);

#endif