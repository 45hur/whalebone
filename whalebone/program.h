#pragma once

#include <fcntl.h> 

#include "cache_iprange.h"
#include "cache_policy.h"
#include "cache_customlist.h"
#include "cache_domains.h"
#include "cache_matrix.h"
#include "thread_shared.h"

#ifndef PROGRAM_H
#define PROGRAM_H

MDB_env *env_customlists;
MDB_env *env_domains;
MDB_env *env_radius;
MDB_env *env_ranges;
MDB_env *env_policies;
MDB_env *env_matrix;

LogBuffer *logBuffer;
struct sockaddr_in si_other;
int socket_id;

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();
int search(const char * querieddomain, struct ip_addr * userIpAddress, const char * userIpAddressString, const char * userIpAddressStringUntruncated, lmdbmatrixvalue *matrix, char * originaldomain, char * logmessage);
int explode(char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, const char * userIpAddressStringUntruncated, lmdbmatrixvalue *matrix);

void* threadproc(void *arg);

#endif