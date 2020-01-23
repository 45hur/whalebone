#pragma once

#ifndef THREAD_SHARED_H
#define THREAD_SHARED_H

#include <stdio.h> 
#include <stdint.h>
#include <pthread.h>

struct shared
{
	pthread_mutex_t mutex;
	int sharedResource;
};

struct shared *thread_shared;

struct ipaddr
{
	uint16_t family : 16;
	uint32_t ipv4_sin_addr : 32;
	uint64_t ipv6_sin_addr_hi : 64;
	uint64_t ipv6_sin_addr_low : 64;
};

struct ip_addr
{
	unsigned int family;
	unsigned int ipv4_sin_addr;
	unsigned char ipv6_sin_addr[16];
};

struct PrimeHeader
{
	uint32_t action : 32;
	uint32_t buffercount : 32;
	uint64_t headercrc : 64;
};

struct MessageHeader
{
	uint64_t length : 64;
	uint64_t msgcrc : 64;
};

enum
{
	Lmdb_domains = 21,
	Lmdb_customlists = 22,
	Lmdb_policy = 23,
	Lmdb_ranges = 24,
	Lmdb_radius = 25,
	Lmdb_matrix = 26,
	Lmdb_cloudgroup = 27
} bufferType;

#endif