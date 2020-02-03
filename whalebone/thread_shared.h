#pragma once

#ifndef THREAD_SHARED_H
#define THREAD_SHARED_H

#include <stdio.h> 
#include <stdint.h>
#include <pthread.h>

#define LOG_MESSAGE_MAX 4096

struct shared
{
	pthread_mutex_t mutex_global;
	int sharedResource;
};
struct shared *thread_shared;

pthread_mutex_t mutex_local;

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
	log_empty_slot = 0,
	log_debug = 1,
	log_audit = 2,
	log_content = 3
} logType;

typedef struct
{
	unsigned int type;
	char message[LOG_MESSAGE_MAX];
} LogRecord;

typedef struct
{
	int capacity;
	_Atomic int index;
	LogRecord *buffer;
} LogBuffer;


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