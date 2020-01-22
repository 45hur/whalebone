/* Convenience macro to declare module API. */
/* Convenience macro to declare module API. */
#define C_MOD_WHALEBONE "\x09""whalebone"

#include "program.h"
#include "ipranger.h"

#include <dirent.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/mman.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h>

#include "crc64.h"
#include "log.h"
#include "socket_srv.h"
#include "thread_shared.h" 

MDB_env *env_customlists = NULL;
MDB_env *env_domains = NULL;
MDB_env *env_ipranges = NULL;
MDB_env *env_policies = NULL;
MDB_env *env_matrix = NULL;

int create(void **args)
{
	int err = 0;
	int fd = shm_open(C_MOD_MUTEX, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (fd == -1)
		return fd;

	if ((err = ftruncate(fd, sizeof(struct shared))) != 0)
		return err;

	thread_shared = (struct shared*)mmap(0, sizeof(struct shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (thread_shared == NULL)
		return -1;

	thread_shared->sharedResource = 0;

	pthread_mutexattr_t shared;
	if ((err = pthread_mutexattr_init(&shared)) != 0)
		return err;

	if ((err = pthread_mutexattr_setpshared(&shared, PTHREAD_PROCESS_SHARED)) != 0)
		return err;

	if ((err = pthread_mutex_init(&(thread_shared->mutex), &shared)) != 0)
		return err;

	if ((env_customlists = iprg_init_DB_env(env_customlists, "/var/whalebone/lmdb/customlists", true)) == NULL)
	{
		debugLog("\"method\":\"create\",\"message\":\"unable to init customlist LMDB\"");
	}
	if ((env_domains = iprg_init_DB_env(env_domains, "/var/whalebone/lmdb/domains", true)) == NULL)
	{
		debugLog("\"method\":\"create\",\"message\":\"unable to init domains LMDB\"");
	}
	if ((env_ipranges = iprg_init_DB_env(env_ipranges, "/var/whalebone/lmdb/ipranges", true)) == NULL)
	{
		debugLog("\"method\":\"create\",\"message\":\"unable to init ipranges LMDB\"");
	}
	if ((env_policies = iprg_init_DB_env(env_policies, "/var/whalebone/lmdb/policies", true)) == NULL)
	{
		debugLog("\"method\":\"create\",\"message\":\"unable to init policies LMDB\"");
	}
	if ((env_matrix = iprg_init_DB_env(env_matrix, "/var/whalebone/lmdb/matrix", true)) == NULL)
	{
		debugLog("\"method\":\"create\",\"message\":\"unable to init matrix LMDB\"");
	}


	pthread_t thr_id;
	if ((err = pthread_create(&thr_id, NULL, &socket_server, NULL)) != 0)
		return err;

	*args = (void *)thr_id;

	debugLog("\"method\":\"create\",\"message\":\"created\"");

	return err;
}

int destroy(void *args)
{
	int err = 0;
	if ((err = munmap(thread_shared, sizeof(struct shared*))) == 0)
		return err;

	if ((err = shm_unlink(C_MOD_MUTEX)) == 0)
		return err;

	iprg_close_DB_env(env_customlists);
	iprg_close_DB_env(env_domains);
	iprg_close_DB_env(env_ipranges);
	iprg_close_DB_env(env_policies);
	iprg_close_DB_env(env_matrix);

	void *res = NULL;
	pthread_t thr_id = (pthread_t)args;
	if ((err = pthread_join(thr_id, res)) != 0)
		return err;

	debugLog("\"method\":\"destroy\",\"message\":\"destroyed\"");

	return err;
}

int search(const char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, const char * userIpAddressStringUntruncated, lmdbmatrixvalue *matrix, char * originaldomain, char * logmessage)
{
	char message[2048] = {};
	unsigned long long crc = crc64(0, (const char*)domainToFind, strlen(domainToFind));
	unsigned long long crcIoC = crc64(0, (const char*)domainToFind, strlen(originaldomain));
	debugLog("\"method\":\"search\",\"ioc=\"%s\",\"crc\":\"%llx\",\"crcioc\":\"%llx\"", domainToFind, crc, crcIoC);

	lmdbdomain domain_item = {};
	if (cache_domain_contains(env_domains, crc, &domain_item) == 1)
	{
		iprange iprange_item = {};
		if (cache_iprange_contains(env_ipranges, userIpAddress, userIpAddressString, &iprange_item) == 1)
		{
			debugLog("\"method\":\"search\",\"range\":\"%s\"", iprange_item.identity);
		}
		else
		{
			debugLog("\"method\":\"search\",\"range\":\"NULL\"", userIpAddressString);
		}

		lmdbpolicy policy_item = {};
		if (cache_policy_contains(env_policies, iprange_item.identity, &policy_item) == 1)
		{
			debugLog("\"method\":\"search\",\"policy\":\"%d\",\"identity\":\"%s\"", policy_item.threatTypes, iprange_item.identity);
		}
		else
		{
			debugLog("\"method\":\"search\",\"policy\":\"NULL\",\"identity\":\"%s\"", iprange_item.identity);
		}

		lmdbcustomlist customlist_item = {};
		if (cache_customlist_contains(env_customlists, domainToFind, iprange_item.identity, &customlist_item) == 1)
		{
			debugLog("\"method\":\"search\",\"customlist\":\"%d\",\"query\":\"%s%s\"", customlist_item.customlisttypes, domainToFind, iprange_item.identity);
		}
		else
		{
			debugLog("\"method\":\"search\",\"customlist\":\"NULL\",\"query\":\"%s%s\"", domainToFind, iprange_item.identity);
		}

		lmdbmatrixvalue matrix_item = {};
		lmdbmatrixkey matrix_key = {};
		cache_matrix_calculate(&domain_item, &policy_item, &customlist_item, &matrix_key);
		if (cache_matrix_contains(env_matrix, &matrix_key, &matrix_item) == 1)
		{
			memcpy(matrix, &matrix_item, sizeof(lmdbmatrixvalue));
			debugLog("\"method\":\"search\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"identity\":\"%s\",\"matrix\":\"%d%d%d%d%d%d%d%d\"", userIpAddressStringUntruncated, originaldomain, domainToFind, iprange_item.identity, 
				matrix_key.accuracyAudit, matrix_key.accuracyBlock, matrix_key.content, matrix_key.advertisement, matrix_key.legal, matrix_key.whitelist, matrix_key.blacklist, matrix_key.bypass); 
			return 1;
		}
		else
		{
			debugLog("\"method\":\"search\",\"message\":\"matrix failed\"");
		}
	}
	else
	{
		debugLog("\"method\":\"search\",\"message\":\"cache domains does not have a match to '%s'\"", domainToFind);
	}

	return 0;
}

int explode(char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, const char * userIpAddressStringUntruncated, lmdbmatrixvalue *matrix)
{
	char logmessage[2048] = { 0 };
	char *ptr = domainToFind;
	ptr += strlen(domainToFind);
	int result = 0;
	int found = 0;
	while (ptr-- != (char *)domainToFind)
	{
		if (ptr[0] == '.')
		{
			if (++found > 1)
			{
				debugLog("\"method\":\"explode\",\"message\":\"search %s\"", ptr + 1);
				if ((result = search(ptr + 1, userIpAddress, userIpAddressString, userIpAddressStringUntruncated, matrix, domainToFind, logmessage)) != 0)
				{
					if (matrix->logContent)
					{
						fileLog(logmessage);
					}
					return result;
				}
			}
		}
		else
		{
			if (ptr == (char *)domainToFind)
			{
				debugLog("\"method\":\"explode\",\"message\":\"search %s\"", ptr);
				if ((result = search(ptr, userIpAddress, userIpAddressString, userIpAddressStringUntruncated, matrix, domainToFind, logmessage)) != 0)
				{
					if (matrix->logContent)
					{
						fileLog(logmessage);
					}
					return result;
				}
			}
		}
	}
	if (logmessage[0] != '\0')
	{
		fileLog(logmessage);
	}

	return 0;
}


#ifdef NOKRES 

static int usage()
{
	fprintf(stdout, "Available commands: ");
	fprintf(stdout, "\n");
	fprintf(stdout, "exit\n");
	fprintf(stdout, "iprangetest4\n");
	fprintf(stdout, "iprangetest6\n");
	fprintf(stdout, "domains\n");
	fprintf(stdout, "domain\n");
	fprintf(stdout, "custom\n");
	fprintf(stdout, "blacklist\n");
	fprintf(stdout, "whitelist\n");
	fprintf(stdout, "policy\n");
	fprintf(stdout, "ranges\n");
	fprintf(stdout, "identity\n");
	fprintf(stdout, "load\n\n");
	return 0;
}

int test_cache_list_ranges()
{
	if (cached_iprange == NULL)
	{
		printf("ranges are emtpy\n");
		return -1;
	}
	printf("capacity: [%x]\n", cached_iprange->capacity);
	for (int i = 0; i < cached_iprange->capacity; i++)
	{
		//if (cached_iprange->policy_id[i] == 0)
		//	continue;

		if (cached_iprange->low[i]->family == 0x02)
		{
			printf("t=>%02x\tcrc=>%016llx\tiplo=>%08x\tiphi=>%08x\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->base[i], cached_iprange->low[i]->ipv4_sin_addr, cached_iprange->high[i]->ipv4_sin_addr, cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
		else
		{
			printf("t=>%02x\tcrc=>%016llx\tiplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tiphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->base[i],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[0], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[1], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[2], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[3],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[4], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[5], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[6], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[7],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[8], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[9], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[10], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[11],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[12], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[13], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[14], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[15],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[0], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[1], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[2], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[3],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[4], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[5], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[6], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[7],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[8], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[9], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[10], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[11],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[12], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[13], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[14], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[15],
				cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
	}
}

int test_domain_exists()
{
	printf("\nenter domain name to query:");
	char query[80] = {};
	scanf("%79s", query);
	unsigned long long crc = crc64(0, (const unsigned char*)query, strlen(query));
	domain item = {};
	int result;
	if ((result = cache_domain_contains(env, crc, &item, 0)) == 1)
	{
		printf("cache contains domain %s", query);

		if (item.accuracy == NULL)
		{
			printf("%s\tcrc=>%016llx\n", "query", item.crc);
		}

		unsigned char *flags = (unsigned char *)item.flags;
		printf("%s\tcrc=>%016llx\taccu=>%04d\t\n", query,  item.crc, item.accuracy);
	}
	else
	{
		printf("cache does not contain domain %s", query);
	}

	return 0;
}

int test_blacklist()
{
	printf("\nenter identity:");
	char identity[80] = {};
	scanf("%79s", identity);
	printf("\nenter domain:");
	char query[80] = {};
	scanf("%79s", query);
	unsigned long long crc = crc64(0, (const char*)query, strlen(query));
	if (cache_customlist_blacklist_contains(cached_customlist, identity, crc) == 1)
	{
		printf("cache contains blacklisted domain %s\n", query);
	}
	else
	{
		printf("cache does not contain blacklisted domain %s %x\n", query, crc);
	}

	for (int i = 0; i < cached_customlist->index; i++)
	{
		if (strcmp(cached_customlist->identity[i], identity) == 0)
		{
			printf("identity=>%s\n", cached_customlist->identity[i]);
			printf(" whitelist:\n");
			cache_list_domains(cached_customlist->whitelist[i], 1);
			printf(" blacklist:\n");
			cache_list_domains(cached_customlist->blacklist[i], 1);
		}
	}


	return 0;
}


int test_whitelist()
{
	printf("\nenter identity:");
	char identity[80] = {};
	scanf("%79s", identity);
	printf("\nenter domain:");
	char query[80] = {};
	scanf("%79s", query);
	unsigned long long crc = crc64(0, (const char*)query, strlen(query));
	if (cache_customlist_whitelist_contains(cached_customlist, identity, crc) == 1)
	{
		printf("cache contains whitelisted domain %s\n", query);
	}
	else
	{
		printf("cache does not contain whitelisted domain %s %x\n", query, crc);
	}

	for (int i = 0; i < cached_customlist->index; i++)
	{
		if (strcmp(cached_customlist->identity[i], identity) == 0)
		{
			printf("identity=>%s\n", cached_customlist->identity[i]);
			printf(" whitelist:\n");
			cache_list_domains(cached_customlist->whitelist[i], 1);
			printf(" blacklist:\n");
			cache_list_domains(cached_customlist->blacklist[i], 1);
		}
	}


	return 0;
}

int test_cache_contains_address4()
{
	struct ip_addr from = {};
	printf("\nenter ip:");
	char query[80] = {};
	scanf("%79s", query);
	char byte[4];
	char *address = query;
	inet_pton(AF_INET, address, &byte);
	from.family = AF_INET;

	iprange item;
	// if (cache_iprange_contains(cached_iprange, (const struct ip_addr *)&from, address, &item) == 1)
	// {
	// 	puts("contains\n");
	// }
	// else
	// {
	// 	puts("NOT contains\n");
	// }

	if (cache_iprange_contains_old(cached_iprange, (const struct ip_addr *)&from, &item) == 1)
	{
		puts("old contains\n");
	}
	else
	{
		puts("old NOT contains");
	}

	return 0;
}

int test_cache_contains_address6()
{
	struct ip_addr from = {};
	printf("\nenter ip:");
	char query[80] = {};
	scanf("%79s", query);

	char byte[16];
	char *address = query;
	if (1 != inet_pton(AF_INET6, address, &byte))
	{
		return 0;
	}
	from.family = AF_INET6;

	//memcpy(&from.ipv6_sin_addr, &byte, 16);
	//memset((unsigned char *)&from.ipv6_sin_addr + 8, 0, 8);

	iprange item;
	// if (cache_iprange_contains(cached_iprange, (const struct ip_addr *)&from, address, &item) == 1)
	// {
	// 	puts("contains\n");
	// }
	// else
	// {
	// 	puts("NOT contains\n");
	// }

	if (cache_iprange_contains_old(cached_iprange, (const struct ip_addr *)&from, &item) == 1)
	{
		puts("old contains\n");
	}
	else
	{
		puts("old NOT contains");
	}

	return 0;
}

int test_cache_list_domains(cache_domain *domainsToList, int padding)
{
	if (domainsToList == NULL)
	{
		printf("%sdomains is NULL\n", (padding == 1) ? "  " : "");
		return 0;
	}
	printf("%scapacity: [%x]\n", (padding == 1) ? "  " : "", domainsToList->capacity);
	for (int i = 0; i < domainsToList->capacity; i++)
	{
		//if (domainsToList->base[i] != 8554644589776997716)
		//	continue;

		if (domainsToList->accuracy == NULL)
		{
			printf("%s[%08d]\tcrc=>%016llx\n", (padding == 1) ? "  " : "", i, domainsToList->base[i]);
			continue;
		}

		unsigned char *flags = (unsigned char *)&domainsToList->flags[i];
		printf("%s[%08d]\tcrc=>%016llx\taccu=>%04d\tflags=>%02X %02X %02X %02X %02X %02X %02X %02X\n", (padding == 1) ? "  " : "", i, domainsToList->base[i], domainsToList->accuracy[i],
			(unsigned char)flags[0],
			(unsigned char)flags[1],
			(unsigned char)flags[2],
			(unsigned char)flags[3],
			(unsigned char)flags[4],
			(unsigned char)flags[5],
			(unsigned char)flags[6],
			(unsigned char)flags[7]);
	}

	return 0;
}

int cache_list_domains(cache_domain *domainsToList, int padding)
{
	if (domainsToList == NULL)
	{
		printf("%sdomains is NULL\n", (padding == 1) ? "  " : "");
		return 0;
	}
	printf("%scapacity: [%x]\n", (padding == 1) ? "  " : "", domainsToList->capacity);
	for (int i = 0; i < domainsToList->index; i++)
	{
		//if (domainsToList->base[i] != 8554644589776997716)
		//	continue;

		if (domainsToList->accuracy == NULL)
		{
			printf("%s[%08d]\tcrc=>%016llx\n", (padding == 1) ? "  " : "", i, domainsToList->base[i]);
			continue;
		}

		unsigned char *flags = (unsigned char *)&domainsToList->flags[i];
		printf("%s[%08d]\tcrc=>%016llx\taccu=>%04d\tflags=>%02X %02X %02X %02X %02X %02X %02X %02X\n", (padding == 1) ? "  " : "", i, domainsToList->base[i], domainsToList->accuracy[i],
			(unsigned char)flags[0],
			(unsigned char)flags[1],
			(unsigned char)flags[2],
			(unsigned char)flags[3],
			(unsigned char)flags[4],
			(unsigned char)flags[5],
			(unsigned char)flags[6],
			(unsigned char)flags[7]);
	}

	return 0;
}

int test_cache_list_custom()
{
	if (cached_customlist == NULL)
	{
		printf("capacity: parent is NULL\n");
		return -1;
	}
	printf("capacity: [%x]\n", cached_customlist->capacity);
	for (int i = 0; i < cached_customlist->index; i++)
	{
		printf("identity=>%s\n", cached_customlist->identity[i]);
		printf(" whitelist:\n");
		cache_list_domains(cached_customlist->whitelist[i], 1);
		printf(" blacklist:\n");
		cache_list_domains(cached_customlist->blacklist[i], 1);
	}
}

int test_cache_list_policy()
{
	printf("capacity: [%x]\n", cached_policy->capacity);
	for (int i = 0; i < cached_policy->index; i++)
	{
		printf("pol=>%08d\tstrat=>%08d\taudit=>%08d\tblock=>%08d\n", cached_policy->policy[i], cached_policy->strategy[i], cached_policy->audit[i], cached_policy->block[i]);
	}

	return 0;
}

int cache_list_ranges()
{
	if (cached_iprange == NULL)
	{
		printf("ranges are emtpy\n");
		return -1;
	}
	printf("capacity: [%x]\n", cached_iprange->capacity);
	for (int i = 0; i < cached_iprange->index; i++)
	{
		if (cached_iprange->low[i]->family == 0x02)
		{
			printf("t=>%02x\tcrc=>%016llx\tiplo=>%08x\tiphi=>%08x\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->base[i], cached_iprange->low[i]->ipv4_sin_addr, cached_iprange->high[i]->ipv4_sin_addr, cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
		else
		{
			printf("t=>%02x\tcrc=>%016llx\tiplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tiphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->base[i],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[0], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[1], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[2], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[3],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[4], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[5], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[6], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[7],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[8], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[9], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[10], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[11],
				((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[12], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[13], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[14], ((unsigned char*)&cached_iprange->low[i]->ipv6_sin_addr)[15],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[0], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[1], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[2], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[3],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[4], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[5], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[6], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[7],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[8], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[9], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[10], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[11],
				((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[12], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[13], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[14], ((unsigned char*)&cached_iprange->high[i]->ipv6_sin_addr)[15],
				cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
	}
}

int cache_list_range_contains()
{
	printf("\nenter identity:");
	char query[80] = {};
	scanf("%79s", query);

	if (cached_iprange == NULL)
	{
		printf("ranges are emtpy\n");
		return -1;
	}
	printf("capacity: [%x]\n", cached_iprange->capacity);
	for (int i = 0; i < cached_iprange->index; i++)
	{
		if (strcmp(query, cached_iprange->identity[i]) != 0)
			continue;

		if (cached_iprange->low[i]->family == 0x02)
		{
			printf("t=>%02x\tiplo=>%08x\tiphi=>%08x\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->low[i]->ipv4_sin_addr, cached_iprange->high[i]->ipv4_sin_addr, cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
		else
		{
			printf("t=>%02x\tiplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tiphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family,
				((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[0], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[1], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[2], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[3],
				((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[4], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[5], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[6], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[7],
				((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[8], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[9], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[10], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[11],
				((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[12], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[13], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[14], ((unsigned char*)& cached_iprange->low[i]->ipv6_sin_addr)[15],
				((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[0], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[1], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[2], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[3],
				((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[4], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[5], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[6], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[7],
				((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[8], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[9], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[10], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[11],
				((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[12], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[13], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[14], ((unsigned char*)& cached_iprange->high[i]->ipv6_sin_addr)[15],
				cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
	}
}

int test_load_file()
{
	printf("\nenter file to load:");
	char query[80] = {};
	scanf("%79s", query);
	//while (1)
	load_file(query);

	return 0;
}

static int userInput()
{
	char command[80] = { 0 };
	fprintf(stdout, "\nType command:");
	scanf("%79s", command);

	if (strcmp("exit", command) == 0)
	{
		return 0;
	} 
	else if (strcmp("iprangetest4", command) == 0)
	{
		test_cache_contains_address4();
	}
	else if (strcmp("iprangetest6", command) == 0)
	{
		test_cache_contains_address6();
	}
	else if (strcmp("domain", command) == 0)
	{
		test_domain_exists();
	} 
	else if (strcmp("domains", command) == 0)
	{
		test_cache_list_domains(cached_domain, 0);
	}
	else if (strcmp("custom", command) == 0)
	{
		test_cache_list_custom();
	}
	else if (strcmp("blacklist", command) == 0)
	{
		test_blacklist();
	}
	else if (strcmp("whitelist", command) == 0)
	{
		test_whitelist();
	}
	else if (strcmp("policy", command) == 0)
	{
		test_cache_list_policy();
	}
	else if (strcmp("ranges", command) == 0)
	{
		test_cache_list_ranges();
	}
	else if (strcmp("identity", command) == 0)
	{
		cache_list_range_contains();
	}
	else if (strcmp("load", command) == 0)
	{
		test_load_file();
	}
	else
	{
		usage();
	}

	return 1;
}

int main()
{
	int err = 0;
	int thr_id = 0;
	if ((err = create((void *)&thr_id)) != 0)
	{
		debugLog("\"%s\":\"%s\"", "message", "error in create");
		return err;
	}

	usage();
	while (userInput());

	if ((err = destroy((void *)&thr_id)) != 0)
	{
		debugLog("\"%s\":\"%s\"", "message", "error in destroy");
		return err;
	}

	return err;
}

#endif