/* Convenience macro to declare module API. */
#define C_MOD_WHALEBONE "\x09""whalebone"

#include "program.h"

#include <string.h>
#include <sys/mman.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h>

#include "log.h"
#include "socket_srv.h"
#include "thread_shared.h" 

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

	if ((err = loader_init()) != 0)
		return err;

	pthread_t thr_id;
	if ((err = pthread_create(&thr_id, NULL, &socket_server, NULL)) != 0)
		return err;

	*args = (void *)thr_id;

	debugLog("\"%s\":\"%s\"", "message", "created");

	return err;
}

int destroy(void *args)
{
	int err = 0;
	if ((err = munmap(thread_shared, sizeof(struct shared*))) == 0)
		return err;

	if ((err = shm_unlink(C_MOD_MUTEX)) == 0)
		return err;

	//destroyVector(statistics);

	void *res = NULL;
	pthread_t thr_id = (pthread_t)args;
	if ((err = pthread_join(thr_id, res)) != 0)
		return err;

	debugLog("\"%s\":\"%s\"", "message", "destroyed");

	return err;
}

int search(const char * querieddomain, struct ip_addr * origin, char * req_addr, int rrtype, char * originaldomain, char * logmessage)
{
	char message[255] = {};
	unsigned long long crc = crc64(0, (const char*)querieddomain, strlen(querieddomain));
	domain domain_item = {};
	if (cache_domain_contains(cached_domain, crc, &domain_item, 0) == 1)
	{
		debugLog("\"type\":\"search\",\"message\":\"detected ioc '%s'\"", querieddomain);

		iprange iprange_item = {};
		if (cache_iprange_contains(cached_iprange, origin, &iprange_item) == 1)
		{
			debugLog("\"type\":\"search\",\"message\":\"detected ioc '%s' matches ip range with ident '%s' policy '%d'\"", querieddomain, iprange_item.identity, iprange_item.policy_id);
		}
		else
		{
			debugLog("\"type\":\"search\",\"message\":\"detected ioc '%s' does not matches any ip range\"", querieddomain);
			iprange_item.identity = "";
			iprange_item.policy_id = 0;
		}

		if (strlen(iprange_item.identity) > 0)
		{
			unsigned long long crcIoC = crc64(0, (const char*)querieddomain, strlen(originaldomain));
			debugLog("\"type\":\"search\",\"message\":\"identity '%s' query '%s'.\"", iprange_item.identity, querieddomain);
			if (cache_customlist_whitelist_contains(cached_customlist, iprange_item.identity, crc) == 1 ||
                            cache_customlist_whitelist_contains(cached_customlist, iprange_item.identity, crcIoC) == 1)
			{
				sprintf(message, "\"client_ip\":\"%s\",\"identity\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"allow\",\"reason\":\"whitelist\"", req_addr, iprange_item.identity, originaldomain, querieddomain);
				sprintf(logmessage, "%s", message);
				debugLog(message);
				return 0;
			}
			if (cache_customlist_blacklist_contains(cached_customlist, iprange_item.identity, crc) == 1 ||
		            cache_customlist_blacklist_contains(cached_customlist, iprange_item.identity, crcIoC) == 1)
			{
				sprintf(message, "\"client_ip\":\"%s\",\"identity\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"block\",\"reason\":\"blacklist\"", req_addr, iprange_item.identity, originaldomain, querieddomain);
				sprintf(logmessage, "%s", message);
				debugLog(message);
				return 1;
			}
		}
		debugLog("\"type\":\"search\",\"message\":\"no identity match, checking policy..\"");

		policy policy_item = {};
		if (cache_policy_contains(cached_policy, iprange_item.policy_id, &policy_item) == 1)
		{
			int domain_flags = cache_domain_get_flags(domain_item.flags, iprange_item.policy_id);
			if (domain_flags == 0)
			{
				debugLog("\"type\":\"search\",\"message\":\"policy has strategy flags_none\",\"flags\":\"%llu\",\"policy_id\":\"%d\"", domain_item.flags, iprange_item.policy_id);
			}
			if (domain_flags & flags_accuracy)
			{
				if (policy_item.block > 0 && domain_item.accuracy > policy_item.block)
				{
					sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"block\",\"reason\":\"accuracy\",\"accuracy\":\"%d\",\"audit\":\"%d\",\"block\":\"%d\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, domain_item.accuracy, policy_item.audit, policy_item.block, iprange_item.identity);
					debugLog(message);
					sprintf(logmessage, "%s", message);
					auditLog(message);

					return 1;
				}
				else
				{
					if (policy_item.audit > 0 && domain_item.accuracy > policy_item.audit)
					{
						sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"audit\",\"reason\":\"accuracy\",\"accuracy\":\"%d\",\"audit\":\"%d\",\"block\":\"%d\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, domain_item.accuracy, policy_item.audit, policy_item.block, iprange_item.identity);
						debugLog(message);
						sprintf(logmessage, "%s", message);
						auditLog(message);
					}
					else
					{
						debugLog("\"type\":\"search\",\"message\":\"policy has no action\",\"accuracy\":\"%d\",\"audit\":\"%d\",\"block\":\"%d\",\"identity\":\"%s\"", domain_item.accuracy, policy_item.audit, policy_item.block, iprange_item.identity);
					}
				}
			}
			if (domain_flags & flags_whitelist)
			{
				debugLog("\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"allow\",\"reason\":\"whitelist\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, iprange_item.identity);
                return 0;
			}
			if (domain_flags & flags_blacklist)
			{
				sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"block\",\"reason\":\"blacklist\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, iprange_item.identity);
				debugLog(message);
				sprintf(logmessage, "%s", message);
				return 1;
			}
			if (domain_flags & flags_drop)
			{
				debugLog("\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"allow\",\"reason\":\"drop\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, iprange_item.identity);
			}
		}
		else
		{
			debugLog("\"type\":\"search\",\"message\":\"cached_policy does not match\"");
		}
	}
	else
	{
		debugLog("\"type\":\"search\",\"message\":\"cache domains does not have a match to '%s'\"", querieddomain);
	}

	return 0;
}

int explode(char * domain, struct ip_addr * origin, char * req_addr, int rrtype)
{
	char message[255] = {};
	char logmessage[255] = {};
	char *ptr = domain;
	ptr += strlen(domain);
	int result = 0;
	int found = 0;
	while (ptr-- != (char *)domain)
	{
		if (ptr[0] == '.')
		{
			if (++found > 1)
			{
				sprintf(message, "\"type\":\"explode\",\"message\":\"search %s\"", ptr + 1);
				debugLog(message);
				if ((result = search(ptr + 1, origin, req_addr, rrtype, domain, logmessage)) != 0)
				{
					if (logmessage[0] != '\0')
					{
						fileLog(logmessage);
					}
					return result;
				}
			}
		}
		else
		{
			if (ptr == (char *)domain)
			{
				sprintf(message, "\"type\":\"explode\",\"message\":\"search %s\"", ptr);
				debugLog(message);
				if ((result = search(ptr, origin, req_addr, rrtype, domain, logmessage)) != 0)
				{
					if (logmessage[0] != '\0')
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
}/*
 

static int finish(kr_layer_t *ctx)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	struct kr_request *request = (struct kr_request *)ctx->req;
	struct kr_rplan *rplan = &request->rplan;

	sprintf(message, "\"type\":\"finish\",\"message\":\"enter\"");
	logtosyslog(message);

	if (!request->qsource.addr) {
		sprintf(message, "\"type\":\"finish\",\"message\":\"request has no source address\"");
		logtosyslog(message);

		return ctx->state;
	}

	const struct sockaddr *res = request->qsource.addr;
	char *req_addr = NULL;
	struct ip_addr origin = {};
	bool ipv4 = true;
	switch (res->sa_family) {
	case AF_INET:
	{
		struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
		req_addr = malloc(INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(addr_in->sin_addr), req_addr, INET_ADDRSTRLEN);
		origin.family = AF_INET;
		memcpy(&origin.ipv4_sin_addr, &(addr_in->sin_addr), 4);
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
		req_addr = malloc(INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), req_addr, INET6_ADDRSTRLEN);
		origin.family = AF_INET6;
		memcpy(&origin.ipv6_sin_addr, &(addr_in6->sin6_addr), 16);
		ipv4 = false;
		break;
	}
	default:
	{
		sprintf(message, "\"type\":\"finish\",\"message\":\"qsource is invalid\"");
		logtosyslog(message);
		return ctx->state;
		break;
	}
	}

	sprintf(message, "\"type\":\"finish\",\"message\":\"request from %s\"", req_addr);
	logtosyslog(message);

	

	return ctx->state;
}

*/

#ifdef NOKRES 

static int usage()
{
	fprintf(stdout, "Available commands: ");
	fprintf(stdout, "\n");
	fprintf(stdout, "exit\n");
	fprintf(stdout, "iprangetest\n");
	fprintf(stdout, "domains\n");
	fprintf(stdout, "domain\n");
	fprintf(stdout, "custom\n");
	fprintf(stdout, "blacklist\n");
	fprintf(stdout, "whitelist\n");
	fprintf(stdout, "policy\n");
	fprintf(stdout, "ranges\n");
	fprintf(stdout, "load\n\n");
	return 0;
}

int test_cache_list_ranges()
{
	if (cached_iprange == NULL)
	{
		printf("ranges are emtpy\n");
		return;
	}
	printf("capacity: [%x]\n", cached_iprange->capacity);
	for (int i = 0; i < cached_iprange->capacity; i++)
	{
		if (cached_iprange->low[i]->family == 0x02)
		{
			printf("t=>%02x\tiplo=>%08x\tiphi=>%08x\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->low[i]->ipv4_sin_addr, cached_iprange->high[i]->ipv4_sin_addr, cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
		else
		{
			printf("t=>%02x\tiplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tiphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family,
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
	domain item;
	int result;
	if ((result = cache_domain_contains(cached_domain, crc, &item, 0)) == 1)
	{
		printf("cache contains domain %s", query);
	}
	else
	{
		printf("cache does not contain domain %s", query);
	}
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
	domain item;
	int result;
	if (cache_customlist_blacklist_contains(cached_customlist, identity, crc) == 1)
	{
		printf("cache contains blacklisted domain %s", query);
	}
	else
	{
		printf("cache does not contain blacklisted domain %s", query);
	}
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
	domain item;
	int result;
	if (cache_customlist_whitelist_contains(cached_customlist, identity, crc) == 1)
	{
		printf("cache contains whitelisted domain %s", query);
	}
	else
	{
		printf("cache does not contain whitelisted domain %s", query);
	}
}

int test_cache_contains_address()
{
	struct ip_addr from = {};
	char byte[4];
	inet_pton(AF_INET, "127.0.0.1", &byte);
	from.family = AF_INET;

	memcpy(&from.ipv4_sin_addr, &byte, 4);

	iprange item;
	if (cache_iprange_contains(cached_iprange, (const struct ip_addr *)&from, &item))
	{
		puts("a");
	}
	else
		puts("b");
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
}

int cache_list_domains(cache_domain *domainsToList, int padding)
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
}

int test_cache_list_custom()
{
	if (cached_customlist == NULL)
	{
		printf("capacity: parent is NULL\n");
		return;
	}
	printf("capacity: [%x]\n", cached_customlist->capacity);
	for (int i = 0; i < cached_customlist->capacity; i++)
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
	for (int i = 0; i < cached_policy->capacity; i++)
	{
		printf("pol=>%08d\tstrat=>%08d\taudit=>%08d\tblock=>%08d\n", cached_policy->policy[i], cached_policy->strategy[i], cached_policy->audit[i], cached_policy->block[i]);
	}
}

int cache_list_ranges()
{
	if (cached_iprange == NULL)
	{
		printf("ranges are emtpy\n");
		return;
	}
	printf("capacity: [%x]\n", cached_iprange->capacity);
	for (int i = 0; i < cached_iprange->capacity; i++)
	{
		if (cached_iprange->low[i]->family == 0x02)
		{
			printf("t=>%02x\tiplo=>%08x\tiphi=>%08x\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family, cached_iprange->low[i]->ipv4_sin_addr, cached_iprange->high[i]->ipv4_sin_addr, cached_iprange->policy_id[i], cached_iprange->identity[i]);
		}
		else
		{
			printf("t=>%02x\tiplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tiphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\tpolicy=>%08d\tident=>%s\n", cached_iprange->low[i]->family,
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

int test_load_file()
{
	printf("\nenter file to load:");
	char query[80] = {};
	scanf("%79s", query);
	load_file(query);
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
	else if (strcmp("iprangetest", command) == 0)
	{
		test_cache_contains_address();
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