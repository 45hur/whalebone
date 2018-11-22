/* Convenience macro to declare module API. */
#define C_MOD_WHALEBONE "\x09""whalebone"

#include "lib/module.h"
#include <pthread.h>
#include <syslog.h>
#include <lib/rplan.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "whalebone.h"

static void* observe(void *arg)
{
	/* ... do some observing ... */
	logtosyslog("\"message\":\"loading\"");


	unsigned long long ret = 0;
	//if ((ret = loader_init()) != 0)
	//{
	//	logtosyslog("\"message\":\"csv load failed\"");
	//	return (void *)-1;
	//}

	if ((cached_iprange_slovakia = cache_iprange_init(5)) == NULL)
	{
		puts("not enough memory to create ip range cache");
		return (void *)-1;
	}

	struct ip_addr ip4addr_low;
	struct ip_addr ip4addr_high;

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "10.98.0.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_low.ipv4_sin_addr = __builtin_bswap32(ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "10.98.127.255", &ip4addr_high.ipv4_sin_addr);
	ip4addr_high.ipv4_sin_addr = __builtin_bswap32(ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "100.120.0.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_low.ipv4_sin_addr = __builtin_bswap32(ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "100.127.255.255", &ip4addr_high.ipv4_sin_addr);
	ip4addr_high.ipv4_sin_addr = __builtin_bswap32(ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "100.112.0.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_low.ipv4_sin_addr = __builtin_bswap32(ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "100.119.255.255", &ip4addr_high.ipv4_sin_addr);
	ip4addr_high.ipv4_sin_addr = __builtin_bswap32(ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.21", &ip4addr_low.ipv4_sin_addr);
	ip4addr_low.ipv4_sin_addr = __builtin_bswap32(ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.21", &ip4addr_high.ipv4_sin_addr);
	ip4addr_high.ipv4_sin_addr = __builtin_bswap32(ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.30", &ip4addr_low.ipv4_sin_addr);
	ip4addr_low.ipv4_sin_addr = __builtin_bswap32(ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "127.0.0.30", &ip4addr_high.ipv4_sin_addr);
	ip4addr_high.ipv4_sin_addr = __builtin_bswap32(ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	ip4addr_low.family = AF_INET;
	inet_pton(AF_INET, "151.236.224.0", &ip4addr_low.ipv4_sin_addr);
	ip4addr_low.ipv4_sin_addr = __builtin_bswap32(ip4addr_low.ipv4_sin_addr);
	ip4addr_high.family = AF_INET;
	inet_pton(AF_INET, "151.236.239.255", &ip4addr_high.ipv4_sin_addr);
	ip4addr_high.ipv4_sin_addr = __builtin_bswap32(ip4addr_high.ipv4_sin_addr);
	cache_iprange_add(cached_iprange_slovakia, &ip4addr_low, &ip4addr_high, "", 0);

	pthread_t thr_id;
	if ((ret = pthread_create(&thr_id, NULL, &socket_server, NULL)) != 0)
	{
		logtosyslog("\"message\":\"create thread failed\"");
		return (void *)ret;
	}

	logtosyslog("\"message\":\"load succeeded\"");

	return NULL;
}

static int load(struct kr_module *module, const char *path)
{
	return kr_ok();
}

static int parse_addr_str(struct sockaddr_storage *sa, const char *addr) {
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	memset(sa, 0, sizeof(struct sockaddr_storage));
	sa->ss_family = family;
	char *addr_bytes = (char *)kr_inaddr((struct sockaddr *)sa);
	if (inet_pton(family, addr, addr_bytes) < 1) {
		return kr_error(EILSEQ);
	}
	return 0;
}

static int consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	if (qry->flags.CACHED || !req->qsource.addr)
	{
		sprintf(message, "\"type\":\"consume\",\"message\":\"consume has no valid address\"");
		logtosyslog(message);

		return ctx->state;
	}

	const struct sockaddr *res = req->qsource.addr;
	char *s = NULL;
	switch (res->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
		s = malloc(INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
		s = malloc(INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
		break;
	}
	default:
	{
		logtosyslog("\"type\":\"consume\",\"message\":\"not valid addr\"");
		return ctx->state;
		break;
	}
	}
	sprintf(message, "\"type\":\"consume\",\"message\":\"consume address: %s\"", s);
	logtosyslog(message);
	free(s);

	return ctx->state;
}

static int redirect(struct kr_request * request, struct kr_query *last, int rrtype, struct ip_addr * origin, const char * originaldomain)
{
	char message[KNOT_DNAME_MAXLEN] = {};

	if (rrtype == KNOT_RRTYPE_A || rrtype == KNOT_RRTYPE_AAAA)
	{
		uint16_t msgid = knot_wire_get_id(request->answer->wire);
		kr_pkt_recycle(request->answer);

		knot_pkt_put_question(request->answer, last->sname, last->sclass, last->stype);
		knot_pkt_begin(request->answer, KNOT_ANSWER); //AUTHORITY?

		struct sockaddr_storage sinkhole;
		if (rrtype == KNOT_RRTYPE_A)
		{
			const char *sinkit_sinkhole = getenv("SINKIP");
			if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
			{
				sinkit_sinkhole = "0.0.0.0";
			}

			iprange iprange_item = {};
			if (cache_iprange_contains(cached_iprange_slovakia, origin, &iprange_item) == 1)
			{
				sprintf(message, "\"message\":\"origin matches slovakia\"");
				logtosyslog(message);
				sinkit_sinkhole = "194.228.41.77";
			}
			else
			{
				sprintf(message, "\"message\":\"origin does not match slovakia\"");
				logtosyslog(message);
			}

			if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
			{
				return kr_error(EINVAL);
			}
		}
		else if (rrtype == KNOT_RRTYPE_AAAA)
		{
			const char *sinkit_sinkhole = getenv("SINKIPV6");
			if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
			{
				sinkit_sinkhole = "0000:0000:0000:0000:0000:0000:0000:0001";
			}
			if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
			{
				return kr_error(EINVAL);
			}
		}


		size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
		const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);
		static knot_rdata_t rdata_arr[RDATA_ARR_MAX];

		knot_wire_set_id(request->answer->wire, msgid);

		kr_pkt_put(request->answer, last->sname, 1, KNOT_CLASS_IN, rrtype, raw_addr, addr_len);
	}
	else if (rrtype == KNOT_RRTYPE_CNAME)
	{
		uint8_t buff[KNOT_DNAME_MAXLEN];
		knot_dname_t *dname = knot_dname_from_str(buff, originaldomain, sizeof(buff));
		if (dname == NULL) {
			return KNOT_EINVAL;
		}

		uint16_t msgid = knot_wire_get_id(request->answer->wire);
		kr_pkt_recycle(request->answer);

		knot_pkt_put_question(request->answer, dname, KNOT_CLASS_IN, KNOT_RRTYPE_A);
		knot_pkt_begin(request->answer, KNOT_ANSWER);
		
		struct sockaddr_storage sinkhole;
		const char *sinkit_sinkhole = getenv("SINKIP");
		if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
		{
			sinkit_sinkhole = "0.0.0.0";
		}

		iprange iprange_item = {};
		if (cache_iprange_contains(cached_iprange_slovakia, origin, &iprange_item) == 1)
		{
			sprintf(message, "\"message\":\"origin matches slovakia\"");
			logtosyslog(message);
			sinkit_sinkhole = "194.228.41.77";
		}
		else
		{
			sprintf(message, "\"message\":\"origin does not match slovakia\"");
			logtosyslog(message);
		}

		if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
		{
			return kr_error(EINVAL);
		}

		size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
		const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);
		static knot_rdata_t rdata_arr[RDATA_ARR_MAX];

		knot_wire_set_id(request->answer->wire, msgid);

		kr_pkt_put(request->answer, dname, 1, KNOT_CLASS_IN, KNOT_RRTYPE_A, raw_addr, addr_len);
	}

	return KR_STATE_DONE;
}

static int search(kr_layer_t *ctx, const char * querieddomain, struct ip_addr * origin, struct kr_request * request, struct kr_query * last, char * req_addr, int rrtype, char * originaldomain, char * logmessage)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	unsigned long long crc = crc64(0, (const unsigned char*)querieddomain, strlen(querieddomain));
	domain domain_item = {};
	if (cache_domain_contains(cached_domain, crc, &domain_item, 0) == 1)
	{
		sprintf(message, "\"type\":\"search\",\"message\":\"detected ioc '%s'\"", querieddomain);
		logtosyslog(message);

		iprange iprange_item = {};
		if (cache_iprange_contains(cached_iprange, origin, &iprange_item) == 1)
		{
			sprintf(message, "\"type\":\"search\",\"message\":\"detected ioc '%s' matches ip range with ident '%s' policy '%d'\"", querieddomain, iprange_item.identity, iprange_item.policy_id);
			logtosyslog(message);
		}
		else
		{
			sprintf(message, "\"type\":\"search\",\"message\":\"detected ioc '%s' does not matches any ip range\"", querieddomain);
			logtosyslog(message);
			iprange_item.identity = "";
			iprange_item.policy_id = 0;
		}

		if (strlen(iprange_item.identity) > 0)
		{
			unsigned long long crcIoC = crc64(0, (const unsigned char*)querieddomain, strlen(originaldomain));
			sprintf(message, "\"type\":\"search\",\"message\":\"identity '%s' query '%s'.\"", iprange_item.identity, querieddomain);
			logtosyslog(message);
			if (cache_customlist_whitelist_contains(cached_customlist, iprange_item.identity, crc) == 1 ||
                            cache_customlist_whitelist_contains(cached_customlist, iprange_item.identity, crcIoC) == 1)
			{
				sprintf(message, "\"client_ip\":\"%s\",\"identity\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"allow\",\"reason\":\"whitelist\"", req_addr, iprange_item.identity, originaldomain, querieddomain);
				//logtofile(message);
				sprintf(logmessage, "%s", message);
				logtosyslog(message);
				return KR_STATE_DONE;
			}
			if (cache_customlist_blacklist_contains(cached_customlist, iprange_item.identity, crc) == 1 ||
		            cache_customlist_blacklist_contains(cached_customlist, iprange_item.identity, crcIoC) == 1)
			{
				sprintf(message, "\"client_ip\":\"%s\",\"identity\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"block\",\"reason\":\"blacklist\"", req_addr, iprange_item.identity, originaldomain, querieddomain);
				//logtofile(message);
				sprintf(logmessage, "%s", message);
				logtosyslog(message);
				return redirect(request, last, rrtype, origin, originaldomain);
			}
		}
		sprintf(message, "\"type\":\"search\",\"message\":\"no identity match, checking policy..\"");
		logtosyslog(message);

		policy policy_item = {};
		if (cache_policy_contains(cached_policy, iprange_item.policy_id, &policy_item) == 1)
		{
			int domain_flags = cache_domain_get_flags(domain_item.flags, iprange_item.policy_id);
			if (domain_flags == 0)
			{
				sprintf(message, "\"type\":\"search\",\"message\":\"policy has strategy flags_none\",\"flags\":\"%llu\",\"policy_id\":\"%d\"", domain_item.flags, iprange_item.policy_id);
				logtosyslog(message);
			}
			if (domain_flags & flags_accuracy)
			{
				if (policy_item.block > 0 && domain_item.accuracy > policy_item.block)
				{
					sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"block\",\"reason\":\"accuracy\",\"accuracy\":\"%d\",\"audit\":\"%d\",\"block\":\"%d\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, domain_item.accuracy, policy_item.audit, policy_item.block, iprange_item.identity);
					logtosyslog(message);
					//logtofile(message);
					sprintf(logmessage, "%s", message);
					logtoaudit(message);

					return redirect(request, last, rrtype, origin, originaldomain);
				}
				else
				{
					if (policy_item.audit > 0 && domain_item.accuracy > policy_item.audit)
					{
						sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"audit\",\"reason\":\"accuracy\",\"accuracy\":\"%d\",\"audit\":\"%d\",\"block\":\"%d\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, domain_item.accuracy, policy_item.audit, policy_item.block, iprange_item.identity);
						logtosyslog(message);
						//logtofile(message);
						sprintf(logmessage, "%s", message);
						logtoaudit(message);
					}
					else
					{
						sprintf(message, "\"type\":\"search\",\"message\":\"policy has no action\",\"accuracy\":\"%d\",\"audit\":\"%d\",\"block\":\"%d\",\"identity\":\"%s\"", domain_item.accuracy, policy_item.audit, policy_item.block, iprange_item.identity);
						logtosyslog(message);
					}
				}
			}
			if (domain_flags & flags_whitelist)
			{
				sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"allow\",\"reason\":\"whitelist\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, iprange_item.identity);
				logtosyslog(message);
                                return KR_STATE_DONE;
			}
			if (domain_flags & flags_blacklist)
			{
				sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"block\",\"reason\":\"blacklist\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, iprange_item.identity);
				logtosyslog(message);
				//logtofile(message);
				sprintf(logmessage, "%s", message);
				return redirect(request, last, rrtype, origin, originaldomain);
			}
			if (domain_flags & flags_drop)
			{
				sprintf(message, "\"policy_id\":\"%d\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"ioc\":\"%s\",\"action\":\"allow\",\"reason\":\"drop\",\"identity\":\"%s\"", iprange_item.policy_id, req_addr, originaldomain, querieddomain, iprange_item.identity);
				logtosyslog(message);
			}
		}
		else
		{
			sprintf(message, "\"type\":\"search\",\"message\":\"cached_policy does not match\"");
			logtosyslog(message);
		}
	}
	else
	{
		sprintf(message, "\"type\":\"search\",\"message\":\"cache domains does not have a match to '%s'\"", querieddomain);
		logtosyslog(message);
	}

	return KR_STATE_DONE;
}

static int explode(kr_layer_t *ctx, char * domain, struct ip_addr * origin, struct kr_request * request, struct kr_query * last, char * req_addr, int rrtype)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	char logmessage[KNOT_DNAME_MAXLEN] = {};
	char *ptr = domain;
	ptr += strlen(domain);
	int result = ctx->state;
	int found = 0;
	while (ptr-- != (char *)domain)
	{
		if (ptr[0] == '.')
		{
			if (++found > 1)
			{
				sprintf(message, "\"type\":\"explode\",\"message\":\"search %s\"", ptr + 1);
				logtosyslog(message);
				if ((result = search(ctx, ptr + 1, origin, request, last, req_addr, rrtype, domain, logmessage)) != KR_STATE_DONE)
				{
					if (logmessage[0] != '\0')
					{
						logtofile(logmessage);
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
				logtosyslog(message);
				if ((result = search(ctx, ptr, origin, request, last, req_addr, rrtype, domain, logmessage)) != KR_STATE_DONE)
				{
					if (logmessage[0] != '\0')
					{
						logtofile(logmessage);
					}
					return result;
				}
			}
		}
	}
	if (logmessage[0] != '\0')
	{
		logtofile(logmessage);
	}

	return ctx->state;
}

static int can_satisfy(struct kr_query *qry)
{
	return 0;
}

static int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	char message[KNOT_DNAME_MAXLEN] = {};
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	/* Query can be satisfied locally. */
	if (can_satisfy(qry) == 1)
	{

		sprintf(message, "\"message\":\"produce can satisfy\"");
		logtosyslog(message);

		/* This flag makes the resolver move the query
		* to the "resolved" list. */
		qry->flags.RESOLVED = true;
		return KR_STATE_DONE;
	}

	sprintf(message, "\"message\":\"produce can't satisfy\"");
	logtosyslog(message);

	/* Pass-through. */
	return ctx->state;
}

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

	char qname_str[KNOT_DNAME_MAXLEN];
	if (rplan->resolved.len > 0)
	{
		bool sinkit = false;
		uint16_t rclass = 0;
		struct kr_query *last = array_tail(rplan->resolved);
		const knot_pktsection_t *ns = knot_pkt_section(request->answer, KNOT_ANSWER);

		if (ns == NULL)
		{
			logtosyslog("\"type\":\"finish\",\"message\":\"ns = NULL\"");
			goto cleanup;
		}

		if (ns->count == 0)
		{
			sprintf(message, "\"type\":\"finish\",\"message\":\"query has no asnwer\"");
			logtosyslog(message);

			const knot_pktsection_t *au = knot_pkt_section(request->answer, KNOT_AUTHORITY);
			for (unsigned i = 0; i < au->count; ++i)
			{
				const knot_rrset_t *rr = knot_pkt_rr(au, i);

				if (rr->type == KNOT_RRTYPE_SOA)
				{
					char querieddomain[KNOT_DNAME_MAXLEN] = {};
					knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

					int domainLen = strlen(querieddomain);
					if (querieddomain[domainLen - 1] == '.')
					{
						querieddomain[domainLen - 1] = '\0';
					}

					sprintf(message, "\"type\":\"finish\",\"message\":\"authority for %s\"", querieddomain);
					logtosyslog(message);

					//ctx->state = explode(ctx, (char *)&querieddomain, &origin, request, last, req_addr);
					//break;
				}
				else
				{
					sprintf(message, "\"type\":\"finish\",\"message\":\"authority rr type is not SOA [%d]\"", (int)rr->type);
					logtosyslog(message);
				}
			}
		}

		for (unsigned i = 0; i < ns->count; ++i)
		{
			const knot_rrset_t *rr = knot_pkt_rr(ns, i);

			if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA || rr->type == KNOT_RRTYPE_CNAME)
			{
				char querieddomain[KNOT_DNAME_MAXLEN];
				knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

				int domainLen = strlen(querieddomain);
				if (querieddomain[domainLen - 1] == '.')
				{
					querieddomain[domainLen - 1] = '\0';
				}

				sprintf(message, "\"type\":\"finish\",\"message\":\"query for %s type %d\"", querieddomain, rr->type);
				logtosyslog(message);


				ctx->state = explode(ctx, (char *)&querieddomain, &origin, request, last, req_addr, rr->type);
				break;
			}
			else
			{
				sprintf(message, "\"type\":\"finish\",\"message\":\"rr type is not A, AAAA or CNAME [%d]\"", (int)rr->type);
				logtosyslog(message);
			}
		}
	}
	else
	{
		sprintf(message, "\"type\":\"finish\",\"message\":\"query has no resolve plan\"");
		logtosyslog(message);
	}

cleanup:
	free(req_addr);

	return ctx->state;
}

KR_EXPORT
const kr_layer_api_t *whalebone_layer(struct kr_module *module) {
	static kr_layer_api_t _layer = {
			.consume = &consume,
			.produce = &produce,
			.finish = &finish,
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}

KR_EXPORT
int whalebone_init(struct kr_module *module)
{
	int fd = shm_open("/mutex.whalebone.kres.module", O_CREAT | O_TRUNC | O_RDWR, 0600);
	ftruncate(fd, sizeof(struct shared));

	p = (struct shared*)mmap(0, sizeof(struct shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	p->sharedResource = 0;

	// Make sure it can be shared across processes
	pthread_mutexattr_t shared;
	pthread_mutexattr_init(&shared);
	pthread_mutexattr_setpshared(&shared, PTHREAD_PROCESS_SHARED);

	pthread_mutex_init(&(p->mutex), &shared);

	/* Create a thread and start it in the background. */
	pthread_t thr_id;
	int ret = pthread_create(&thr_id, NULL, &observe, NULL);
	if (ret != 0) {
		return kr_error(errno);
	}

	char msginit[KNOT_DNAME_MAXLEN] = {};
	sprintf(msginit, "\"message\":\"module init\"");
	logtosyslog(msginit);

	/* Keep it in the thread */
	module->data = (void *)thr_id;
	return kr_ok();
}

KR_EXPORT
int whalebone_deinit(struct kr_module *module)
{
	munmap(p, sizeof(struct shared*));
	shm_unlink("/mutex.whalebone.kres.module");

	/* ... signalize cancellation ... */
	void *res = NULL;
	pthread_t thr_id = (pthread_t)module->data;
	int ret = pthread_join(thr_id, res);
	if (ret != 0) {
		return kr_error(errno);
	}

	return kr_ok();
}

KR_MODULE_EXPORT(whalebone)