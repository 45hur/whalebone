#define C_MOD_WHALEBONE "\x09""whalebone"

#include "cache_matrix.h"
#include "log.h"
#include "program.h"
#include "whalebone.h"

#ifndef NOKRES

#include <arpa/inet.h>

int begin(kr_layer_t *ctx)
{
	debugLog("\"%s\":\"%s\"", "debug", "begin");

	return ctx->state;
}

int consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	debugLog("\"%s\":\"%s\"", "debug", "consume");
	
	return ctx->state;
}

int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	debugLog("\"%s\":\"%s\"", "debug", "produce");

	return ctx->state;
}

int finish(kr_layer_t *ctx)
{
	//debugLog("\"%s\":\"%s\"", "debug", "finish");

	char userIpAddressString[256] = { 0 };
	char userIpAddressStringUntruncated[256] = { 0 };
	int err = 0;
	struct ip_addr userIpAddress = { 0 };
	struct ip_addr userIpAddressUntruncated = { 0 };

	if ((err = getip(ctx, (char *)&userIpAddressString, &userIpAddress)) != 0)
	{
		//return err; generates log message --- [priming] cannot resolve '.' NS, next priming query in 10 seconds
		//we do not care about no address sources
		//debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "finish", "getip", err);

		return ctx->state;
	}

	if ((err = getuntruncatedip(ctx, (char *)&userIpAddressStringUntruncated, &userIpAddressUntruncated)) != 0)
	{
		//return err; generates log message --- [priming] cannot resolve '.' NS, next priming query in 10 seconds
		//we do not care about no address sources
		//debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "finish", "getuntruncatedip", err);

		return ctx->state;
	}

	char qname_str[KNOT_DNAME_MAXLEN] = { 0 };
	lmdbmatrixvalue matrix = {};
	int rr;
	if ((err = checkDomain((char *)&qname_str, &rr, &matrix, ctx, &userIpAddress, (char *)&userIpAddressString, (char *)&userIpAddressStringUntruncated)) != 0)
	{
		if (matrix.action & MAT_BLOCK) 
		{ 
			debugLog("\"action\":\"block\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"answer\":\"%s\"", userIpAddressStringUntruncated, qname_str, matrix.answer); 
			if (matrix.logContent)
			{
				fileLog("\"action\":\"block\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"answer\":\"%s\"", userIpAddressStringUntruncated, qname_str, matrix.answer); 
			}

			if (strcmp(matrix.answer, "Original") == 0)
			{
				debugLog("\"action\":\"original\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"answer\":\"%s\"", userIpAddressStringUntruncated, qname_str, matrix.answer); 
				return ctx->state;
			}
			return redirect(ctx, rr, &matrix, (char *)&qname_str);
		} 
		if (matrix.action & MAT_ALLOW) 
		{ 
			debugLog("\"action\":\"allow\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"answer\":\"%s\"", userIpAddressStringUntruncated, qname_str, matrix.answer); 
			if (matrix.logContent)
			{
				fileLog("\"action\":\"allow\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"answer\":\"%s\"", userIpAddressStringUntruncated, qname_str, matrix.answer); 
			}
			
			if (strcmp(matrix.answer, "Original") == 0)
			{
				debugLog("\"action\":\"original\",\"client_ip\":\"%s\",\"domain\":\"%s\",\"answer\":\"%s\"", userIpAddressStringUntruncated, qname_str, matrix.answer); 
				return ctx->state;
			}
			return ctx->state;
		} 
	}

	return ctx->state;
}

int checkDomain(char * qname_Str, int * r, lmdbmatrixvalue *matrix, kr_layer_t *ctx, struct ip_addr *userIpAddress, const char *userIpAddressString, const char *userIpAddressStringUntruncated)
{
	struct kr_request *request = (struct kr_request *)ctx->req;
	struct kr_rplan *rplan = &request->rplan;

	if (rplan->resolved.len > 0)
	{
		//bool sinkit = false;
		//uint16_t rclass = 0;
		/*struct kr_query *last = */
		//array_tail(rplan->resolved);
		const knot_pktsection_t *ns = knot_pkt_section(request->answer, KNOT_ANSWER);

		if (ns == NULL)
		{
			debugLog("\"method\":\"getdomain\",\"ns\":\"NULL\"");
			return -1;
		}

		if (ns->count == 0)
		{
			debugLog("\"method\":\"getdomain\",\"message\":\"query has no asnwer\"");

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

					debugLog("\"method\":\"getdomain\",\"authority\":\"%s\"", querieddomain);

					return explode((char *)&querieddomain, userIpAddress, userIpAddressString, userIpAddressStringUntruncated, matrix);
				}
				else
				{
					debugLog("\"method\":\"getdomain\",\"message\":\"authority rr type is not SOA [%d]\"", (int)rr->type);
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

				debugLog("\"method\":\"getdomain\",\"query\":\"%s\",\"type\":\"%d\"", querieddomain, rr->type);
				strcpy(qname_Str, querieddomain);
				*r = rr->type;
				return explode((char *)&querieddomain, userIpAddress, userIpAddressString, userIpAddressStringUntruncated, matrix);
			}
			else
			{
				debugLog("\"method\":\"getdomain\",\"message\":\"rr type is not A, AAAA or CNAME [%d]\"", (int)rr->type);
			}
		}
	}
	else
	{
		debugLog("\"method\":\"getdomain\",\"message\":\"query has no resolve plan\"");
	}

	debugLog("\"method\":\"getdomain\",\"message\":\"return\"");

	return 0;
}

int getip(kr_layer_t *ctx, char *address, struct ip_addr *req_addr)
{
	struct kr_request *request = (struct kr_request *)ctx->req;

	if (!request->qsource.addr) {
		//debugLog("\"%s\":\"%s\"", "error", "no source address");

		return -1;
	}

	const struct sockaddr *res = request->qsource.addr;
	switch (res->sa_family)
	{
	case AF_INET:
	{
		struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
		inet_ntop(AF_INET, &(addr_in->sin_addr), address, INET_ADDRSTRLEN);
		req_addr->family = AF_INET;
		memcpy(&req_addr->ipv4_sin_addr, &(addr_in->sin_addr), 4);
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
		req_addr->family = AF_INET6;
		memcpy(&req_addr->ipv6_sin_addr, &(addr_in6->sin6_addr), 16);
		memset((unsigned char *)&req_addr->ipv6_sin_addr + 8, 0, 8);
		inet_ntop(AF_INET6, &req_addr->ipv6_sin_addr, address, INET6_ADDRSTRLEN);
		break;
	}
	default:
	{
		debugLog("\"%s\":\"%s\"", "error", "qsource invalid");

		return -1;
	}
	}

	return 0;
}

int getuntruncatedip(kr_layer_t *ctx, char *address, struct ip_addr *req_addr)
{
	struct kr_request *request = (struct kr_request *)ctx->req;

	if (!request->qsource.addr) {
		debugLog("\"%s\":\"%s\"", "error", "no source address");

		return -1;
	}

	const struct sockaddr *res = request->qsource.addr;
	switch (res->sa_family)
	{
	case AF_INET:
	{
		struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
		inet_ntop(AF_INET, &(addr_in->sin_addr), address, INET_ADDRSTRLEN);
		req_addr->family = AF_INET;
		memcpy(&req_addr->ipv4_sin_addr, &(addr_in->sin_addr), 4);
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
		req_addr->family = AF_INET6;
		memcpy(&req_addr->ipv6_sin_addr, &(addr_in6->sin6_addr), 16);
		inet_ntop(AF_INET6, &req_addr->ipv6_sin_addr, address, INET6_ADDRSTRLEN);
		break;
	}
	default:
	{
		debugLog("\"%s\":\"%s\"", "error", "qsource invalid");

		return -1;
	}
	}

	return 0;
}

int parse_addr_str(struct sockaddr_storage *sa, const char *addr) 
{
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	memset(sa, 0, sizeof(struct sockaddr_storage));
	sa->ss_family = family;
	char *addr_bytes = (char *)kr_inaddr((struct sockaddr *)sa);
	if (inet_pton(family, addr, addr_bytes) < 1) 
	{
		return kr_error(EILSEQ);
	}
	return 0;
}

int redirect(kr_layer_t *ctx, int rrtype, lmdbmatrixvalue *matrix, const char * originaldomain)
{
	struct kr_request *request = (struct kr_request *)ctx->req;
	struct kr_rplan *rplan = &request->rplan;
	struct kr_query *last = array_tail(rplan->resolved);

	if (rrtype == KNOT_RRTYPE_A || rrtype == KNOT_RRTYPE_AAAA)
	{
		uint16_t msgid = knot_wire_get_id(request->answer->wire);
		kr_pkt_recycle(request->answer);

		knot_pkt_put_question(request->answer, last->sname, last->sclass, last->stype);

		knot_pkt_begin(request->answer, KNOT_ANSWER); //AUTHORITY?

		struct sockaddr_storage sinkhole;
		if (rrtype == KNOT_RRTYPE_A)
		{
			char *sinkit_sinkhole = NULL;
			if (strcmp((char *)&matrix->answer, "SINKHOLE_IP") != 0)
			{
				sinkit_sinkhole = getenv("SINKIP");
				if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
				{
					sinkit_sinkhole = "0.0.0.0";
				}
			}
			else
			{
				sinkit_sinkhole = matrix->answer;
			}
			if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
			{
				return kr_error(EINVAL);
			}
		}
		else if (rrtype == KNOT_RRTYPE_AAAA)
		{
			char *sinkit_sinkhole = NULL;
			if (strcmp((char *)&matrix->answer, "SINKIPV6") != 0)
			{
				sinkit_sinkhole = getenv("SINKIP");
				if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
				{
					sinkit_sinkhole = "0000:0000:0000:0000:0000:0000:0000:0001";
				}
			}
			else
			{
				sinkit_sinkhole = matrix->answer;
			}

			if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
			{
				return kr_error(EINVAL);
			}
		}

		size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
		const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);

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
		char *sinkit_sinkhole = NULL;
		if (strcmp((char *)&matrix->answer, "SINKHOLE_IP") != 0)
		{
			sinkit_sinkhole = getenv("SINKIP");
			if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
			{
				sinkit_sinkhole = "0.0.0.0";
			}
		}
		else
		{
			sinkit_sinkhole = matrix->answer;
		}

		if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
		{
			return kr_error(EINVAL);
		}

		size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
		const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);

		knot_wire_set_id(request->answer->wire, msgid);

		kr_pkt_put(request->answer, dname, 1, KNOT_CLASS_IN, KNOT_RRTYPE_A, raw_addr, addr_len);
	}

	return KR_STATE_DONE;
}

// KR_EXPORT 
// const kr_layer_api_t *whalebone_layer(struct kr_module *module) {
// 	static kr_layer_api_t _layer = {
// //			.begin = &begin,
// //			.consume = &consume,
// //			.produce = &produce,
// 			.finish = &finish,
// 	};

// 	_layer.data = module;
// 	return &_layer;
// }

KR_EXPORT 
int whalebone_init(struct kr_module *module)
{
	int err = 0;

	void *args = NULL;
	if ((err = create(&args)) != 0)
	{
		debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "whalebone_init", "create", err);
		return kr_error(err);
	}

	static kr_layer_api_t layer = {
		.finish = &finish,
	};
	layer.data = module;
	module->layer = &layer;
	module->data = (void *)args;
	
	return kr_ok();
}

KR_EXPORT 
int whalebone_deinit(struct kr_module *module)
{
	int err = 0;
	if ((err = destroy((void *)module->data)) != 0)
	{
		debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "whalebone_deinit", "destroy", err);
		return kr_error(err);
	}

	return kr_ok();
}

KR_MODULE_EXPORT(whalebone)

#endif