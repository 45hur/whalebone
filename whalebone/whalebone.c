#define C_MOD_WHALEBONE "\x09""whalebone"

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
	debugLog("\"%s\":\"%s\"", "debug", "finish");

	struct kr_request *request = (struct kr_request *)ctx->req;
	struct kr_rplan *rplan = &request->rplan;
	char address[256] = { 0 };
	int err = 0;
	struct ip_addr req_addr = { 0 };

	if ((err = getip(request, (char *)&address, &req_addr)) != 0)
	{
		//return err; generates log message --- [priming] cannot resolve '.' NS, next priming query in 10 seconds
		//we do not care about no address sources
		debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "finish", "getip", err);

		return ctx->state;
	}

	//redirect(request, last, rrtype, origin, originaldomain)
	char qname_str[KNOT_DNAME_MAXLEN] = { 0 };
	if ((err = getdomain((char *)&qname_str, request, rplan, &req_addr)) != 0)
	{
		if (err == 1)
		{
			debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "finish", "redirect", err);
			//redirect(request, rplan, )
		}
		else
		{
			debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "finish", "getdomain", err);
			ctx->state = KR_STATE_FAIL;
		}
	}

	return ctx->state;
}

int getip(struct kr_request *request, char *address, struct ip_addr *req_addr)
{
	if (!request->qsource.addr) {
		debugLog("\"%s\":\"%s\"", "error", "no source address");

		return -1;
	}

	const struct sockaddr *res = request->qsource.addr;
	bool ipv4 = true;
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
		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), address, INET6_ADDRSTRLEN);
		req_addr->family = AF_INET6;
		memcpy(&req_addr->ipv6_sin_addr, &(addr_in6->sin6_addr), 16);
		ipv4 = false;
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

int getdomain(char *qname_str, struct kr_request *request, struct kr_rplan *rplan, struct ip_addr *req_addr)
{
	if (rplan->resolved.len > 0)
	{
		bool sinkit = false;
		uint16_t rclass = 0;
		struct kr_query *last = array_tail(rplan->resolved);
		const knot_pktsection_t *ns = knot_pkt_section(request->answer, KNOT_ANSWER);

		if (ns == NULL)
		{
			debugLog("\"type\":\"finish\",\"message\":\"ns = NULL\"");
			return -1;
		}

		if (ns->count == 0)
		{
			debugLog("\"type\":\"finish\",\"message\":\"query has no asnwer\"");

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

					debugLog("\"type\":\"finish\",\"message\":\"authority for %s\"", querieddomain);

					//ctx->state = explode(ctx, (char *)&querieddomain, &origin, request, last, req_addr);
					//break;
				}
				else
				{
					debugLog("\"type\":\"finish\",\"message\":\"authority rr type is not SOA [%d]\"", (int)rr->type);
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

				debugLog("\"type\":\"finish\",\"message\":\"query for %s type %d\"", querieddomain, rr->type);

				return explode((char *)&querieddomain, req_addr, qname_str, rr->type);
			}
			else
			{
				debugLog("\"type\":\"finish\",\"message\":\"rr type is not A, AAAA or CNAME [%d]\"", (int)rr->type);
			}
		}
	}
	else
	{
		debugLog("\"type\":\"finish\",\"message\":\"query has no resolve plan\"");
	}

	return 0;
}

int redirect(struct kr_request * request, struct kr_query *last, int rrtype, struct ip_addr * origin, const char * originaldomain)
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

			//iprange iprange_item = {};
			//if (cache_iprange_contains(cached_iprange_slovakia, origin, &iprange_item) == 1)
			//{
			//	debugLog("\"message\":\"origin matches slovakia\"");
			//	sinkit_sinkhole = "194.228.41.77";
			//}
			//else
			//{
			//	debugLog("\"message\":\"origin does not match slovakia\"");
			//}

			//if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
			//{
			//	return kr_error(EINVAL);
			//}
		}
		else if (rrtype == KNOT_RRTYPE_AAAA)
		{
			const char *sinkit_sinkhole = getenv("SINKIPV6");
			if (sinkit_sinkhole == NULL || strlen(sinkit_sinkhole) == 0)
			{
				sinkit_sinkhole = "0000:0000:0000:0000:0000:0000:0000:0001";
			}
			//if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
			//{
			//	return kr_error(EINVAL);
			//}
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

		//iprange iprange_item = {};
		//if (cache_iprange_contains(cached_iprange_slovakia, origin, &iprange_item) == 1)
		//{
		//	sprintf(message, "\"message\":\"origin matches slovakia\"");
		//	logtosyslog(message);
		//	sinkit_sinkhole = "194.228.41.77";
		//}
		//else
		//{
		//	sprintf(message, "\"message\":\"origin does not match slovakia\"");
		//	logtosyslog(message);
		//}

		//if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0)
		//{
		//	return kr_error(EINVAL);
		//}

		size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
		const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);
		static knot_rdata_t rdata_arr[RDATA_ARR_MAX];

		knot_wire_set_id(request->answer->wire, msgid);

		kr_pkt_put(request->answer, dname, 1, KNOT_CLASS_IN, KNOT_RRTYPE_A, raw_addr, addr_len);
	}

	return KR_STATE_DONE;
}

KR_EXPORT 
const kr_layer_api_t *whalebone_layer(struct kr_module *module) {
	static kr_layer_api_t _layer = {
			.begin = &begin,
			.consume = &consume,
			.produce = &produce,
			.finish = &finish,
	};

	_layer.data = module;
	return &_layer;
}

KR_EXPORT 
int whalebone_init(struct kr_module *module)
{
	pthread_t thr_id;
	int err = 0;

	void *args = NULL;
	if ((err = create(&args)) != 0)
	{
		debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "whalebone_init", "create", err);
		return kr_error(err);
	}

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