#pragma once

#ifndef NOKRES

#include <libknot/packet/pkt.h>

#include "lib/module.h"
#include "lib/layer.h"

#include "lib/resolve.h"
#include "lib/rplan.h"

int begin(kr_layer_t *ctx);
int consume(kr_layer_t *ctx, knot_pkt_t *pkt);
int produce(kr_layer_t *ctx, knot_pkt_t *pkt);
int finish(kr_layer_t *ctx);

int getip(struct kr_request *request, char *address, struct ip_addr *origin);
int getdomain(char *qname_str, struct kr_request * request, struct kr_rplan *rplan, struct ip_addr *req_addr);
int redirect(struct kr_request * request, struct kr_query *last, int rrtype, struct ip_addr *origin, const char *originaldomain);

#endif