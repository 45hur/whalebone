#pragma once

#ifndef NOKRES

#include <libknot/packet/pkt.h>

#include "lib/module.h"
#include "lib/layer.h"

#include "lib/resolve.h"
#include "lib/rplan.h"

int begin(kr_layer_t * ctx);
int consume(kr_layer_t * ctx, knot_pkt_t * pkt);
int produce(kr_layer_t * ctx, knot_pkt_t * pkt);
int finish(kr_layer_t * ctx);

int getip(kr_layer_t * ctx, char * address, struct ip_addr * origin);
int checkDomain(char * qname_str, int * r, kr_layer_t * ctx, struct ip_addr * userIpAddress, const char * userIpAddressString);
int redirect(kr_layer_t *ctx, int rrtype, const char * originaldomain);

#endif