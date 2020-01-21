#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>      
#include <unistd.h>

#include "crc64.h"
#include "ipranger.h"
#include "cache_iprange.h"
#include "log.h"

int cache_iprange_contains(MDB_env *env, const struct ip_addr * ip, const char * ipaddr, iprange *item)
{
	int rc = 0;
	debugLog("\"method\":\"cache_iprange_contains\",\"ip\":\"%s\"", ipaddr);
	if ((rc = iprg_get_identity_str(env, ipaddr, item->identity)) == 0)
	{
		debugLog("\"method\":\"cache_iprange_contains\",\"id\":\"%s\"", item->identity);

		return 1;
	}

	return 0;
}