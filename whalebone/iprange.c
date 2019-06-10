#include <string.h>

#include "iprange.h"

int is_ip_in_range(const struct ip_addr *ip, const struct ip_addr *from, const struct ip_addr *to)
{

int result = 0;
if (ip->family != from->family || ip->family != to->family)
return result;

switch (ip->family) {
case AF_INET: {
	unsigned int addr_ip = __builtin_bswap32(ip->ipv4_sin_addr);
	unsigned int addr_fr = from->ipv4_sin_addr;
	unsigned int addr_to = to->ipv4_sin_addr;

	result = (addr_ip >= addr_fr) && (addr_ip <= addr_to);
	//printf("%08x => %08x <= %08x -- %d\n",
	//	addr_fr,
	//	addr_ip,
	//	addr_to,
	//	result
	//);
	break;
}
case AF_INET6: {
	unsigned __int128 addr6_ip = ip->ipv6_sin_addr;
	unsigned __int128 addr6_fr = ip->ipv6_sin_addr;
	unsigned __int128 addr6_to = ip->ipv6_sin_addr;

	printf("iplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\niphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\nips=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n\n",
	((unsigned char*)&addr6_fr))[0], ((unsigned char*)&addr6_fr)[1], ((unsigned char*)&addr6_fr)[2], ((unsigned char*)&addr6_fr)[3],
	((unsigned char*)&addr6_fr))[4], ((unsigned char*)&addr6_fr)[5], ((unsigned char*)&addr6_fr)[6], ((unsigned char*)&addr6_fr)[7],
	((unsigned char*)&addr6_fr)[8], ((unsigned char*)&addr6_fr)[9], ((unsigned char*)&addr6_fr)[10], ((unsigned char*)&addr6_fr)[11],
	((unsigned char*)&addr6_fr)[12], ((unsigned char*)&addr6_fr)[13], ((unsigned char*)&addr6_fr)[14], ((unsigned char*)&addr6_fr)[15],
	((unsigned char*)&addr6_fr))[0], ((unsigned char*)&addr6_fr)[1], ((unsigned char*)&addr6_fr)[2], ((unsigned char*)&addr6_fr)[3],
	((unsigned char*)&addr6_fr))[4], ((unsigned char*)&addr6_fr)[5], ((unsigned char*)&addr6_fr)[6], ((unsigned char*)&addr6_fr)[7],
	((unsigned char*)&addr6_fr)[8], ((unsigned char*)&addr6_fr)[9], ((unsigned char*)&addr6_fr)[10], ((unsigned char*)&addr6_fr)[11],
	((unsigned char*)&addr6_fr)[12], ((unsigned char*)&addr6_fr)[13], ((unsigned char*)&addr6_fr)[14], ((unsigned char*)&addr6_fr)[15],
	((unsigned char*)&addr6_fr))[0], ((unsigned char*)&addr6_fr)[1], ((unsigned char*)&addr6_fr)[2], ((unsigned char*)&addr6_fr)[3],
	((unsigned char*)&addr6_fr))[4], ((unsigned char*)&addr6_fr)[5], ((unsigned char*)&addr6_fr)[6], ((unsigned char*)&addr6_fr)[7],
	((unsigned char*)&addr6_fr)[8], ((unsigned char*)&addr6_fr)[9], ((unsigned char*)&addr6_fr)[10], ((unsigned char*)&addr6_fr)[11],
	((unsigned char*)&addr6_fr)[12], ((unsigned char*)&addr6_fr)[13], ((unsigned char*)&addr6_fr)[14], ((unsigned char*)&addr6_fr)[15],
	);
	
				      printf("%llx => %llx <= %llx\n", 
	      (unsigned long long)(addr6_fr& 0xFFFFFFFFFFFFFFFF), 
	      (unsigned long long)(addr6_ip& 0xFFFFFFFFFFFFFFFF), 
	      (unsigned long long)(addr6_to& 0xFFFFFFFFFFFFFFFF) 
	      );

	result = memcmp(&addr6_ip, &addr6_fr, 16) >= 0 && memcmp(&addr6_ip, &addr6_to, 16) <= 0;
	break;
}
default:
{
	printf("wrong ip address\n");
	break;
}
}

return result;
}