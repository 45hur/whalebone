/*************************************************************************
 * Copyright (C) 2019 Contributors to ipranger project.                   *
 *                                                                        *
 * This program is free software: you can redistribute it and/or modify   *
 * it under the terms of the GNU General Public License as published by   *
 * the Free Software Foundation, either version 3 of the License, or      *
 * (at your option) any later version.                                    *
 *                                                                        *
 * This program is distributed in the hope that it will be useful,        *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 * GNU General Public License for more details.                           *
 *                                                                        *
 * You should have received a copy of the GNU General Public License      *
 * along with this program.  If not, see <https://www.gnu.org/licenses/>. *
 *                                                                        *
 * See ACKNOWLEDGEMENTS.md for further details on licenses.               *
 *************************************************************************/

#include "util.h"
#include "thread_shared.h"
#include "log.h"

#ifndef NOKRES

#define SMALL_BUFFER 512
#define BIG_BUFFER 1024

/*

http://man7.org/linux/man-pages/man3/inet_pton.3.html

NAME         top

       inet_pton - convert IPv4 and IPv6 addresses from text to binary form

SYNOPSIS         top

       #include <arpa/inet.h>

       int inet_pton(int af, const char *src, void *dst);



*/

void ipv6_to_str(const struct in6_addr *addr) {
  printf(
      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
      (int)addr->s6_addr[0], (int)addr->s6_addr[1], (int)addr->s6_addr[2],
      (int)addr->s6_addr[3], (int)addr->s6_addr[4], (int)addr->s6_addr[5],
      (int)addr->s6_addr[6], (int)addr->s6_addr[7], (int)addr->s6_addr[8],
      (int)addr->s6_addr[9], (int)addr->s6_addr[10], (int)addr->s6_addr[11],
      (int)addr->s6_addr[12], (int)addr->s6_addr[13], (int)addr->s6_addr[14],
      (int)addr->s6_addr[15]);
}

// TODO: ??? *addr ???
void ipv4_to_str(const struct in_addr *addr) { printf("%s",inet_ntoa(*addr)); }

static int ntop(struct in_addr *ip, char *host, size_t host_size) {
  struct sockaddr_in in;
  memset(&in, 0, sizeof(struct sockaddr_in));
  in.sin_addr = *ip;
  in.sin_family = AF_INET;
  return getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), host,
                     host_size, NULL, 0, NI_NUMERICHOST);
}

static int ntop6(struct in6_addr *ip, char *host, size_t host_size) {
  struct sockaddr_in6 in6;
  memset(&in6, 0, sizeof(struct sockaddr_in6));
  memcpy(&in6.sin6_addr, ip, sizeof(struct in6_addr));
  in6.sin6_family = AF_INET6;
  return getnameinfo((struct sockaddr *)&in6, sizeof(struct sockaddr_in6), host,
                     host_size, NULL, 0, NI_NUMERICHOST);
}

int   cidr_to_ip(const char *cidr, char **start_ip, char **stop_ip, unsigned char *mymask,
               ip_range_t *ip_range, unsigned char default_mask) {
  char *cidr_tok;
  char *first_ip;
  unsigned char mask;
  char *saveptr = NULL;
  ip_range_t ip;
  int mask_val;
  int mask_byte;
  unsigned long mask_bit;
  char host[SMALL_BUFFER];
  struct addrinfo hints;
  struct addrinfo *res;
  struct sockaddr_in *s_in;
  struct sockaddr_in6 *s_in6;

  *start_ip = NULL;
  *stop_ip = NULL;
  *mymask = 0;

  char *cidrt = strdup(cidr);
  cidr_tok = cidrt;
  if (strstr(cidr, "/") == NULL)
  {
    first_ip = strdup(cidr);
  }
  else
  {
    saveptr = strtok(cidr_tok, "/");
    first_ip = strdup(saveptr);
    saveptr = strtok(NULL, "/");
  }

  if (saveptr == NULL || strlen(saveptr) == 0) 
  {
    mask = default_mask;
  }
  else
  {
    mask = atoi(saveptr);
  }
  free(cidrt);
  
  *mymask = mask;
  if (mask == 0) {
    free(first_ip);
    return 0;
  }

  mask_val = mask;
  
  /* Detecting IPv4 vs IPv6 */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;

  ip.type = IPv4;
  /* Detecting IPv4 vs IPv6 */
  if (getaddrinfo(first_ip, NULL, &hints, &res) != 0) {
    /*Try IPv6 detection */
    ip.type = IPv6;
    hints.ai_family = AF_INET6;
    int ret;
    if ((ret = getaddrinfo(first_ip, NULL, &hints, &res)) != 0) {
      free(first_ip);
      return 0;
    }

    s_in6 = (struct sockaddr_in6 *)res->ai_addr;
    memcpy(&ip.start6, &s_in6->sin6_addr, sizeof(struct in6_addr));
    freeaddrinfo(res);
  } else {
    s_in = (struct sockaddr_in *)res->ai_addr;
    ip.start = s_in->sin_addr;
    freeaddrinfo(res);
  }

  if (ip.type == IPv4) {

    if (mask_val > 0) {
      mask_val--;
      mask_bit = 0x80000000;
      mask_bit >>= mask_val;
      mask_bit--;
    } else {
      mask_bit = 0xffffffff;
    }
    ip.stop.s_addr = htonl(ntohl(ip.start.s_addr) | mask_bit);
    ip.start.s_addr = htonl(ntohl(ip.start.s_addr) & (~mask_bit));

    if (ntop(&ip.start, host, sizeof(host)) != 0) {
      *start_ip = NULL;
      *stop_ip = NULL;
      return 0;
    }
    *start_ip = strdup(host);

    if (ntop(&ip.stop, host, sizeof(host)) != 0) {
      free(*start_ip);
      *start_ip = NULL;
      *stop_ip = NULL;
      return 0;
    }
    *stop_ip = strdup(host);
  } else {
    if (getaddrinfo(first_ip, NULL, &hints, &res) != 0) {
      return 0;
    }
    s_in6 = (struct sockaddr_in6 *)res->ai_addr;
    memcpy(&ip.stop6, &s_in6->sin6_addr, sizeof(struct in6_addr));
    freeaddrinfo(res);

    mask_byte = mask_val / 8;
    if (mask_byte < 16) {
      memset(&(ip.stop6.s6_addr[mask_byte + 1]), 0xFF, 15 - mask_byte);
      memset(&(ip.start6.s6_addr[mask_byte + 1]), 0x00, 15 - mask_byte);

      mask_bit = (0x100 >> mask_val % 8) - 1;
      ip.stop6.s6_addr[mask_byte] |= mask_bit;
      ip.start6.s6_addr[mask_byte] &= (~mask_bit);
    }

    if (ntop6(&ip.start6, host, sizeof(host)) != 0) {
      *start_ip = NULL;
      *stop_ip = NULL;
      return 0;
    }
    *start_ip = strdup(host);

    if (ntop6(&ip.stop6, host, sizeof(host)) != 0) {
      free(*start_ip);
      *start_ip = NULL;
      *stop_ip = NULL;
      return 0;
    }
    *stop_ip = strdup(host);
  }

  *ip_range = ip;

  free(first_ip);
  return 1;
}

#endif 