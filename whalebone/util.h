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

#ifndef IPRANGER_UTIL
#define IPRANGER_UTIL
#define _POSIX_C_SOURCE 200809L

#ifndef NOKRES

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define DEBUG 1

#define T(test, ...)                                                           \
  ((test) ? (void)0                                                            \
          : ((void)fprintf(stderr, "%s:%d: ", __FILE__, __LINE__),             \
             (void)fprintf(stderr, ##__VA_ARGS__), abort()))

#define E(expr) CHECK((rc = (expr)) == MDB_SUCCESS, #expr)
#define RES(err, expr) ((rc = expr) == (err) || (CHECK(!rc, #expr), 0))
#define CHECK(test, msg)                                                       \
  ((test) ? (void)0                                                            \
          : ((void)fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, msg, \
                           mdb_strerror(rc)),                                  \
             abort()))
#define DIE(X, ...)                                                            \
  fprintf(stderr, "ERROR %s:%d: " X "\n", __FILE__, __LINE__, ##__VA_ARGS__);  \
  exit(EXIT_FAILURE);
#define ERR_MSG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

enum network_type { IPv4, IPv6 };

typedef struct ip_range {
  enum network_type type;
  struct in_addr start;
  struct in_addr stop;
  struct in6_addr start6;
  struct in6_addr stop6;
} ip_range_t;

typedef uint32_t in_addr_t;

int cidr_to_ip(const char *cidr, char **start_ip, char **stop_ip, unsigned char *mymask,
               ip_range_t *ip_range, unsigned char default_mask);

// Debug stuff
void ipv6_to_str(const struct in6_addr *addr);
void ipv4_to_str(const struct in_addr *addr);

#endif

#endif
