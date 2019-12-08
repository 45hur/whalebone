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

/**
 * @file ipranger.h
 * @author Michal Karm Babacek <karm@email.cz>
 * @brief ipranger API
 *
 * IPRanger enables you to associate byte arrays with particular CIDR subnets,
 * IP ranges.
 */

#include "util.h"
#include "thread_shared.h"

#ifndef NOKRES

#include <lmdb.h>

#ifndef IPRANGER
#define IPRANGER

/**
 * @defgroup IPRanger IPRanger library
 */

/**
 * @defgroup DB_Constants DB specific constants
 *
 * @ingroup IPRanger
 * @{
 */
/** Maximum size of the DB in multiples of page size in bytes
 * e.g. on my system: getconf PAGESIZE is 4096 so setting 1048576 here gives 4GB
 * max LMDB DB size.*/
#define IPRANGER_MAX_MAP_SIZE_IN_PAGES 1048576
/** DB name used to store IPv6 ranges */
#define IPRANGER_IPv6_DB_NAME "IPv6"
/** DB name used to store IPv4 ranges */
#define IPRANGER_IPv4_DB_NAME "IPv4"
/** DB name used to store IPv6 masks used */
#define IPRANGER_IPv6_MASKS_DB_NAME "IPv6_masks"
/** DB name used to store IPv4 masks used */
#define IPRANGER_IPv4_MASKS_DB_NAME "IPv4_masks"
/** Max masks recorded - in reality probably just 33, theoretically 128 **/
#define IPRANGER_MAX_MASKS 128
/** Identity string returned if no subnet (range) match is found for the given
 * address. */
#define IPRANGER_NO_MATCH_STR "NULL"
/** Identity is the string we associate with CIDRs, i.e. it is what you get when
 * you give an IP address to one of the get_identity* functions. Note it must
 * not be a smaller number than what IPRANGER_NO_MATCH_STR fits in. */
#define IPRANGER_MAX_IDENTITY_LENGTH 32
/** @} */

/**
 * @defgroup Return_codes Return codes
 * @ingroup IPRanger
 * @{
 */
/** Type for specifying an error or status code. */
typedef int iprg_stat_t;
/** Successful operation */
#define RC_SUCCESS 1
/** Failed operation */
#define RC_FAILURE 0
/** @} */

/**
 * @defgroup IPRanger_API IPRanger API
 *
 * Functions to store mapping between CIDR and Identity and to look up in this
 * mapping with IP address.
 *
 * In attempt to avoid data corruption and operation on inaccurate data, the
 * library could terminate the program with abort(). If you don't like the
 * behaviour, open a GitHub issue, please.
 * @ingroup IPRanger
 * @{
 */
/**
 * @brief Initializes DB engine. Must be called before any DB operations.
 * @return RC_SUCCESS or RC_FAILURE
 */
extern iprg_stat_t iprg_init_DB_env(const char *path_to_db_dir, bool read_only);

/**
 * @brief Insert Identity for a CIDR defined subnet.
 *
 * It finds the LAST address of the given CIDR and stores it in the DB
 * as the key for the given Identity value. The mask used is also stored
 * for lookup purposes.
 *
 * @param cidr pointer to up to INET6_ADDRSTRLEN (46) chars long array, e.g.
 * 3eed:ec3e:33dd:745c::/64 Note the library is pretty unforgiving about
 * CIDR format. Mask is mandatory.
 * @param identity pointer to up to 32 chars long array, e.g. XXX-1
 *
 * @return RC_SUCCESS or RC_FAILURE
 */
extern iprg_stat_t iprg_insert_cidr_identity_pair(const char *cidr,
                                                  const char *identity);
/**
 * @brief Insert Identities for CIDR defined subnets.
 *
 * @see iprg_insert_cidr_identity_pair
 *
 * @return RC_SUCCESS if all inserts succeeded or RC_FAILURE if any of inserts
 * failed
 */
extern iprg_stat_t iprg_insert_cidr_identity_pairs(const char *cidrs[],
                                                   const char *identities[],
                                                   int length);

/**
 * @brief Get Identity for a given string Address
 *
 * The address is combined with each mask previously used in @see
 * iprg_insert_cidr_identity_pair and the LAST address of thus created subnet is
 * used for lookup. Effectively you get the Identity corresponding to the subnet
 * this address belongs to.
 *
 * @param address pointer to up to 40 chars long array, e.g.
 * 8078:5a6c:9a02:43cb:ffff:ffff:ffff:ffff
 * Note the library accepts also compressed format, e.g.
 * f2f5:3aa1:d14e:494e::20c8
 * @param identity pointer to 32 chars long array where the found identity will
 * be written. Note that if no match is found, special string value is written,
 * @see IPRANGER_NO_MATCH_STR
 *
 * @return RC_SUCCESS or RC_FAILURE. If RC_FAILURE is returned, the content of
 * identity is not defined and should be discarded.
 */
extern iprg_stat_t iprg_get_identity_str(const char *address, char *identity);

/**
 * @brief Get Identities for given string Addresses
 *
 * @see iprg_get_identity_str
 *
 * @return RC_SUCCESS if all get ops succeeded or RC_FAILURE if any of get
 * ops failed
 */
extern iprg_stat_t iprg_get_identity_strs(const char *addresses[],
                                          char *identities[], int length);

/**
 * @brief Get Identity for a given ip_addr Address
 *
 * @param address IPv4 or IPv6 address
 * @param identity @see iprg_get_identity_str
 *
 * @return RC_SUCCESS or RC_FAILURE
 */
extern iprg_stat_t iprg_get_identity_ip_addr(struct ip_addr *address,
                                             char *identity);
/**
 * @brief Get Identities for a given ip_addr Addresses
 *
 * @param addresses IPv4 or IPv6 addresses
 * @param identities @see iprg_get_identity_str
 *
 * @return RC_SUCCESS or RC_FAILURE
 */
extern iprg_stat_t iprg_get_identity_ip_addrs(struct ip_addr *addresses[],
                                              char *identities[], int length);

/**
 * @brief No idea what Ashur means with this :-)
 *
 * @param address pointer to up to 40 chars long array, e.g.
 * 8078:5a6c:9a02:43cb:ffff:ffff:ffff:ffff Note the library accepts also
 * compressed format, e.g. f2f5:3aa1:d14e:494e::20c8
 * @param identity multiple identities to....what? Check whther they belong ot
 * he IP...?
 *
 * @return RC_SUCCESS or RC_FAILURE
 */
extern iprg_stat_t iprg_check_ip_range(char *address, int *identity, ...);

/**
 * @brief Should be called after all DB operations.
 */
extern void iprg_close_DB_env();

/**
 * @brief Dumps *whole* DB to stdout with printf record by record.
 *
 * Potentially expensive.
 */
extern void iprg_printf_db_dump();
void ipv6_db_dump();
void ipv4_db_dump();
/** @} */

#endif

#endif 