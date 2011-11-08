/*
** Copyright (C) 2011, Ian Firns <firnsy@securixlive.com>
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#ifndef __IP_H__
#define __IP_H__

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>

#ifdef __FreeBSD__
#include <sys/socket.h>
#endif /* __FreeBSD__ */

#define IP_ADDRMAX       NI_MAXHOST

// TODO: raise these values to deconflict with the NI_* flags
#define IP_FQDN           0x00
#define IP_NUMERIC        0x01
#define IP_NUMERIC_DEC    0x02
#define IP_NUMERIC_HEX    0x04
#define IP_OBFUSCATE      0x20

#define IP_SET_POINTER_COPY   0x01
#define IP_SET_MEMCPY         0x02
#define IP_SET_OBFUSCATE      0x04  // implies memcpy

typedef struct _ip_addr_s {
    union
    {
        uint8_t  u_addr8[16];
        uint16_t u_addr16[8];
        uint32_t u_addr32[4];
        uint64_t u_addr64[2];
    } ip;
    #define ip8  ip.u_addr8
    #define ip16 ip.u_addr16
    #define ip32 ip.u_addr32
    #define ip64 ip.u_addr64
} ip_addr_t;

typedef struct _ip_s {
    int16_t   family;              // IP family
    uint8_t   bits;                // bits used for masking
    ip_addr_t *addr;
} ip_t;


typedef struct _ip_config_s {
    void    (*set)(ip_t*, const void *, int);
} ip_config_t;


//
// MEMBER ACCESS

static inline int16_t ip_family_get(const ip_t *ip)
{
    return ip->family;
}

static inline uint8_t ip_bits_get(const ip_t *ip)
{
    return ip->bits;
}

static inline void ip_bits_set(ip_t *ip, uint8_t bits)
{
    if ( NULL == ip )
        return;

    if (bits > 128)
        return;

    ip->bits = bits;
}

//
// MANAGER FUNCTIONS
int ip_init(ip_config_t *config, int mode);

/**
 * \brief Set IP address based on existing IP structure
 * \param Structure for writing resulting IP
 * \param Structure for sourcing IP from
 */
void ip_set(ip_config_t *config, ip_t *dst, const void *src, int family);

//
// ALLOCATORS AND SETTERS

/**
 * \brief Allocate IP address
 * \param character array describing the IP literally or numerically
 * \return Structure containing numeric representation of IP
 */
ip_t *ip_alloc(const char *ip);

/**
 * \brief Allocate IP address from raw numeric representation
 * \param Array of integers describing the IP numerically in network byte order
 * \return Structure containing numeric representation of IP
 */
ip_t *ip_alloc_raw(const void *ip, int family);

/**
 * \brief Allocate IP address
 * \param Pre-allocated structure created with ip_alloc() or similar
 */
void ip_free(ip_t *);



//
// COMPARISONS AND CHECKS

/**
 * \brief Checks if the IP address is set
 * \param structure containing numeric representation of IP
 * \return Non-zero if IP is set. Zero (0) otherwise.
 *
 * An IP is considered set when all appropriate values for it's family have
 * been set to a non-zero value. The following cases are conisdered zero 
 * addresses:
 *   * IPV4 - 0.0.0.0
 *   * IPV6 - 0000:0000:0000:0000:0000:0000:0000:0000:0000, ::, or similar.
 */
static inline int ip_isset(const ip_t *ip)
{
  return ( ip && ip->addr &&
           (
             (
               ( ip->addr->ip32[0] ) || (
                 ( ip->family == AF_INET6 ) &&
                 ( ip->addr->ip32[1] ||
                   ip->addr->ip32[2] ||
                   ip->addr->ip32[3] ||
                   ip->bits != 128 )
               )
             ) || (
               ( ip->family == AF_INET ) &&
               ( ip->bits != 32 )
             )
           )
         );
}


/**
 * \brief Checks if the IP describes the loopback address
 * \param structure containing numeric representation of IP
 * \return Non-zero if IP is a loopback address. Zero (0) otherwise
 *
 * An IP is considered set when all appropriate values for it's family have
 * been set to a non-zero value. The following cases are conisdered zero 
 * addresses:
 *   * IPV4 - 0.0.0.0
 *   * IPV6 - 0000:0000:0000:0000:0000:0000:0000:0000:0000, ::, or similar.
 */
int ip_isloopback(const ip_t *ip);

/**
 * \brief Checks if the IP describes an IPv4 mapped to IPv6 address
 * \param structure containing numeric representation of IP
 * \return Non-zero if IP is a mapped address. Zero (0) otherwise
 *
 * An IPv4 mapped to IPv6 address has the first 80 bits set to zero (0),
 * followed by 16 bits set to one (1). The final 32-bits represent the
 * IPv4 address. A literal example of an IPv4 mapped IPv6 address has looks
 * like:
 *   * 0000:0000:0000:0000:0000::ffff::192.168.10.44
 */
int ip_ismapped(const ip_t *);

static inline int _ip_ip4_cmp(uint32_t ip1, uint32_t ip2)
{
    uint32_t ip1_h = ntohl(ip1);
    uint32_t ip2_h = ntohl(ip2);

    if ( ip1_h < ip2_h )
        return -1;

    if ( ip1_h > ip2_h )
        return 1;

    return 0;
}

static inline int _ip_ip6_cmp(const ip_t *ip1, const ip_t *ip2)
{
    int ret;

    if ( (ret = _ip_ip4_cmp(ip1->addr->ip32[0], ip2->addr->ip32[0])) )
        return ret;

    if ( (ret = _ip_ip4_cmp(ip1->addr->ip32[1], ip2->addr->ip32[1])) )
        return ret;

    if ( (ret = _ip_ip4_cmp(ip1->addr->ip32[2], ip2->addr->ip32[2])) )
        return ret;

    if ( (ret = _ip_ip4_cmp(ip1->addr->ip32[3], ip2->addr->ip32[3])) )
        return ret;

    return ret;
}

static inline int ip_cmp(const ip_t *ip1, const ip_t *ip2)
{
  int ip1_set = ip_isset(ip1);
  int ip2_set = ip_isset(ip2);
  int ip1_family = ip_family_get(ip1);
  int ip2_family = ip_family_get(ip2);

  if ( ! (ip1_set && ip2_set) )
      return 0;
  else if ( ! ip2_set )
      return 1;
  else if ( ! ip1_set )
      return -1;

  if ( (ip1_family == AF_INET) && (ip2_family == AF_INET) )
  {
      return _ip_ip4_cmp(ip1->addr->ip32[0], ip2->addr->ip32[0]);
  }
  else if ( (ip1_family == AF_INET6) && (ip2_family == AF_INET6) )
  {
      return _ip_ip6_cmp(ip1, ip2);
  }
  else if (ip2_family == AF_INET6)
  {
      return -1;
  }

  return 1;
}

/**
 * \brief Checks if an IP is contained in a network
 * \param IP network to search in
 * \param IP to search for
 * \return Non-zero if IP is the loopback address. Zero (0) otherwise
 */
static inline int ip_contains(const ip_t *haystack, const ip_t *needle)
{
    uint32_t remainder;
    int i;
    int bits = ip_bits_get(haystack);
    int words = bits / 32;
    bits = 32 - (bits % 32);

    for (i=0; i<words; i++)
        if ( haystack->addr->ip32[i] != needle->addr->ip32[i] )
            return 0;

    if ( bits == 32 )
        return 1;

    remainder = ntohl(needle->addr->ip32[i]);
    remainder >>= bits;
    remainder <<= bits;

    return (ntohl(haystack->addr->ip32[i]) == remainder) ? 1 : 0;
}

/**
 * \brief Checks if the IP describes the loopback address
 * \param structure containing numeric representation of IP
 * \return Non-zero if IP is the loopback address. Zero (0) otherwise
 *
 * An IP is considered set when all appropriate values for it's family have
 * been set to a non-zero value. The following cases are conisdered zero 
 * addresses:
 *   * IPV4 - 0.0.0.0
 *   * IPV6 - 0000:0000:0000:0000:0000:0000:0000:0000:0000, ::, or similar.
 */
static inline uint64_t ip_hash(const ip_t *ip1, const ip_t *ip2, uint64_t size)
{
    if ( ip_family_get(ip1) == AF_INET6 )
    {
        return ( ip1->addr->ip32[0] + ip1->addr->ip32[1] +
                 ip1->addr->ip32[2] + ip1->addr->ip32[3] +
                 ip2->addr->ip32[0] + ip2->addr->ip32[1] +
                 ip2->addr->ip32[2] + ip2->addr->ip32[3] ) % size;
    }

    return ( ip1->addr->ip32[0] + ip2->addr->ip32[0] ) % size;
}

//
// UTILITIES

/**
 * \brief Obfuscate an IP address
 * \param Reference to obfuscated IP
 * \param Reference to source IP
 *
 * Assists in avoiding disclosure of real network IP addresses by obfuscating
 * for the purpose of public demonstration. The obfuscated IP's are not
 * guaranteed to conform to IEEE standards.
 */
void ip_obfuscate(ip_t *ob, const ip_t *ip);

/**
 * \brief Converts IP from presentation to numeric format.
 * \param IP storage buffer
 * \param Buffer containing IP in presentation format
 * \return Non-zero if IP is the loopback address. Zero (0) otherwise
 */
int ip_pton(ip_t *ip, const char *name);

/**
 * \brief Converts from numeric to presentation format using a supplied buffer
 * \param IP to be converted
 * \param Buffer to store presentation format into
 * \param Length of buffer
 * \param Conversion flags (see below)
 * \return Non-zero if IP is the loopback address. Zero (0) otherwise
 */
int ip_ntop(const ip_t *ip, char *buf, int buflen, int flags);

/**
 * \brief Converts from numeric to presentation format using a static buffer
 * \param IP to be converted
 * \param Conversion flags (see below)
 * \return Reference to static buffer holding literal representation of IP
 *
 * Conversion flags:
 *
 */
const char *ip_ntops(const ip_t *ip, int flags);

#endif /* __IP_H__ */
