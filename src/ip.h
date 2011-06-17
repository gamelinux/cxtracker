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

#define IP_ADDRMAX       NI_MAXHOST

#define IP_NUMERIC       0x01
#define IP_NUMERIC_DEC   0x02
#define IP_NUMERIC_HEX   0x04

#define IP_OBFUSCATE     0x20

typedef struct _ip_s {
    int16_t family;                 // IP family
    uint8_t bits;                   // bits used for masking

    union
    {
        uint8_t  u_addr8[16];
        uint16_t u_addr16[8];
        uint32_t u_addr32[4];
    } ip;
    #define ip8  ip.u_addr8
    #define ip16 ip.u_addr16
    #define ip32 ip.u_addr32
} ip_t;


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
 * \brief Set IP address from raw byte representation
 * \param Structure for writing resulting IP
 * \param Array of integers describing the IP numerically in network byte order
 * \param The IP family type (eg. AF_INET, AF_INET6)
 */
void ip_set_raw(ip_t *dst, const void *src, int family);

/**
 * \brief Allocate IP address
 * \param Pre-allocated structure created with ip_alloc() or similar
 */
void ip_free(ip_t *);

/**
 * \brief Set IP address from raw byte representation
 * \param Structure for writing resulting IP
 * \param Structure for sourcing IP from
 */
void ip_set(ip_t *dst, const ip_t *src);


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
  return ( ip &&
           (
             (
               ( ip->ip32[0] ) || 
               ( ip->family == AF_INET6 ) &&
               ( ip->ip32[1] || 
                 ip->ip32[2] || 
                 ip->ip32[3] || 
                 ip->bits != 128 )
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
 * \return Non-zero if IP is the loopback address. Zero (0) otherwise
 *
 * An IP is considered set when all appropriate values for it's family have
 * been set to a non-zero value. The following cases are conisdered zero 
 * addresses:
 *   * IPV4 - 0.0.0.0
 *   * IPV6 - 0000:0000:0000:0000:0000:0000:0000:0000:0000, ::, or similar.
 */
int ip_isloopback(const ip_t *ip);

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

    if ( (ret = _ip_ip4_cmp(ip1->ip32[0], ip2->ip32[0])) )
        return ret;

    if ( (ret = _ip_ip4_cmp(ip1->ip32[1], ip2->ip32[1])) )
        return ret;

    if ( (ret = _ip_ip4_cmp(ip1->ip32[2], ip2->ip32[2])) )
        return ret;

    if ( (ret = _ip_ip4_cmp(ip1->ip32[3], ip2->ip32[3])) )
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
      return _ip_ip4_cmp(ip1->ip32[0], ip2->ip32[0]);
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

static inline int ip_contains(const ip_t *ip1, const ip_t *ip2)
{
    uint32_t ip;
    int i;
    int bits = ip_bits_get(ip1);
    int words = bits / 32;
    bits = 32 - (bits % 32);

    for (i=0; i<words; i++)
        if ( ip1->ip32[i] != ip2->ip32[i] )
            return 0;

    if ( bits == 32 )
        return 1;

    ip = ntohl(ip2->ip32[i]);
    ip >>= bits;
    ip <<= bits;

    return ntohl(ip1->ip32[i]) == ip;
}



//
// UTILITIES

/**
 * \brief Obfuscate an IP address
 * \param reference to obfuscated IP structure
 * \param reference to source IP structure
 *
 * Assists in avoiding disclosure of real network IP addresses by obfuscating
 * for the purpose of public demonstration. The obfuscated IP's are not
 * guaranteed to conform to IEEE standards.
 */
void ip_obfuscate(ip_t *ob, const ip_t *ip);

int ip_pton(ip_t *ip, const char *name);

const char *ip_ntop(const ip_t *ip, char *buf, int buflen, int flags);
const char *ip_ntops(const ip_t *ip, int flags);

#endif /* __IP_H__ */
