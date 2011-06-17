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

#include "ip.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <error.h>

// private functions




void ip_free(ip_t *ip)
{
    if( NULL != ip )
        free(ip);
}

ip_t *ip_alloc(const char *ip)
{
    ip_t *ret;

    if( NULL == ip )
        return NULL;

    if( (ret=calloc(sizeof(ip_t), 1)) == NULL )
        return NULL;

    if( ip_pton(ret, ip) != 1 )
    {
        ip_free(ret);
        return NULL;
    }

    return ret;
}

ip_t *ip_alloc_raw(const void *ip, int family)
{
    ip_t *ret;

    if( NULL == ip || (family != AF_INET && family != AF_INET6) )
        return NULL;

    if( (ret=calloc(sizeof(ip_t), 1)) == NULL )
        return NULL;

    if( ip_pton(ret, ip) != 0 )
    {
        ip_free(ret);
        return NULL;
    }

    ip_set_raw(ret, ip, family);

    return ret;
}

void ip_set_raw(ip_t *dst, const void *src, int family)
{
    dst->family = family;

    if ( family == AF_INET )
        memcpy(dst->ip8, src, sizeof(struct in_addr));
    else if ( family == AF_INET6 )
        memcpy(dst->ip8, src, sizeof(struct in6_addr));
    else
      printf("Unknown family\n");
}

int ip_pton(ip_t *ip, const char *name)
{
    const char *mask;
    char ip_buf[IP_ADDRMAX];
    int bits = -1;

    /* check for and extract a mask in CIDR short form only */
    if( (mask=strchr(name, (int)'/')) == NULL )
        mask = name + strlen(name);
    else
        bits = atoi(mask);

    strncpy(ip_buf, name, mask-name);

    struct addrinfo *ai;
    struct addrinfo hints;
    memset(&hints, '\0', sizeof(hints));

    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;

    int ret;
    if ( (ret=getaddrinfo(name, NULL, &hints, &ai)) != 0 )
    {
        // TODO: remove
        printf("Unable to get info for: %s\n", name);
        return ret;
    }

    ip->family = ai->ai_family;

    /* set up the bits if we haven't determined them yet */
    if ( bits < 0 )
        bits = (ai->ai_family == AF_INET) ? 32 : 128;

    ip->bits = (uint8_t)bits;

    if ( ai->ai_family == AF_INET )
        memcpy(ip->ip8, &((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr, ai->ai_addrlen);
    else if ( ai->ai_family == AF_INET6 )
        memcpy(ip->ip8, ((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr.s6_addr, ai->ai_addrlen);
    else
    {
        freeaddrinfo(ai);
        return -1; // TODO
    }

    // XXX: debug segfault
    //freeaddrinfo(ai);
    return 1;
}

const char *ip_ntop(const ip_t *ip, char *buf, int buflen, int flags)
{
    if (NULL == ip)
        return NULL;

    int ret;

    if ( ip->family == AF_INET )
    {
        if ( flags & IP_NUMERIC_HEX )
        {
            snprintf(buf, buflen, "%02x%02x%02x%02x", ip->ip8[0], ip->ip8[1], ip->ip8[2], ip->ip8[3]);
        }
        else if ( flags & IP_NUMERIC_DEC )
        {
            snprintf(buf, buflen, "%u", ntohl(ip->ip32[0]));
        }
        else
        {
            struct sockaddr_in sin;
            int lflags = ( flags & ( IP_NUMERIC | IP_NUMERIC_DEC | IP_NUMERIC_HEX ) ) ? NI_NUMERICHOST : 0;

            sin.sin_family = AF_INET;
            memcpy(&sin.sin_addr.s_addr, ip->ip8, sizeof(struct in_addr));
      
            if ( (ret=getnameinfo((struct sockaddr *)&sin, sizeof(sin), buf, buflen, NULL, 0, lflags)) != 0 )
                return NULL;
        }
    }
    else if ( ip->family == AF_INET6 )
    {
        if ( flags & IP_NUMERIC_HEX )
        {
            snprintf(buf, buflen, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    ip->ip8[0], ip->ip8[1], ip->ip8[2], ip->ip8[3],
                    ip->ip8[4], ip->ip8[5], ip->ip8[6], ip->ip8[7],
                    ip->ip8[8], ip->ip8[9], ip->ip8[10], ip->ip8[11],
                    ip->ip8[12], ip->ip8[13], ip->ip8[14], ip->ip8[15]);
        }
        else
        {
            struct sockaddr_in6 sin;
            int lflags = ( flags & ( IP_NUMERIC | IP_NUMERIC_DEC | IP_NUMERIC_HEX ) ) ? NI_NUMERICHOST : 0;

            sin.sin6_family = AF_INET6;
            memcpy(&sin.sin6_addr.s6_addr, ip->ip8, sizeof(struct in6_addr));

            if ( getnameinfo((struct sockaddr *)&sin, sizeof(sin), buf, IP_ADDRMAX, NULL, 0, lflags) != 0 )
                return NULL;
        }
    }
    else
        return NULL; //EAI_FAMILY; (errno)
    
    // XXX: hack
    // getnameinfo is returning addresses with wierd appendage in the form
    // of "%number" where the number if variable but consistent between
    // compiles
    //
    // eg.  fe80::202:b3ff:fe1e:8329%4212018 
    char *hack;
    if ( (hack = strchr(buf, '%')) )
        *hack = '\0';

    return buf;
}

const char *ip_ntops(const ip_t *ip, int flags)
{
    static char ip_buf[IP_ADDRMAX];

    if (NULL == ip)
      return NULL;

    return ip_ntop(ip, ip_buf, IP_ADDRMAX, flags);
}

int ip_isloopback(const ip_t *ip)
{
    // 127.0.0.0/8 is IPv4 loopback
    if( ip_family_get(ip) == AF_INET )
        return ( ip->ip8[0] == 0x7f );

    // first 64 bits should be 0
    if( ip->ip32[0] || ip->ip32[1] )
        return 0;

    // ::7f00:0/104 is ipv4 compatible ipv6 
    // ::1 is the IPv6 loopback
    if( ip->ip32[2] == 0 )
        return ( ( ip->ip8[12] == 0x7f ) ||
                 ( ntohl(ip->ip32[3]) == 0x1 ) );
    
    // ::ffff:127.0.0.0/104 is IPv4 loopback mapped over IPv6 
    if( ntohl(ip->ip32[2]) == 0xffff )
        return ( ip->ip8[12] == 0x7f );

    return 0;
}

int ip_ismapped(const ip_t *ip)
{
    if( ip_family_get(ip) == AF_INET )
        return 0;
       
    // first 80 bits should be 0
    // next 16 should be 1
    if( ip->ip32[0] ||
        ip->ip32[1] ||
        ( ntohl(ip->ip32[2]) != 0xffff && 
          ip->ip32[2] != 0 ) )
        return 0;

    return 1;
}


void ip_obfuscate(ip_t *ob, const ip_t *ip)
{
    unsigned int *ob_p, *ip_p;
    int index, i;
    unsigned int mask = 0;

    if(!ob || !ip)
        return;
/*
    ob_p = ob->ip32;
    ip_p = ip->ip32;

    // Build the netmask by converting "val" into 
    // the corresponding number of bits that are set
    index = (int)ceil(ob->bits / 32.0) - 1;

    for(i = 0; i < 32- (ob->bits - (index * 32)); i++)
        mask = (mask<<1) + 1;

    ip_p[index] = htonl((ntohl(ip_p[index]) & mask));

    // 0 off the start of the IP
    while ( index > 0 ) ip_p[--index] = 0;

    // OR remaining pieces
    ip_p[0] |= ob_p[0];
    ip_p[1] |= ob_p[1];
    ip_p[2] |= ob_p[2];
    ip_p[3] |= ob_p[3];
*/
}


