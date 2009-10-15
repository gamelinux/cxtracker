/*
** This file is a part of cxtracker.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include "cxtracker.h"

/*  G L O B A L E S  **********************************************************/
u_int64_t    cxtrackerid;
time_t       timecnt,tstamp;
pcap_t       *handle;
connection   *bucket[BUCKET_SIZE];
connection   *cxtbuffer = NULL;
static char  src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
static char  *dev,*dpath;
static int   verbose, inpacket, gameover, use_syslog;

/*  I N T E R N A L   P R O T O T Y P E S  ************************************/
void move_connection (connection*, connection**);
void cx_track4(uint64_t ip_src,uint16_t src_port,uint64_t ip_dst,uint16_t dst_port,uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af);
void cx_track6(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af);
void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet);
void end_sessions();
void cxtbuffer_write();

void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet) {
//   if ( gameover == 1 ) { game_over(); }
   inpacket = 1;
   tstamp = time(NULL);
   u_short p_bytes;

   /* printf("[*] Got network packet...\n"); */
   ether_header *eth_hdr;
   eth_hdr = (ether_header *) (packet);
   u_short eth_type;
   eth_type = ntohs(eth_hdr->eth_ip_type);
   int eth_header_len;
   eth_header_len = ETHERNET_HEADER_LEN;

   if ( eth_type == ETHERNET_TYPE_8021Q ) {
      /* printf("[*] ETHERNET TYPE 8021Q\n"); */
      eth_type = ntohs(eth_hdr->eth_8_ip_type);
      eth_header_len +=4;
   }

   else if ( eth_type == (ETHERNET_TYPE_802Q1MT|ETHERNET_TYPE_802Q1MT2|ETHERNET_TYPE_802Q1MT3|ETHERNET_TYPE_8021AD) ) {
      /* printf("[*] ETHERNET TYPE 802Q1MT\n"); */
      eth_type = ntohs(eth_hdr->eth_82_ip_type);
      eth_header_len +=8;
   }

   if ( eth_type == ETHERNET_TYPE_IP ) {
      /* printf("[*] Got IPv4 Packet...\n"); */
      ip4_header *ip4;
      ip4 = (ip4_header *) (packet + eth_header_len);
      p_bytes = (ip4->ip_len - (IP_HL(ip4)*4));

      if ( ip4->ip_p == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE TCP:\n"); */
         cx_track4(ip4->ip_src, tcph->src_port, ip4->ip_dst, tcph->dst_port, ip4->ip_p, p_bytes, tcph->t_flags, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE UDP:\n"); */
         cx_track4(ip4->ip_src, udph->src_port, ip4->ip_dst, udph->dst_port, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_ICMP) {
         icmp_header *icmph;
         icmph = (icmp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IP PROTOCOL TYPE ICMP\n"); */
         cx_track4(ip4->ip_src, icmph->s_icmp_id, ip4->ip_dst, icmph->s_icmp_id, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else {
         /* printf("[*] IPv4 PROTOCOL TYPE OTHER: %d\n",ip4->ip_p); */
         cx_track4(ip4->ip_src, ip4->ip_p, ip4->ip_dst, ip4->ip_p, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
   }
   inpacket = 0;
   return;
}

void cx_track4(uint64_t ip_src,uint16_t src_port,uint64_t ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *s_cxt = NULL;
   connection *head = NULL;
   uint64_t s_hash;

   s_hash = (( ip_src + ip_dst )) % BUCKET_SIZE;

   s_cxt = bucket[s_hash];
   head = s_cxt;

   while ( s_cxt != NULL ) {
      if ( s_cxt->s_ip4 == ip_src && s_cxt->d_ip4 == ip_dst && s_cxt->s_port == src_port && s_cxt->d_port == dst_port ) {
         s_cxt->s_tcpFlags    |= tcpflags;
         s_cxt->s_total_bytes += p_bytes;
         s_cxt->s_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         return;
      }
      else if ( s_cxt->s_ip4 == ip_dst && s_cxt->d_ip4 == ip_src && s_cxt->d_port == src_port && s_cxt->s_port == dst_port ) {
         s_cxt->d_tcpFlags    |= tcpflags;
         s_cxt->d_total_bytes += p_bytes;
         s_cxt->d_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         return;
      }
      if (s_cxt == s_cxt->next ) {
         s_cxt->next = NULL;
      }
      s_cxt = s_cxt->next;
   }

   if ( s_cxt == NULL ) {
      cxtrackerid += 1;
      s_cxt = (connection*) calloc(1, sizeof(connection));
      if (head != NULL && s_cxt != head) {
         head->prev = s_cxt;
      }
      /* printf("[*] New connection...\n"); */
      s_cxt->cxid           = cxtrackerid;
      s_cxt->ipversion      = af;
      s_cxt->s_tcpFlags     = tcpflags;
      s_cxt->d_tcpFlags     = 0x00;
      s_cxt->s_total_bytes  = p_bytes;
      s_cxt->s_total_pkts   = 1;
      s_cxt->d_total_bytes  = 0;
      s_cxt->d_total_pkts   = 0;
      s_cxt->start_time     = tstamp;
      s_cxt->last_pkt_time  = tstamp;
      s_cxt->s_ip4          = ip_src;
      /* s_cxt->s_ip6          = 0; */
      s_cxt->s_port         = src_port;
      s_cxt->d_ip4          = ip_dst;
      /* s_cxt->d_ip6          = 0; */
      s_cxt->d_port         = dst_port;
      s_cxt->proto          = ip_proto;
      s_cxt->next           = head;
      s_cxt->prev           = NULL;

      /* New connections are pushed on to the head of bucket[s_hash] */
      bucket[s_hash] = s_cxt;

      if ( ((tstamp - timecnt) > TIMEOUT) ) {
         timecnt = time(NULL);
         end_sessions();
         //printf("Total sessions... %lu\n",cxtrackerid);
      }
      return;
   }
   /* Should never be here! */
   return;
}

void end_sessions() {

   connection *cxt;
   time_t check_time;
   check_time = time(NULL);
   int cxkey, xpir;
   uint32_t curcxt  = 0;
   uint32_t expired = 0;
   //cxtbuffer = NULL;

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cxt = bucket[cxkey];
      xpir = 0;
      while ( cxt != NULL ) {
         curcxt++;
         if ( (check_time - cxt->last_pkt_time) > 30 ) {
            xpir = 1;
         }
         if ( xpir == 1 ) {
            expired++;
            xpir = 0;
            connection *tmp = cxt;
            if (cxt == cxt->next) {
               cxt->next == NULL;
            }
            cxt = cxt->next;
            move_connection(tmp, &bucket[cxkey]);
         }else{
            cxt = cxt->next;
         }
      }
   }
   printf("Expired: %u of %u total connections:\n",expired,curcxt);
   //cxtbuffer_write();
   printf("End.\n");
}

void move_connection (connection* cxt, connection **bucket_ptr ){
   /* remove cxt from bucket */
   connection *prev = cxt->prev; /* OLDER connections */
   connection *next = cxt->next; /* NEWER connections */

   /* if next NULL, NEWEST. if PREV NULL, oldest. */
   if(prev != NULL && next != *bucket_ptr) {
      prev->next = next;
   }
   if(next != NULL && prev != *bucket_ptr){
      next->prev = prev;
   }

   if(next == NULL && prev == NULL) {
      /* bucket should now point to NULL */
      *bucket_ptr = NULL;
   }
   /* add cxt to expired list cxtbuffer */
   cxt->next = cxtbuffer;
   cxt->prev = NULL;
   cxtbuffer = cxt;
}

void cxtbuffer_write () {

   if ( cxtbuffer == NULL ) { return; }
   connection *next, *debug;
   next = NULL;
   debug = NULL;

   while ( cxtbuffer != NULL ) {
      next = NULL;
      debug = cxtbuffer;
      if(cxtbuffer == cxtbuffer->next){
         cxtbuffer->next = NULL;
      }
      next = cxtbuffer->next;
      if (cxtbuffer != NULL) {
         free(cxtbuffer);
      }
      cxtbuffer = next;
   }
/* just write something*/
printf("Done...\n");
}

int main(int argc, char *argv[]) {

   int ch, fromfile, setfilter, version, drop_privs_flag, daemon_flag = 0;
   int use_syslog = 0;
   struct in_addr addr;
   struct bpf_program cfilter;
   char *bpff, errbuf[PCAP_ERRBUF_SIZE], *user_filter;
   char *net_ip_string;
   bpf_u_int32 net_mask;
   dev = "eth0";
   bpff = "";
   dpath = "/tmp";
   cxtbuffer = NULL;
   cxtrackerid  = 999999999;
   inpacket = gameover = 0;
   timecnt = time(NULL);

   if (getuid()) {
      printf("[*] You must be root..\n");
      return (1);
   }
   printf("[*] Running cxtracker...\n");

//   signal(SIGTERM, game_over);
//   signal(SIGINT,  game_over);
//   signal(SIGQUIT, game_over);
//   signal(SIGALRM, end_sessions);
   /* alarm(TIMEOUT); */

   while ((ch = getopt(argc, argv, "b:d:D:g:i:p:P:u:v")) != -1)
   switch (ch) {
      case 'i':
         dev = strdup(optarg);
         break;
      case 'b':
         bpff = strdup(optarg);
         break;
      case 'v':
         verbose = 1;
         break;
      case 'd':
         dpath = strdup(optarg);
         break;
      case 'D':
         daemon_flag = 1;
         break;
      default:
         exit(1);
         break;
   }

   errbuf[0] = '\0';
   /* look up an availible device if non specified */
   if (dev == 0x0) dev = pcap_lookupdev(errbuf);
   printf("[*] Device: %s\n", dev);

   if ((handle = pcap_open_live(dev, 65535, 1, 500, errbuf)) == NULL) {
      printf("[*] Error pcap_open_live: %s \n", errbuf);
      exit(1);
   }
   else if ((pcap_compile(handle, &cfilter, bpff, 1 ,net_mask)) == -1) {
      printf("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(handle));
      exit(1);
   }

   pcap_setfilter(handle, &cfilter);

   /* B0rk if we see an error... */
   if (strlen(errbuf) > 0) {
      printf("[*] Error errbuf: %s \n", errbuf);
      exit(1);
   }

   printf("[*] Sniffing...\n\n");
   pcap_loop(handle,-1,got_packet,NULL);

   pcap_close(handle);
   return(0);
}

