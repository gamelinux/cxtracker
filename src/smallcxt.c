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
#include <signal.h>
#include <netinet/in.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include "cxtracker.h"
#include <assert.h>

/*  G L O B A L E S  **********************************************************/
u_int64_t    cxtrackerid;
time_t       timecnt,tstamp;
pcap_t       *handle;
connection   *bucket[BUCKET_SIZE], *cxtfree;
connection   *cxtbuffer = NULL;
static char  src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
static char  *dev,*dpath;
static int   verbose, inpacket, intr_flag, gameover, use_syslog;
static uint64_t   freecnt, buffercnt, cxtcnt;

/*  I N T E R N A L   P R O T O T Y P E S  ************************************/
void move_connection (connection*, connection**, connection**);
void clear_connection (connection*);
void cx_track(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af);
void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet);
void end_sessions();
void cxtbuffer_write();
void game_over();
void check_interupt();
void dump_active();
void set_end_sessions();


void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet) {
   if ( intr_flag != 0 ) { check_interupt(); }
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
      struct in6_addr ip_src, ip_dst;
      ip_src.s6_addr32[0] = ip4->ip_src;
      ip_dst.s6_addr32[0] = ip4->ip_dst;


      if ( ip4->ip_p == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE TCP:\n"); */
         cx_track(ip_src, tcph->src_port, ip_dst, tcph->dst_port, ip4->ip_p, p_bytes, tcph->t_flags, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE UDP:\n"); */
         cx_track(ip_src, udph->src_port, ip_dst, udph->dst_port, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_ICMP) {
         icmp_header *icmph;
         icmph = (icmp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IP PROTOCOL TYPE ICMP\n"); */
         cx_track(ip_src, icmph->s_icmp_id, ip_dst, icmph->s_icmp_id, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else {
         /* printf("[*] IPv4 PROTOCOL TYPE OTHER: %d\n",ip4->ip_p); */
         cx_track(ip_src, ip4->ip_p, ip_dst, ip4->ip_p, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
   }
   inpacket = 0;
   return;
}

void cx_track(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *cxt = NULL;
   connection *head = NULL;
   uint64_t hash;

   if (af == AF_INET) {
      hash = (( ip_src.s6_addr32[0] + ip_dst.s6_addr32[0] )) % BUCKET_SIZE;
   } else {
   /* Do we need an if? */
   /* if (af == AF_INET6) { */
      hash = ((  ip_src.s6_addr32[0] + ip_src.s6_addr32[1] + ip_src.s6_addr32[2] + ip_src.s6_addr32[3]
               + ip_dst.s6_addr32[0] + ip_dst.s6_addr32[1] + ip_dst.s6_addr32[2] + ip_dst.s6_addr32[3]
             )) % BUCKET_SIZE;
   }

   cxt = bucket[hash];
   head = cxt;

   while ( cxt != NULL ) {
      if (af == AF_INET) {
         if ( cxt->s_ip.s6_addr32[0] == ip_src.s6_addr32[0] && cxt->d_ip.s6_addr32[0] == ip_dst.s6_addr32[0]
              && cxt->s_port == src_port && cxt->d_port == dst_port ) {
            cxt->s_tcpFlags    |= tcpflags;
            cxt->s_total_bytes += p_bytes;
            cxt->s_total_pkts  += 1;
            cxt->last_pkt_time  = tstamp;
            return;
         }
         else if ( memcmp(&cxt->s_ip,&ip_src,4) ) {
            cxt->d_tcpFlags    |= tcpflags;
            cxt->d_total_bytes += p_bytes;
            cxt->d_total_pkts  += 1;
            cxt->last_pkt_time  = tstamp;
            return;
         }
      } else {
      /* Do we need an if ? */
      /* if (af == AF_INET6) { */
            if ( memcmp(&cxt->s_ip,&ip_src,16) && memcmp(&cxt->d_ip,&ip_dst,16) &&
                 cxt->s_port == src_port && cxt->d_port == dst_port ) {
               cxt->s_tcpFlags    |= tcpflags;
               cxt->s_total_bytes += p_bytes;
               cxt->s_total_pkts  += 1;
               cxt->last_pkt_time  = tstamp;
               return;
            } else
            if ( memcmp(&cxt->s_ip,&ip_dst,16) && memcmp(&cxt->d_ip,&ip_src,16) &&
                 cxt->d_port == src_port && cxt->s_port == dst_port ) {
               cxt->d_tcpFlags    |= tcpflags;
               cxt->d_total_bytes += p_bytes;
               cxt->d_total_pkts  += 1;
               cxt->last_pkt_time  = tstamp;
               return;
            }
      }
      cxt = cxt->next;
   }

   if ( cxt == NULL ) {
      u_int64_t cxtrackerid;
      cxtrackerid += 1;
      cxtcnt += 1;
      if (cxtfree != NULL) {
         /* Use a connection from cxtfree */
         //move_connection(cxtfree, &cxtfree, cxt);
         // pop a connection from cxtfree
         cxt = cxtfree;
         cxtfree = cxtfree->next;
         //printf("[*] Re-used a connection from cxtfree...\n");
         freecnt -= 1;
      }else{
         /* Allocate memory for a new connection */
         cxt = (connection*) calloc(1, sizeof(connection));
         printf("[*] Allocated a new connection...\n");
      }
      if (head != NULL ) {
         head->prev = cxt;
      }
      /* printf("[*] New connection...\n"); */
      cxt->cxid           = cxtrackerid;
      cxt->ipversion      = af;
      cxt->s_tcpFlags     = tcpflags;
      cxt->d_tcpFlags     = 0x00;
      cxt->s_total_bytes  = p_bytes;
      cxt->s_total_pkts   = 1;
      cxt->d_total_bytes  = 0;
      cxt->d_total_pkts   = 0;
      cxt->start_time     = tstamp;
      cxt->last_pkt_time  = tstamp;

      cxt->s_ip          = ip_src;
      cxt->d_ip          = ip_dst;
      if (af == AF_INET) {
         cxt->s_ip.s6_addr32[1]          = 0;
         cxt->s_ip.s6_addr32[2]          = 0;
         cxt->s_ip.s6_addr32[3]          = 0;
         cxt->d_ip.s6_addr32[1]          = 0;
         cxt->d_ip.s6_addr32[2]          = 0;
         cxt->d_ip.s6_addr32[3]          = 0;
      }

      cxt->s_port         = src_port;
      cxt->d_port         = dst_port;
      cxt->proto          = ip_proto;
      cxt->next           = head;
      cxt->prev           = NULL;

      /* New connections are pushed on to the head of bucket[s_hash] */
      bucket[hash] = cxt;

      /* Return value should be X, telling to do fingerprinting */
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
            assert(cxt != cxt->next);
            cxt = cxt->next;
            move_connection(tmp, &bucket[cxkey], &cxtbuffer);
            cxtcnt -= 1; 
         }else{
            cxt = cxt->next;
         }
      }
   }
   fprintf(stderr, "[*] Expired: %u of %u total connections:\n",expired,curcxt);
   cxtbuffer_write();
//   fprintf(stderr, "[*] End.\n");
   printf("[*] cnxfree:%ju\tbucket:%ju\n",freecnt,cxtcnt);
}

void clear_connection (connection *cxt){
      memset(cxt, 0, sizeof(*cxt));
      /*
      cxt->cxid = 0;
      cxt->ipversion = 0;
      cxt->s_tcpFlags = 0x00;
      cxt->d_tcpFlags = 0x00;
      cxt->s_total_bytes = 0;
      cxt->s_total_pkts = 0;
      cxt->d_total_bytes = 0;
      cxt->d_total_pkts = 0;
      cxt->start_time = 0;
      cxt->last_pkt_time = 0;
      cxt->s_ip.s6_addr32[0] = 0;
      cxt->s_ip.s6_addr32[1] = 0;
      cxt->s_ip.s6_addr32[2] = 0;
      cxt->s_ip.s6_addr32[3] = 0;
      cxt->d_ip.s6_addr32[0] = 0;
      cxt->d_ip.s6_addr32[1] = 0;
      cxt->d_ip.s6_addr32[2] = 0;
      cxt->d_ip.s6_addr32[3] = 0;
      cxt->s_port = 0;
      cxt->d_port = 0;
      cxt->proto = 0;
      */
}

/* move cxt from bucket to cxtbuffer
 * there are three cases usually:
 * either, we are in the middle of list. Update next and prev
 * or, we are at end of list, next==NULL, update prev->next = NULL

*/
void move_connection (connection *cxt_from, connection **bucket_ptr_from, connection **cxt_to ){
   /* remove cxt from bucket */
   connection *prev = cxt_from->prev; /* OLDER connections */
   connection *next = cxt_from->next; /* NEWER connections */
   if(prev == NULL){
      // beginning of list
      *bucket_ptr_from = next;
      // not the only entry
      if(next)
         next->prev = NULL;
   } else if(next == NULL){
      // at end of list!
      prev->next = NULL;
   } else {
      // a node.
      prev->next = next;
      next->prev = prev;
   }

   /* add cxt to expired list cxtbuffer 
    - if head is null -> head = cxt; */
   cxt_from->next = *cxt_to; // next = head
   cxt_from->prev = NULL;
   *cxt_to = cxt_from;       // head = cxt. result: newhead = cxt->oldhead->list...
}

/* flush connection buffer to output */
void cxtbuffer_write () {

   if ( cxtbuffer == NULL ) { return; }
   connection *next, oldhead;
   next = NULL;

   while ( cxtbuffer != NULL ) {
      oldhead = cxtfree;
      next = cxtbuffer->next;

      // free connection:
      //pop from cxtbuffer, push to cxtfree
      cxtfree = cxtbuffer;
      cxtbuffer = next;

      freecnt += 1;
      clear_connection(cxtfree);
      cxtfree->next = oldhead;
      //printf("[*] cxtfree'd a connection\n");
      //debug = NULL;
   }

//   if (head != NULL ) { free(head); }
   /* just write something*/
//   fprintf(stderr, "Done...\n");
}

void check_interupt() {
   if ( intr_flag == 1 ) {
      game_over();
   }
/*
   else if ( intr_flag == 2 ) {
      dump_active();
   }
*/
   else if ( intr_flag == 3 ) {
      set_end_sessions();
   }
   else {
      intr_flag = 0;
   }
}

void set_end_sessions() {
   intr_flag = 3;
   if ( inpacket == 0 ) {
      end_sessions();
      cxtbuffer_write();
      intr_flag = 0;
      alarm(TIMEOUT);
   }
}

void game_over() {
   if ( inpacket == 0 ) {
      //end_all_sessions();
      cxtbuffer_write();
      pcap_close(handle);
      exit (0);
   }
   intr_flag = 1;
}

void add_connections() {
   int cxkey;
   connection *cxt;

   for ( cxkey = 0; cxkey < BUCKET_SIZE * 9; cxkey++ ) {
      freecnt += 1;
      cxt = (connection*) calloc(1, sizeof(connection));
      //clear_connection(cxt); // already calloced!
      if (cxtfree != NULL) {
         cxt->next = cxtfree;
         cxtfree->prev = cxt;
      }else{
         cxt->next = NULL;
      }
      cxt->prev           = NULL;

      cxtfree = cxt;
   }
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
   cxtrackerid  = 9999999999;
   inpacket = gameover = 0;
   freecnt = buffercnt = cxtcnt = 0;
   timecnt = time(NULL);

   if (getuid()) {
      printf("[*] You must be root..\n");
      return (1);
   }
   printf("[*] Running cxtracker...\n");

   signal(SIGTERM, game_over);
   signal(SIGINT,  game_over);
   signal(SIGQUIT, game_over);
   signal(SIGALRM, set_end_sessions);
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
   add_connections();

   /* B0rk if we see an error... */
   if (strlen(errbuf) > 0) {
      printf("[*] Error errbuf: %s \n", errbuf);
      exit(1);
   }

   alarm(TIMEOUT);
   printf("[*] Sniffing...\n\n");
   pcap_loop(handle,-1,got_packet,NULL);

   pcap_close(handle);
   return(0);
}

