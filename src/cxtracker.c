/*
 cxtracker.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include "cxtracker.h"

u_int64_t   cxtrackerid;
time_t      timecnt;
connection  *bucket[BUCKET_SIZE];
static char src_s[INET6_ADDRSTRLEN];
static char dst_s[INET6_ADDRSTRLEN];

void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet) {
   time_t tstamp = time(NULL);
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
         return;
      }
      else if (ip4->ip_p == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE UDP:\n"); */
         cx_track4(ip4->ip_src, udph->src_port, ip4->ip_dst, udph->dst_port, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         return;
      }
      else if (ip4->ip_p == IP_PROTO_ICMP) {
         icmp_header *icmph;
         icmph = (icmp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IP PROTOCOL TYPE ICMP\n"); */
         cx_track4(ip4->ip_src, icmph->s_icmp_id, ip4->ip_dst, icmph->s_icmp_id, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         return;
      }
      else {
         /* printf("[*] IPv4 PROTOCOL TYPE OTHER: %d\n",ip4->ip_p); */
         cx_track4(ip4->ip_src, ip4->ip_p, ip4->ip_dst, ip4->ip_p, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         return;
      }
      return;
   }

   else if ( eth_type == ETHERNET_TYPE_IPV6) {
      /* printf("[*] Got IPv6 Packet...\n"); */
      ip6_header *ip6;
      ip6 = (ip6_header *) (packet + eth_header_len);
      if ( ip6->next == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE TCP:\n"); */
         cx_track6(ip6->ip_src, tcph->src_port, ip6->ip_dst, tcph->dst_port, ip6->next, ip6->len, tcph->t_flags, tstamp, AF_INET6);
         return;
      }
      else if (ip6->next == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE UDP:\n"); */
         cx_track6(ip6->ip_src, udph->src_port, ip6->ip_dst, udph->dst_port, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         return;
      }
      else if (ip6->next == IP6_PROTO_ICMP) {
         icmp6_header *icmph;
         icmph = (icmp6_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE ICMP\n"); */
         /*cx_track6(ip6->ip_src, icmph->icmp6_id, ip6->ip_dst, icmph->icmp6_id, ip6->next, ip6->len, 0, tstamp, AF_INET6);*/
         cx_track6(ip6->ip_src, ip6->hop_lmt, ip6->ip_dst, ip6->hop_lmt, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         return;
      }
      else {
         /* printf("[*] IPv6 PROTOCOL TYPE OTHER: %d\n",ip6->next); */
         cx_track6(ip6->ip_src, ip6->next, ip6->ip_dst, ip6->next, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         return;
      }
   }
   return;
   /* else { */
      /* printf("[*] ETHERNET TYPE : %x\n", eth_hdr->eth_ip_type); */
   /*   return; */
   /* } */
}

void cx_track4(uint64_t ip_src,uint16_t src_port,uint64_t ip_dst,uint16_t dst_port,uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *s_cxt = NULL;
   uint64_t s_hash;

   s_hash = (( ip_src + ip_dst ) + (src_port + dst_port )) % BUCKET_SIZE; 

   s_cxt = bucket[s_hash];

   while ( s_cxt != NULL ) {
      if ( s_cxt->s_ip4 == ip_src && s_cxt->d_ip4 == ip_dst && s_cxt->s_port == src_port && s_cxt->d_port == dst_port ) {
         s_cxt->s_tcpFlags    |= tcpflags;
         s_cxt->s_total_bytes += p_bytes;
         s_cxt->s_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         bucket[s_hash] = s_cxt;
         return;
      }
      else if ( s_cxt->s_ip4 == ip_dst && s_cxt->d_ip4 == ip_src && s_cxt->d_port == src_port && s_cxt->d_port == src_port ) {
         s_cxt->d_tcpFlags    |= tcpflags;
         s_cxt->d_total_bytes += p_bytes;
         s_cxt->d_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         bucket[s_hash] = s_cxt;
         return;
      }
      if ( s_cxt->next != NULL ) {
         s_cxt = s_cxt->next;
      }
      else {
         /* Have hash, but not the connection. Must be a new one... */
         s_cxt = s_cxt->next;
         break;
      }
   }

   if ( s_cxt == NULL ) {
      cxtrackerid += 1;
      s_cxt = (connection*) calloc(1, sizeof(connection));
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
      s_cxt->next           = NULL;

      bucket[s_hash] = s_cxt;

      if ( ((tstamp - timecnt) > TIMEOUT) ) {
         timecnt = time(NULL);
         end_sessions();
      }

      return;
   }

   /* Should never be here! */
   /* printf("[*] ERROR: Should never be here - hash collision?!!!\n"); */
   return;
}

void cx_track6(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *s_cxt = NULL;
   uint32_t s_hash;

   /* Need to enhance this! */
   s_hash = (( src_port + dst_port + ip_proto + af )) % BUCKET_SIZE;

   s_cxt = bucket[s_hash];

   while ( s_cxt != NULL ) {
/* if (s_cxt->s_ip6 == ip_src && s_cxt->d_ip6 == ip_dst && s_cxt->s_port == src_port && s_cxt->d_port == dst_port ) { */
      if ( s_cxt->s_port == src_port && s_cxt->d_port == dst_port && s_cxt->proto == ip_proto ) {
         s_cxt->s_tcpFlags    |= tcpflags;
         s_cxt->s_total_bytes += p_bytes;
         s_cxt->s_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         bucket[s_hash] = s_cxt;
         return;
      }
/* else if(s_cxt->s_ip6 == ip_dst && s_cxt->d_ip6 == ip_src && s_cxt->d_port == src_port && s_cxt->d_port == src_port ) { */
   else if ( s_cxt->d_port == src_port && s_cxt->d_port == src_port && s_cxt->proto == ip_proto ) {
         s_cxt->d_tcpFlags    |= tcpflags;
         s_cxt->d_total_bytes += p_bytes;
         s_cxt->d_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         bucket[s_hash] = s_cxt;
         return;
      }
      if ( s_cxt->next != NULL ) {
         s_cxt = s_cxt->next;
      }
      else {
         /* Have hash, but not the connection. Must be a new one... */
         s_cxt = s_cxt->next;
         break;
      }
   }

   if ( s_cxt == NULL ) {
      cxtrackerid += 1;
      s_cxt = (connection*) calloc(1, sizeof(connection));
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
      s_cxt->s_ip4          = 0;
      s_cxt->s_ip6          = ip_src;
      s_cxt->s_port         = src_port;
      s_cxt->d_ip4          = 0;
      s_cxt->d_ip6          = ip_dst;
      s_cxt->d_port         = dst_port;
      s_cxt->proto          = ip_proto;
      s_cxt->next           = NULL;

      bucket[s_hash] = s_cxt;
      if ( ((tstamp - timecnt) > TIMEOUT) ) {
         timecnt = time(NULL);
         end_sessions();
      }
      return;
   }

   /* Should never be here! */
   /* printf("[*] ERROR: Should never be here - hash collision?!!!\n"); */
   return;
}

/*
 This sub marks sessions as ENDED on different criterias:

 Default TCP initial timeout                   10 seconds
 Default TCP ongoing timeout                    2 hours
 TCP timeout after RST received either way      5 seconds
 TCP timeout after ACK after FIN each way       5 seconds
 TCP timeout after ICMP error                   5 seconds
 Default UDP initial timeout                   60 seconds
 Default UDP ongoing timeout                   10 seconds
 UDP timeout after ICMP error                  10 seconds
 Default ICMP initial timeout                  10 seconds
 Default ICMP ongoing timeout                  60 seconds
 ICMP timeout after ICMP error                 10 seconds
 Default other initial timeout                100 seconds
 Default other ongoing timeout                100 minutes
*/

void end_sessions() {
   connection *cnx;
   time_t check_time;
   check_time = time(NULL);
   int cxkey, xpir;
   int expired = 0;
   
   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cnx = bucket[cxkey];
      xpir = 0;
      while ( cnx != NULL ) {
         /* TCP */
         if ( cnx->proto == IP_PROTO_TCP ) {
           /* FIN from both sides */
           if ( cnx->s_tcpFlags & TF_FIN && cnx->d_tcpFlags & TF_FIN && (check_time - cnx->last_pkt_time) > 5 ) {
              xpir = 1;
           }
           /* RST from eather side */
           else if ( (cnx->s_tcpFlags & TF_RST || cnx->d_tcpFlags & TF_RST) && (check_time - cnx->last_pkt_time) > 5) {
              xpir = 1;
           }
           /* if not a complete TCP 3-way handshake */
           else if ( !cnx->s_tcpFlags&TF_SYNACK || !cnx->d_tcpFlags&TF_SYNACK && (check_time - cnx->last_pkt_time) > 10) {
              xpir = 1;
           }
           /* Ongoing timout */
           else if ( (cnx->s_tcpFlags&TF_SYNACK || cnx->d_tcpFlags&TF_SYNACK) && ((check_time - cnx->last_pkt_time) > 120)) {
              xpir = 1;
           }
         }
         else if ( cnx->proto == IP_PROTO_UDP ) {
            if ( !cnx->d_total_pkts > 0 && (check_time - cnx->last_pkt_time) > 10) {
               xpir = 1;
            }
            else if ( (check_time - cnx->last_pkt_time) > 60 ) {
               xpir = 1;
            }
         }
         else if ( cnx->proto == IP_PROTO_ICMP || cnx->proto == IP6_PROTO_ICMP ) {
            if ( !cnx->d_total_pkts > 0 && (check_time - cnx->last_pkt_time) > 10) {
               xpir = 1;
            }
            /* > 10 should be > 60 (Keep for testing now) */
            else if ( (check_time - cnx->last_pkt_time) > 60 ) {
               xpir = 1;
            }
         }
         else if ( cnx->d_total_pkts > 0 && (check_time - cnx->last_pkt_time) > 100 ) {
            xpir = 1;
         }
         else if ( (check_time - cnx->last_pkt_time) > 600 ) {
            xpir = 1;
         }

         if ( xpir == 1 ) {

            export_session (cnx);
            expired++;
            xpir = 0;

            /* If there are no more elements in the list - NULL and free() */
            if ( cnx->prev == NULL && cnx->next == NULL ) {
               cnx = NULL;
               bucket[cxkey] = NULL;
               free (bucket[cxkey]);
               break;
            }

            /* Update pointers */
            if ( cnx->prev != NULL ) { 
               cnx->prev->next = cnx->next;
            }
            if ( cnx->next != NULL ) {
               cnx->next->prev = cnx->prev;
            }

            cnx = cnx->next;
         }
         else {
            if ( cnx->next != NULL ) {
               cnx = cnx->next;
            }
            else {
               break;
            }
         }
      }
   }
}

void end_all_sessions() {
   connection *cnx;
   int cxkey;

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cnx = bucket[cxkey];
      while ( cnx != NULL ) {
         export_session (cnx);
         if ( cnx->next == NULL ) {
            break;
         }
         cnx = cnx->next;
      }
   }
}

/*
 Prints out the ended sessions or status of active sessions.
 Takes %$session of sessions as input along with $delete.
 If $delete is 1, the session gets removed from %$session.
 If $delete is 0, the session is not removed from %$session.
*/

void export_session(connection *cnx) {

   char stime[80], ltime[80];
   time_t tot_time;

   static char src_s[INET6_ADDRSTRLEN];
   static char dst_s[INET6_ADDRSTRLEN];

   if (cnx->ipversion == AF_INET) {
      if (!inet_ntop(AF_INET, &cnx->s_ip4, src_s, INET6_ADDRSTRLEN))
         perror("Something died in inet_ntop");
      if (!inet_ntop(AF_INET, &cnx->d_ip4, dst_s, INET6_ADDRSTRLEN))
         perror("Something died in inet_ntop");
   }
   else if (cnx->ipversion == AF_INET6) {
      if (!inet_ntop(AF_INET6, &cnx->s_ip6, src_s, INET6_ADDRSTRLEN))
         perror("Something died in inet_ntop");
      if (!inet_ntop(AF_INET6, &cnx->d_ip6, dst_s, INET6_ADDRSTRLEN))
         perror("Something died in inet_ntop");
   }

   tot_time = cnx->last_pkt_time - cnx->start_time;
   strftime(stime, 80, "%F %H:%M:%S", gmtime(&cnx->start_time));
   strftime(ltime, 80, "%F %H:%M:%S", gmtime(&cnx->last_pkt_time));

   printf("%ld%ju|%s|%s|%ld|%d|%s|%u|",cnx->start_time,cnx->cxid,stime,ltime,tot_time,cnx->proto,src_s,ntohs(cnx->s_port));
   printf("%s|%u|%ju|%ju|",dst_s,ntohs(cnx->d_port),cnx->s_total_pkts,cnx->s_total_bytes);
   printf("%ju|%ju|%d|%d\n",cnx->d_total_pkts,cnx->d_total_bytes,cnx->s_tcpFlags,cnx->d_tcpFlags);
}

void game_over() {
   printf("\nDumping ongoing connection:\n");
   end_all_sessions();
   exit (0);
}

int main(int argc, char *argv[]) {

   if (getuid()) {
      printf("[*] You must be root..\n");
      return (1);
   }
   printf("[*] Running cxtracker...\n");

   signal(SIGKILL, game_over);
   signal(SIGTERM, game_over);
   signal(SIGINT,  game_over);
   signal(SIGQUIT, game_over);
   signal(SIGALRM, end_sessions);
   /* alarm(TIMEOUT); */

   int ch, fromfile, setfilter, verbose;
   struct in_addr addr;
   struct bpf_program cfilter;
   char *dev, *bpff, *filename, errbuf[PCAP_ERRBUF_SIZE], *user_filter;
   char *net_ip_string;
   char *net_mask_string;
   bpf_u_int32 net_mask;
   bpf_u_int32 net_ip;
   pcap_t *handle;
   dev = "eth0";
   bpff = "";
   cxtrackerid   = 999999999;
   timecnt = time(NULL);

   while ((ch = getopt(argc, argv, "v:i:b:")) != -1)
   switch (ch) {
      case 'i':
         dev = optarg;
         break;
      case 'b':
         bpff = optarg;
         break;
      case 'v':
         verbose = 1;
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

   /* signal(SIGINT, sigproc); */

   printf("[*] Sniffing...\n\n");
   pcap_loop(handle,-1,got_packet,NULL);

   pcap_close(handle);
   return(0);
}
