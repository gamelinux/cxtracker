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
time_t      tstamp;
char        *dev,*dpath;
int         verbose;
int         inpacket, gameover;
pcap_t      *handle;
connection  *bucket[BUCKET_SIZE];
connection  *cxtbuffer = NULL;
static char src_s[INET6_ADDRSTRLEN];
static char dst_s[INET6_ADDRSTRLEN];

/* internal prototypes */
void move_connection (connection*, connection**);

void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet) {
   if ( gameover == 1 ) { game_over(); }
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

   else if ( eth_type == ETHERNET_TYPE_IPV6) {
      /* printf("[*] Got IPv6 Packet...\n"); */
      ip6_header *ip6;
      ip6 = (ip6_header *) (packet + eth_header_len);
      if ( ip6->next == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE TCP:\n"); */
         cx_track6(ip6->ip_src, tcph->src_port, ip6->ip_dst, tcph->dst_port, ip6->next, ip6->len, tcph->t_flags, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE UDP:\n"); */
         cx_track6(ip6->ip_src, udph->src_port, ip6->ip_dst, udph->dst_port, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP6_PROTO_ICMP) {
         icmp6_header *icmph;
         icmph = (icmp6_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE ICMP\n"); */
         cx_track6(ip6->ip_src, ip6->hop_lmt, ip6->ip_dst, ip6->hop_lmt, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
      else {
         /* printf("[*] IPv6 PROTOCOL TYPE OTHER: %d\n",ip6->next); */
         cx_track6(ip6->ip_src, ip6->next, ip6->ip_dst, ip6->next, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
   }
   inpacket = 0;
   return;
   /* else { */
      /* printf("[*] ETHERNET TYPE : %x\n", eth_hdr->eth_ip_type); */
   /*   return; */
   /* } */
}
void cx_track4(uint64_t ip_src,uint16_t src_port,uint64_t ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *s_cxt = NULL;
   connection *prev = NULL;
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
      else if ( s_cxt->s_ip4 == ip_dst && s_cxt->d_ip4 == ip_src && s_cxt->d_port == src_port && s_cxt->s_port == dst_port ) {
         s_cxt->d_tcpFlags    |= tcpflags;
         s_cxt->d_total_bytes += p_bytes;
         s_cxt->d_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         bucket[s_hash] = s_cxt;
         return;
      }
      prev = s_cxt;
      s_cxt = s_cxt->next;
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
      s_cxt->prev           = prev;

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

void cx_track6(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *s_cxt = NULL;
   connection *prev = NULL;
   uint32_t s_hash;

   /* Do we need all fields? */
   s_hash = ((  ip_src.s6_addr32[0] + ip_src.s6_addr32[1] + ip_src.s6_addr32[2] + ip_src.s6_addr32[3]
              + ip_dst.s6_addr32[0] + ip_dst.s6_addr32[1] + ip_dst.s6_addr32[2] + ip_dst.s6_addr32[3]
              + src_port + dst_port )) % BUCKET_SIZE;

   s_cxt = bucket[s_hash];

   while ( s_cxt != NULL ) {
      if ( memcmp(&s_cxt->s_ip6,&ip_src,16) && memcmp(&s_cxt->d_ip6,&ip_dst,16) &&
           s_cxt->s_port == src_port && s_cxt->d_port == dst_port ) {
         s_cxt->s_tcpFlags    |= tcpflags;
         s_cxt->s_total_bytes += p_bytes;
         s_cxt->s_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         bucket[s_hash] = s_cxt;
         return;
      }else 
      if ( memcmp(&s_cxt->s_ip6,&ip_dst,16) && memcmp(&s_cxt->d_ip6,&ip_src,16) &&
           s_cxt->d_port == src_port && s_cxt->s_port == dst_port ) {
         s_cxt->d_tcpFlags    |= tcpflags;
         s_cxt->d_total_bytes += p_bytes;
         s_cxt->d_total_pkts  += 1;
         s_cxt->last_pkt_time  = tstamp;
         bucket[s_hash] = s_cxt;
         return;
      }
      prev = s_cxt;
      s_cxt = s_cxt->next;
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
      s_cxt->prev           = prev;

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

   connection *cxt;
   time_t check_time;
   check_time = time(NULL);
   int cxkey, xpir;
   int expired = 0;
   
   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cxt = bucket[cxkey];
      xpir = 0;
      while ( cxt != NULL ) {
         /* TCP */
         if ( cxt->proto == IP_PROTO_TCP ) {
           /* FIN from both sides */
           if ( cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN && (check_time - cxt->last_pkt_time) > 5 ) {
              xpir = 1;
           }
           /* RST from eather side */
           else if ( (cxt->s_tcpFlags & TF_RST || cxt->d_tcpFlags & TF_RST) && (check_time - cxt->last_pkt_time) > 5) {
              xpir = 1;
           }
           /* if not a complete TCP 3-way handshake */
           else if ( !cxt->s_tcpFlags&TF_SYNACK || !cxt->d_tcpFlags&TF_SYNACK && (check_time - cxt->last_pkt_time) > 10) {
              xpir = 1;
           }
           /* Ongoing timout */
           else if ( (cxt->s_tcpFlags&TF_SYNACK || cxt->d_tcpFlags&TF_SYNACK) && ((check_time - cxt->last_pkt_time) > 120)) {
              xpir = 1;
           }
         }
         else if ( cxt->proto == IP_PROTO_UDP ) {
            if ( !cxt->d_total_pkts > 0 && (check_time - cxt->last_pkt_time) > 10) {
               xpir = 1;
            }
            else if ( (check_time - cxt->last_pkt_time) > 60 ) {
               xpir = 1;
            }
         }
         else if ( cxt->proto == IP_PROTO_ICMP || cxt->proto == IP6_PROTO_ICMP ) {
            if ( !cxt->d_total_pkts > 0 && (check_time - cxt->last_pkt_time) > 10) {
               xpir = 1;
            }
            else if ( (check_time - cxt->last_pkt_time) > 60 ) {
               xpir = 1;
            }
         }
         else if ( cxt->d_total_pkts > 0 && (check_time - cxt->last_pkt_time) > 100 ) {
            xpir = 1;
         }
         else if ( (check_time - cxt->last_pkt_time) > 600 ) {
            xpir = 1;
         }

         if ( xpir == 1 ) {
            expired++;
            xpir = 0;
            connection *tmp = cxt;
            cxt = cxt->next;
            move_connection(tmp, &bucket[cxkey]);
         }else{
            cxt = cxt->next;
         }
      }
   }
   cxtbuffer_write(); 
}

void move_connection (connection* cxt, connection **bucket_ptr ){
   /* remove cxt from bucket */
   connection *prev = cxt->prev; /* OLDER connections */
   connection *next = cxt->next; /* NEWER connections */
   /* if next NULL, NEWEST. if PREV NULL, oldest. */
   if(prev != NULL) prev->next = next;
   if(next == NULL){
      *bucket_ptr = prev;
   }else{
      next->prev = prev;
   }
   /* add cxt to expired list */
   cxt->next = cxtbuffer;
   cxtbuffer = cxt;
   cxt->prev = NULL;
}

void cxtbuffer_write () {

   if ( cxtbuffer == NULL ) { return; }
   connection *next;
   next = NULL;
 
   FILE *cxtFile;
   char *cxtfname;
   cxtfname = "";
   asprintf(&cxtfname, "%s/stats.%s.%ld", dpath, dev, tstamp);

   cxtFile = fopen(cxtfname, "w");

   if (cxtFile == NULL) {
      printf("[*] ERROR: Cant open file %s\n",cxtfname);
   }
   else {
      
      while ( cxtbuffer != NULL ) {
         char stime[80], ltime[80];
         time_t tot_time;

         static char src_s[INET6_ADDRSTRLEN];
         static char dst_s[INET6_ADDRSTRLEN];

         if (cxtbuffer->ipversion == AF_INET) {
            if (!inet_ntop(AF_INET, &cxtbuffer->s_ip4, src_s, INET6_ADDRSTRLEN))
               perror("Something died in inet_ntop");
            if (!inet_ntop(AF_INET, &cxtbuffer->d_ip4, dst_s, INET6_ADDRSTRLEN))
               perror("Something died in inet_ntop");
         }
         else if (cxtbuffer->ipversion == AF_INET6) {
            if (!inet_ntop(AF_INET6, &cxtbuffer->s_ip6, src_s, INET6_ADDRSTRLEN))
               perror("Something died in inet_ntop");
            if (!inet_ntop(AF_INET6, &cxtbuffer->d_ip6, dst_s, INET6_ADDRSTRLEN))
               perror("Something died in inet_ntop");
         }

         tot_time = cxtbuffer->last_pkt_time - cxtbuffer->start_time;
         strftime(stime, 80, "%F %H:%M:%S", gmtime(&cxtbuffer->start_time));
         strftime(ltime, 80, "%F %H:%M:%S", gmtime(&cxtbuffer->last_pkt_time));

         if ( verbose == 1 ) {
            printf("%ld%ju|%s|%s|%ld|%u|%s|%u|",cxtbuffer->start_time,cxtbuffer->cxid,stime,ltime,tot_time,
                                                cxtbuffer->proto,src_s,ntohs(cxtbuffer->s_port));
            printf("%s|%u|%ju|%ju|",dst_s,ntohs(cxtbuffer->d_port),cxtbuffer->s_total_pkts,cxtbuffer->s_total_bytes);
            printf("%ju|%ju|%u|%u\n",cxtbuffer->d_total_pkts,cxtbuffer->d_total_bytes,cxtbuffer->s_tcpFlags,
                                     cxtbuffer->d_tcpFlags);
         }

         fprintf(cxtFile,"%ld%ju|%s|%s|%ld|%u|%s|%u|",cxtbuffer->start_time,cxtbuffer->cxid,stime,ltime,tot_time,
                                                      cxtbuffer->proto,src_s,ntohs(cxtbuffer->s_port));
         fprintf(cxtFile,"%s|%u|%ju|%ju|",dst_s,ntohs(cxtbuffer->d_port),cxtbuffer->s_total_pkts,
                                          cxtbuffer->s_total_bytes);
         fprintf(cxtFile,"%ju|%ju|%u|%u\n",cxtbuffer->d_total_pkts,cxtbuffer->d_total_bytes,cxtbuffer->s_tcpFlags,
                                           cxtbuffer->d_tcpFlags);

         next = cxtbuffer->next;
         free(cxtbuffer);
         cxtbuffer = next;
      }
      fclose(cxtFile);
      free(cxtfname);
   }
}

void end_all_sessions() {
   connection *cxt;
   int cxkey;
   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cxt = bucket[cxkey];
      while ( cxt != NULL ) {
         connection *tmp = cxt;
         cxt = cxt->next;           
         move_connection(tmp, &bucket[cxkey]);
      }
   }
}

void game_over() {
   gameover = 1;
   if (inpacket == 0) {
      end_all_sessions();
      cxtbuffer_write();
      pcap_close(handle);
      exit (0);
   }
}

int main(int argc, char *argv[]) {

   if (getuid()) {
      printf("[*] You must be root..\n");
      return (1);
   }
   printf("[*] Running cxtracker...\n");

   signal(SIGTERM, game_over);
   signal(SIGINT,  game_over);
   signal(SIGQUIT, game_over);
   signal(SIGALRM, end_sessions);
   /* alarm(TIMEOUT); */

   int ch, fromfile, setfilter, version;
   struct in_addr addr;
   struct bpf_program cfilter;
   char *bpff, errbuf[PCAP_ERRBUF_SIZE], *user_filter;
   char *net_ip_string, *configfile;
   char *net_mask_string;
   bpf_u_int32 net_mask;
   bpf_u_int32 net_ip;
   dev = "eth0";
   bpff = "";
   dpath = "/tmp";
   cxtbuffer = NULL;
   cxtrackerid  = 999999999;
   inpacket = gameover = 0;
   timecnt = time(NULL);

   while ((ch = getopt(argc, argv, "i:b:V:v:d:c:")) != -1)
   switch (ch) {
      case 'i':
         dev = optarg;
         break;
      case 'b':
         bpff = optarg;
         break;
      case 'V':
         version = 1;
         break;
      case 'v':
         verbose = 1;
         break;
      case 'd':
         dpath = optarg;
         break;
      case 'c':
         configfile = optarg;
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
