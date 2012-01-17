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

/*  I N C L U D E S  **********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include "cxtracker.h"

#include "format.h"

/*  G L O B A L E S  **********************************************************/
u_int64_t    cxtrackerid;
time_t       tstamp;

pcap_t        *handle;
pcap_dumper_t *dump_handle;

connection   *bucket[BUCKET_SIZE];
connection   *cxtbuffer = NULL;
static char  *dev,*chroot_dir,*output_format;
static char  dpath[STDBUF] = "./";
static char  *group_name, *user_name, *true_pid_name;
static char  *pidfile = "cxtracker.pid";
static char  *pidpath = "/var/run";
static int   verbose, inpacket, intr_flag, use_syslog, dump_with_flush;
static int   mode;
static char  *read_file;
static int64_t  read_file_offset = 0;

static uint64_t roll_size;
static time_t   roll_time;
static time_t   roll_time_last;
static int64_t  dump_file_offset = 0;
static char     *dump_file_prefix;
static char     dump_file[STDBUF];
//uint64_t        max_cxt   = 0;
//uint64_t        cxt_alloc = 0;
//uint64_t        cxt_free  = 0;

ip_config_t  ip_config;


/*  I N T E R N A L   P R O T O T Y P E S  ************************************/
void move_connection (connection*, connection**);
inline void cx_track(ip_t ip_src, uint16_t src_port, ip_t ip_dst, uint16_t dst_port,uint8_t ip_proto,uint32_t p_bytes,uint8_t tcpflags,time_t tstamp, int af);
void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet);
void end_sessions();
void cxtbuffer_write();
void game_over();
void check_interupt();
void dump_active();
void set_end_sessions();


int dump_file_open();
int dump_file_roll();
int dump_file_close();




void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet) {
   if ( intr_flag != 0 ) { check_interupt(); }
   inpacket = 1;

   tstamp = pheader->ts.tv_sec;

   /* are we dumping */
   if (mode & MODE_DUMP) {
      time_t now = time(NULL);

      /* check if we should roll on time */
      if( ( roll_time != 0 ) &&
          ( now >= (roll_time_last + roll_time) ) )
      {
         roll_time_last = now;
         printf("Rolling on time.\n");
         dump_file_roll();
      }

      dump_file_offset = (int64_t)ftell((FILE *)dump_handle);

      /* check if we should roll on size */
      if ( (roll_size > 0) &&
           (dump_file_offset >= roll_size) )
      {
         printf("Rolling on size.\n");
         dump_file_roll();
      }

      /* write the packet */
      pcap_dump((u_char *)dump_handle, pheader, packet);

      if ( dump_with_flush )
         pcap_dump_flush(dump_handle);
   }
   else if ( mode & MODE_FILE ) {
      read_file_offset = (int64_t)ftell(pcap_file(handle)) - pheader->caplen - 16;
   }

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

   /* zero-ise our structure, simplifies our hashing later on */
   ip_t ip_src = { 0 };
   ip_t ip_dst = { 0 };

   if ( eth_type == ETHERNET_TYPE_IP ) {
      /* printf("[*] Got IPv4 Packet...\n"); */
      ip4_header *ip4;
      ip4 = (ip4_header *) (packet + eth_header_len);

      ip_set(&ip_config, &ip_src, &ip4->ip_src, AF_INET);
      ip_set(&ip_config, &ip_dst, &ip4->ip_dst, AF_INET);

      if ( ip4->ip_p == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE TCP:\n"); */
         cx_track(ip_src, tcph->src_port, ip_dst, tcph->dst_port, ip4->ip_p, pheader->len, tcph->t_flags, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE UDP:\n"); */
         cx_track(ip_src, udph->src_port, ip_dst, udph->dst_port, ip4->ip_p, pheader->len, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_ICMP) {
         icmp_header *icmph;
         icmph = (icmp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IP PROTOCOL TYPE ICMP\n"); */
         cx_track(ip_src, icmph->s_icmp_id, ip_dst, icmph->s_icmp_id, ip4->ip_p, pheader->len, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
      else {
         /* printf("[*] IPv4 PROTOCOL TYPE OTHER: %d\n",ip4->ip_p); */
         cx_track(ip_src, ip4->ip_p, ip_dst, ip4->ip_p, ip4->ip_p, pheader->len, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
   }

   else if ( eth_type == ETHERNET_TYPE_IPV6) {
      /* printf("[*] Got IPv6 Packet...\n"); */
      ip6_header *ip6;
      ip6 = (ip6_header *) (packet + eth_header_len);

      ip_set(&ip_config, &ip_src, &ip6->ip_src, AF_INET6);
      ip_set(&ip_config, &ip_dst, &ip6->ip_dst, AF_INET6);

      if ( ip6->next == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + IP6_HEADER_LEN);
         /* printf("[*] IPv6 PROTOCOL TYPE TCP:\n"); */
         cx_track(ip_src, tcph->src_port, ip_dst, tcph->dst_port, ip6->next, pheader->len, tcph->t_flags, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + IP6_HEADER_LEN);
         /* printf("[*] IPv6 PROTOCOL TYPE UDP:\n"); */
         cx_track(ip_src, udph->src_port, ip_dst, udph->dst_port, ip6->next, pheader->len, 0, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP6_PROTO_ICMP) {
         //icmp6_header *icmph;
         //icmph = (icmp6_header *) (packet + eth_header_len + IP6_HEADER_LEN);

         /* printf("[*] IPv6 PROTOCOL TYPE ICMP\n"); */
         cx_track(ip_src, ip6->hop_lmt, ip_dst, ip6->hop_lmt, ip6->next, pheader->len, 0, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
      else {
         /* printf("[*] IPv6 PROTOCOL TYPE OTHER: %d\n",ip6->next); */
         cx_track(ip_src, ip6->next, ip_dst, ip6->next, ip6->next, pheader->len, 0, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
   }
   inpacket = 0;
   return;
   /* else { */
   /*   printf("[*] ETHERNET TYPE : %x\n", eth_hdr->eth_ip_type); */
   /*   return; */
   /* } */
}

inline
void cx_track(ip_t ip_src, uint16_t src_port,ip_t ip_dst, uint16_t dst_port,
               uint8_t ip_proto, uint32_t p_bytes, uint8_t tcpflags,time_t tstamp, int af) {

   connection *cxt = NULL;
   connection *head = NULL;

   /* for non-ipv6 addresses, indexes 1, 2 and 3 are zero and don't influence the hash */
   uint64_t hash = ip_hash(&ip_src, &ip_dst, BUCKET_SIZE);

   cxt = bucket[hash];
   head = cxt;

   while ( cxt != NULL ) {
      if ( cxt->s_port == src_port && cxt->d_port == dst_port
           && ip_cmp(&cxt->s_ip, &ip_src) == 0
           && ip_cmp(&cxt->d_ip, &ip_dst) == 0 )
      {
         cxt->s_tcpFlags    |= tcpflags;
         cxt->s_total_bytes += p_bytes;
         cxt->s_total_pkts  += 1;
         cxt->last_pkt_time  = tstamp;

         if ( mode & MODE_DUMP )
         {
            cxt->last_offset = dump_file_offset + p_bytes;
            snprintf(cxt->last_dump, STDBUF, "%s", dump_file);
         }
         else if ( mode & MODE_FILE )
         {
            cxt->last_offset = read_file_offset + p_bytes;
            snprintf(cxt->last_dump, STDBUF, "%s", read_file);
         }

         return;
      }
      else if ( cxt->d_port == src_port && cxt->s_port == dst_port
                && ip_cmp(&cxt->s_ip, &ip_dst) == 0
                && ip_cmp(&cxt->d_ip, &ip_src) == 0 )
      {
         cxt->d_tcpFlags    |= tcpflags;
         cxt->d_total_bytes += p_bytes;
         cxt->d_total_pkts  += 1;
         cxt->last_pkt_time  = tstamp;

         if ( mode & MODE_DUMP )
         {
            cxt->last_offset = dump_file_offset + p_bytes;
            snprintf(cxt->last_dump, STDBUF, "%s", dump_file);
         }
         else if ( mode & MODE_FILE )
         {
            cxt->last_offset = read_file_offset + p_bytes;
            snprintf(cxt->last_dump, STDBUF, "%s", read_file);
         }

         return;
      }
      cxt = cxt->next;
   }

   if ( cxt == NULL ) {
      cxtrackerid += 1;
      cxt = (connection*) calloc(1, sizeof(connection));
      //cxt_alloc++;
      if (head != NULL ) {
         head->prev = cxt;
      }
      /* printf("[*] New connection...\n"); */
      cxt->cxid           = cxtrackerid;
      cxt->ipversion      = af;
      cxt->s_tcpFlags     = tcpflags;
      /* cxt->d_tcpFlags     = 0x00; */
      cxt->s_total_bytes  = p_bytes;
      cxt->s_total_pkts   = 1;
      /* cxt->d_total_bytes  = 0; */
      /* cxt->d_total_pkts   = 0; */
      cxt->start_time     = tstamp;

      if ( mode & MODE_DUMP )
      {
         cxt->start_offset = dump_file_offset;
         cxt->last_offset = cxt->start_offset + p_bytes;
         snprintf(cxt->start_dump, STDBUF, "%s", dump_file);
         snprintf(cxt->last_dump, STDBUF, "%s", dump_file);
      }
      else if ( mode & MODE_FILE )
      {
         cxt->start_offset = read_file_offset;
         cxt->last_offset = cxt->start_offset + p_bytes;
         snprintf(cxt->start_dump, STDBUF, "%s", read_file);
         snprintf(cxt->last_dump, STDBUF, "%s", read_file);
      }
      else
      {
         cxt->start_offset = -1;
         cxt->last_offset = -1;
      }

      cxt->last_pkt_time  = tstamp;

      cxt->s_ip          = ip_src;
      cxt->d_ip          = ip_dst;
      /* This should be Zeroed due to calloc */
      /*
      if (af == AF_INET) {
         cxt->s_ip.s6_addr32[1]          = 0;
         cxt->s_ip.s6_addr32[2]          = 0;
         cxt->s_ip.s6_addr32[3]          = 0;
         cxt->d_ip.s6_addr32[1]          = 0;
         cxt->d_ip.s6_addr32[2]          = 0;
         cxt->d_ip.s6_addr32[3]          = 0;
      }
      */
      cxt->s_port         = src_port;
      cxt->d_port         = dst_port;
      cxt->proto          = ip_proto;
      cxt->next           = head;
      //cxt->prev           = NULL;

      /* New connections are pushed on to the head of bucket[s_hash] */
      bucket[hash] = cxt;

      /* Return value should be X, telling to do fingerprinting */
      return;
   }
   /* Should never be here! */
   return;
}

/*
 This sub marks sessions as ENDED on different criterias:
*/

void end_sessions() {

   connection *cxt;
   time_t check_time;
   check_time = time(NULL);
   int cxkey, xpir;
   uint32_t curcxt  = 0;
   uint32_t expired = 0;
   cxtbuffer = NULL;

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cxt = bucket[cxkey];
      xpir = 0;
      while ( cxt != NULL ) {
         curcxt++;
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
           else if ( ( ( !(cxt->s_tcpFlags&TF_SYN) ) && ( !(cxt->s_tcpFlags&TF_ACK) ) ) || (
                       ( ( !(cxt->d_tcpFlags&TF_SYN) ) && ( !(cxt->d_tcpFlags&TF_ACK) ) ) &&
                       ( (check_time-cxt->last_pkt_time) > 30)
                     )
                   ) {
              xpir = 1;
           }
           /* Ongoing timout */
           //else if ( (cxt->s_tcpFlags&TF_SYNACK || cxt->d_tcpFlags&TF_SYNACK) && ((check_time - cxt->last_pkt_time) > 120)) {
           //   xpir = 1;
           //}
           else if ( (check_time - cxt->last_pkt_time) > 600 ) {
              xpir = 1;
           }
         }
         else if ( cxt->proto == IP_PROTO_UDP && (check_time - cxt->last_pkt_time) > 60 ) {
               xpir = 1;
         }
         else if ( cxt->proto == IP_PROTO_ICMP || cxt->proto == IP6_PROTO_ICMP ) {
            if ( (check_time - cxt->last_pkt_time) > 60 ) {
               xpir = 1;
            }
         }
         else if ( (check_time - cxt->last_pkt_time) > 300 ) {
            xpir = 1;
         }

         if ( xpir == 1 ) {
            expired++;
            xpir = 0;
            connection *tmp = cxt;
            if (cxt == cxt->next) {
               cxt->next = NULL;
            }
            cxt = cxt->next;
            move_connection(tmp, &bucket[cxkey]);
         } else {
            cxt = cxt->next;
         }
      }
   }
   /* printf("Expired: %u of %u total connections:\n",expired,curcxt); */
}

void move_connection (connection *cxt_from, connection **bucket_ptr_from) {
   /* remove cxt from bucket */
   connection *prev = cxt_from->prev; /* OLDER connections */
   connection *next = cxt_from->next; /* NEWER connections */
   if ( prev == NULL ) {
      /* beginning of list */
      *bucket_ptr_from = next;
      /* not only entry */
      if ( next )
         next->prev = NULL;
   } else if ( next == NULL ) {
      /* at end of list! */
      prev->next = NULL;
   } else {
      /* a node */
      prev->next = next;
      next->prev = prev;
   }

   /* add cxt to expired list cxtbuffer
    * - if head is null -> head = cxt;
    */
   cxt_from->next = cxtbuffer; /* next = head */
   cxt_from->prev = NULL;
   cxtbuffer = cxt_from;       /* head = cxt. result: newhead = cxt->oldhead->list... */
}

void cxtbuffer_write () {

   if ( cxtbuffer == NULL ) { return; }
   connection *next;
   next = NULL;
   FILE *cxtFile;
   char cxtfname[4096];

   sprintf(cxtfname, "%sstats.%s.%ld", dpath, dev, tstamp);
   cxtFile = fopen(cxtfname, "w");

   if (cxtFile == NULL) {
      printf("[E] ERROR: Cant open file %s\n",cxtfname);
      /* Free them anyways! */
      while ( cxtbuffer != NULL ) {
         next = cxtbuffer->next;
         free(cxtbuffer);
         //cxt_free++;
         cxtbuffer = NULL;
         cxtbuffer = next;
      }
      printf("[W] connections went to visit /dev/null\n");
   }
   else {

      while ( cxtbuffer != NULL ) {
         format_write(cxtFile, cxtbuffer);

         next = cxtbuffer->next;
         free(cxtbuffer);
         //cxt_free++;
         cxtbuffer = NULL;
         cxtbuffer = next;
      }
      fclose(cxtFile);
   }
   cxtbuffer = NULL;
}

void end_all_sessions() {
   connection *cxt;
   int cxkey;
   int expired = 0;

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cxt = bucket[cxkey];
      while ( cxt != NULL ) {
         expired++;
         connection *tmp = cxt;
         cxt = cxt->next;
         move_connection(tmp, &bucket[cxkey]);
         if ( cxt == NULL ) {
            bucket[cxkey] = NULL;
         }
      }
   }
   //printf("Expired: %d.\n",expired);
}

void bucket_keys_NULL() {
   int cxkey;

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      bucket[cxkey] = NULL;
   }
}

void check_interupt() {
   if ( intr_flag == 1 ) {
      game_over();
   }
   else if ( intr_flag == 2 ) {
      dump_active();
   }
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
      end_all_sessions();
      cxtbuffer_write();
      pcap_close(handle);
      format_clear();
      //printf("    cxt_alloc: %lu\n",cxt_alloc);
      //printf("    cxt_free : %lu\n",cxt_free);
      exit(0);
   }
   intr_flag = 1;
}

void dump_active() {
   if ( inpacket == 0 && intr_flag == 2 ) {
      end_all_sessions();
      cxtbuffer_write();
      intr_flag = 0;
   } else {
      intr_flag = 2;
   }
}

int dump_file_open()
{

   /* calculate filename */
   time_t now = time(NULL);

   memset(dump_file, 0, STDBUF);

   if ( dpath != NULL )
      snprintf(dump_file, STDBUF, "%s%s.%lu", dpath, dump_file_prefix, (long unsigned int) now);
   else
      snprintf(dump_file, STDBUF, "%s.%lu", dump_file_prefix, (long unsigned int) now);

   // TODO: check if destination file already exists


   if ( (dump_handle=pcap_dump_open(handle, dump_file)) == NULL )
   {
      exit(1);
   }

   return SUCCESS;
}

int dump_file_roll()
{
   dump_file_close();
   dump_file_open();

   return SUCCESS;
}


int dump_file_close()
{
   if ( dump_handle != NULL ) {
      pcap_dump_flush(dump_handle);
      pcap_dump_close(dump_handle);
      dump_handle = NULL;
   }

   return SUCCESS;
}


static int set_chroot(void) {
   char *absdir;

   /* logdir = get_abs_path(logpath); */

   /* change to the directory */
   if ( chdir(chroot_dir) != 0 ) {
      printf("set_chroot: Can not chdir to \"%s\": %s\n",chroot_dir,strerror(errno));
   }

   /* always returns an absolute pathname */
   absdir = getcwd(NULL, 0);

   /* make the chroot call */
   if ( chroot(absdir) < 0 ) {
      printf("Can not chroot to \"%s\": absolute: %s: %s\n",chroot_dir,absdir,strerror(errno));
   }

   if ( chdir("/") < 0 ) {
        printf("Can not chdir to \"/\" after chroot: %s\n",strerror(errno));
   }

   return 0;
}

static int drop_privs(void) {
   struct group *gr;
   struct passwd *pw;
   char *endptr;
   int i;
   int do_setuid = 0;
   int do_setgid = 0;
   unsigned long groupid = 0;
   unsigned long userid = 0;

   if ( group_name != NULL ) {
      do_setgid = 1;
      if( isdigit(group_name[0]) == 0 ) {
         gr = getgrnam(group_name);
         groupid = gr->gr_gid;
      }
      else {
         groupid = strtoul(group_name, &endptr, 10);
      }
   }

   if ( user_name != NULL ) {
      do_setuid = 1;
      do_setgid = 1;
      if ( isdigit(user_name[0]) == 0 ) {
         pw = getpwnam(user_name);
         userid = pw->pw_uid;
      } else {
         userid = strtoul(user_name, &endptr, 10);
         pw = getpwuid(userid);
      }

      if ( group_name == NULL ) {
         groupid = pw->pw_gid;
      }
   }

   if ( do_setgid ) {
      if ( (i = setgid(groupid)) < 0 ) {
         printf("Unable to set group ID: %s", strerror(i));
      }
   }

   endgrent();
   endpwent();

   if ( do_setuid ) {
      if (getuid() == 0 && initgroups(user_name, groupid) < 0 ) {
         printf("Unable to init group names (%s/%lu)", user_name, groupid);
      }
      if ( (i = setuid(userid)) < 0 ) {
         printf("Unable to set user ID: %s\n", strerror(i));
      }
   }
   return 0;
}

static int is_valid_path(char *path) {
   struct stat st;

   if ( path == NULL ) {
      return 0;
   }
   if ( stat(path, &st) != 0 ) {
      return 0;
   }
   if ( !S_ISDIR(st.st_mode) || access(path, W_OK) == -1 ) {
      return 0;
   }
   return 1;
}

static int create_pid_file(char *path, char *filename) {
   char filepath[STDBUF];
   char *fp = NULL;
   char *fn = NULL;
   char pid_buffer[12];
   struct flock lock;
   int rval;
   int fd;

   memset(filepath, 0, STDBUF);

   if ( !filename ) {
      fn = pidfile;
   }
   else {
      fn = filename;
   }

   if ( !path ) {
      fp = pidpath;
   }
   else {
      fp = path;
   }

   if ( is_valid_path(fp) ) {
      snprintf(filepath, STDBUF-1, "%s/%s", fp, fn);
   }
   else {
      printf("PID path \"%s\" isn't a writeable directory!", fp);
   }

   true_pid_name = strdup(filename);

   if ( (fd = open(filepath, O_CREAT | O_WRONLY,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1 ) {
      return ERROR;
   }

   /* pid file locking */
   lock.l_type = F_WRLCK;
   lock.l_start = 0;
   lock.l_whence = SEEK_SET;
   lock.l_len = 0;

   if ( fcntl(fd, F_SETLK, &lock) == -1 ) {
      if ( errno == EACCES || errno == EAGAIN ) {
         rval = ERROR;
      }
      else {
         rval = ERROR;
      }
      close(fd);
      return rval;
   }

   snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int) getpid());
   if ( ftruncate(fd, 0) != 0 ) { return ERROR; }
   if ( write(fd, pid_buffer, strlen(pid_buffer)) != 0 ) { return ERROR; }
   return SUCCESS;
}

int daemonize() {
   pid_t pid;
   int fd;

   pid = fork();

   if ( pid > 0 ) {
      exit(0); /* parent */
   }

   use_syslog = 1;
   if ( pid < 0 ) {
      return ERROR;
   }

   /* new process group */
   setsid();

   /* close file handles */
   if ( (fd = open("/dev/null", O_RDWR)) >= 0 ) {
      dup2(fd, 0);
      dup2(fd, 1);
      dup2(fd, 2);
      if ( fd > 2 ) {
         close(fd);
      }
   }

   if ( pidfile ) {
      return create_pid_file(pidpath, pidfile);
   }

   return SUCCESS;
}

static int go_daemon() {
    return daemonize(NULL);
}

static void usage(const char *program_name) {
    fprintf(stdout, "\n");
    fprintf(stdout, "USAGE: %s [-options]\n", program_name);
    fprintf(stdout, "\n");
    fprintf(stdout, " General Options:\n");
    fprintf(stdout, "  -?             You're reading it.\n");
    fprintf(stdout, "  -v             Verbose output.\n");
//    fprintf(stdout, "  -V            Version and compiled in options.\n");
    fprintf(stdout, "  -i <iface>     Interface to sniff from.\n");
    fprintf(stdout, "  -f <format>    Output format line. See Format options.\n");
    fprintf(stdout, "  -b <bfp>       Berkley packet filter.\n");
    fprintf(stdout, "  -d <dir>       Directory to write session files to.\n");
    fprintf(stdout, "  -D             Enable daemon mode.\n");
    fprintf(stdout, "  -u <user>      User to drop priveleges to after daemonising.\n");
    fprintf(stdout, "  -g <group>     Group to drop priveleges to after daemonising.\n");
    fprintf(stdout, "  -T <dir>       Direct to chroot into.\n");
    fprintf(stdout, "  -P <path>      Path to PID file (/var/run).\n");
    fprintf(stdout, "  -p <file>      Name of pidfile (cxtracker.pid).\n");
    fprintf(stdout, "  -r <pcap>      PCAP file to read.\n");
    fprintf(stdout, "  -w <name>      Dump PCAP to file with specified prefix.\n");
    fprintf(stdout, "  -F             Flush output after every write to dump file.\n");
    fprintf(stdout, "  -s <bytes>     Roll over dump file based on size.\n");
    fprintf(stdout, "  -t <interval>  Roll over dump file based on time intervals.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, " Long Options:\n");
    fprintf(stdout, "  --help         Same as '?'\n");
//    fprintf(stdout, "  --version     Same as 'V'\n");
    fprintf(stdout, "  --interface    Same as 'i'\n");
    fprintf(stdout, "  --format       Same as 'f'\n");
    fprintf(stdout, "  --bpf          Same as 'b'\n");
    fprintf(stdout, "  --log-dir      Same as 'd'\n");
    fprintf(stdout, "  --daemonize    Same as 'D'\n");
    fprintf(stdout, "  --user         Same as 'u'\n");
    fprintf(stdout, "  --group        Same as 'g'\n");
    fprintf(stdout, "  --chroot-dir   Same as 'T'\n");
    fprintf(stdout, "  --pid-file     Same as 'p'\n");
    fprintf(stdout, "  --pcap-file    Same as 'r'\n");
    fprintf(stdout, "\n");
    format_options();
 }

int main(int argc, char *argv[]) {

   int ch, fromfile, setfilter, version, drop_privs_flag, daemon_flag, chroot_flag;
   struct bpf_program cfilter;
   char *bpff, errbuf[PCAP_ERRBUF_SIZE];
   extern char *optarg;
   char roll_metric = 0;
   char roll_type = GIGABYTES;
   size_t roll_point = 2;
   roll_size = roll_point * GIGABYTE;

   int long_option_index = 0;
   static struct option long_options[] = {
     {"help", 0, NULL, '?'},
     {"interface", 1, NULL, 'i'},
     {"format", 1, NULL, 'f'},
     {"bpf", 1, NULL, 'b'},
     {"log-dir", 1, NULL, 'd'},
     {"daemonize", 0, NULL, 'D'},
     {"user", 1, NULL, 'u'},
     {"group", 1, NULL, 'g'},
     {"chroot-dir", 1, NULL, 'T'},
     {"pid-file", 1, NULL, 'p'},
     {"pcap-file", 1, NULL, 'r'},
     {0, 0, 0, 0}
   };


   bpf_u_int32 net_mask = 0;
   ch = fromfile = setfilter = version = drop_privs_flag = daemon_flag = 0;
   dev = "eth0";
   bpff = "";
   chroot_dir = "/tmp/";
   output_format = "sguil";
   cxtbuffer = NULL;
   cxtrackerid  = 0;
   dump_with_flush = inpacket = intr_flag = chroot_flag = 0;
   mode = 0;

   signal(SIGTERM, game_over);
   signal(SIGINT,  game_over);
   signal(SIGQUIT, game_over);
   signal(SIGHUP,  dump_active);
   signal(SIGALRM, set_end_sessions);

   while( (ch=getopt_long(argc, argv, "?b:d:DT:f:g:i:p:P:r:u:vw:s:t:", long_options, &long_option_index)) != EOF )
     switch (ch) {
      case 'i':
         dev = strdup(optarg);
         mode |= MODE_DEV;
         break;
      case 'b':
         bpff = strdup(optarg);
         break;
      case 'v':
         verbose = 1;
         break;
      case 'f':
         output_format = strdup(optarg);
         break;
      case 'd':
         snprintf(dpath, STDBUF, "%s", optarg);

         // normalise the directory path to ensure it's slash terminated
         if( dpath[strlen(dpath)-1] != '/' )
            strncat(dpath, "/", STDBUF);
         break;
      case '?':
         usage(argv[0]);
         exit(0);
         break;
      case 'D':
         daemon_flag = 1;
         break;
      case 'T':
         chroot_flag = 1;
         break;
      case 'u':
         user_name = strdup(optarg);
         drop_privs_flag = 1;
         break;
      case 'g':
         group_name = strdup(optarg);
         drop_privs_flag = 1;
         break;
      case 'p':
         pidfile = strdup(optarg);
         break;
      case 'P':
         pidpath = strdup(optarg);
         break;
      case 'r':
         read_file = strdup(optarg);
         mode |= MODE_FILE;
         break;
      case 'w':
         dump_file_prefix = strdup(optarg);
         mode |= MODE_DUMP;
         break;
      case 'F':
         dump_with_flush = 1;
         break;
      case 's':
         sscanf(optarg, "%zu%c", &roll_point, &roll_metric);

         switch( tolower(roll_metric) ) {
            case 'k':
               roll_size = roll_point * KILOBYTE;
               roll_type = KILOBYTES;
               break;
            case 'm':
               roll_size = roll_point * MEGABYTE;
               roll_type = MEGABYTES;
               break;
            case 'g':
               roll_size = roll_point * GIGABYTE;
               roll_type = GIGABYTES;
               break;
            case 't':
               roll_size = roll_point * TERABYTE;
               roll_type = TERABYTES;
               break;
            default:
               printf("[*] Invalid size metric: %c\n", roll_metric ? roll_metric : '-');
               break;
         }

         break;
      case 't':
         sscanf(optarg, "%zu%c", &roll_point, &roll_metric);

         switch( tolower(roll_metric) ) {
            case 's':
               roll_time = roll_point;
               roll_type = SECONDS;
               break;
            case 'm':
               roll_time = roll_point * 60;
               roll_type = MINUTES;
               break;
            case 'h':
               roll_time = roll_point * 60 * 60;
               roll_type = HOURS;
               break;
            case 'd':
               roll_time = roll_point * 60 * 60 * 24;
               roll_type = DAYS;
               break;
            default:
               printf("[*] Invalid size metric: %c\n", roll_metric ? roll_metric : '-');
               break;
         }

         break;
      default:
         exit(1);
         break;
   }

   errbuf[0] = '\0';

   // validate the output format string
   format_validate(output_format);

   // specify reading from a device OR a file and not both
   if ( (mode & MODE_DEV) && (mode & MODE_FILE) )
   {
      printf("[!] You must specify a device OR file to read from, not both.\n");
      usage(argv[0]);
      exit(1);
   }
   else if ( (mode & MODE_FILE) && read_file) {
      /* Read from PCAP file specified by '-r' switch. */
      printf("[*] Reading from file %s", read_file);
      if (!(handle = pcap_open_offline(read_file, errbuf))) {
         printf("\n");
         printf("[*] Unable to open %s. (%s)\n", read_file, errbuf);
         exit(1);
      } else {
         printf(" - OK\n");
      }

      // in pcap_open_offline(), libpcap appears to use a static buffer
      // for reading in the file. we must use memcpy's to ensure data
      // persists as expected
      if ( ip_init(&ip_config, IP_SET_MEMCPY) )
      {
        printf("[!] Unable to initialise the IP library.\n");
        exit(1);
      }
      else
        printf("[*] IP library using \"memcpy\" set.\n");
   }
   else if ( (mode & MODE_DEV) && dev) {
      if (getuid()) {
         printf("[*] You must be root..\n");
         exit(1);
      }

      printf("[*] Running cxtracker %s\n",VERSION);

      //errbuf[0] = '\0';
      /* look up an availible device if non specified */
      if (dev == 0x0) dev = pcap_lookupdev(errbuf);
      printf("[*] Device: %s\n", dev);

      if ((handle = pcap_open_live(dev, SNAPLENGTH, 1, 500, errbuf)) == NULL) {
         printf("[*] Error pcap_open_live: %s \n", errbuf);
         pcap_close(handle);
         exit(1);
      }

      // in pcap_open_live(), libpcap maintains a heap allocated buffer
      // for reading off the wire. we can use pointer copies here for 
      // improved speed
      if ( ip_init(&ip_config, IP_SET_MEMCPY) )
      {
        printf("[*] Unable to initialise the IP library.\n");
        exit(1);
      }
      else
        printf("[*] IP library using \"memcpy\" set.\n");

      if ( chroot_flag == 1 ) {
         set_chroot();
      }

      if(daemon_flag) {
         if(!is_valid_path(pidpath))
            printf("[*] PID path \"%s\" is bad, check privilege.",pidpath);
            openlog("cxtracker", LOG_PID | LOG_CONS, LOG_DAEMON);
            printf("[*] Daemonizing...\n\n");
            go_daemon();
      }
   }
   else
   {
      printf("[*] You must specify where to read from.\n");
      exit(1);
   }

   if ((pcap_compile(handle, &cfilter, bpff, 1 ,net_mask)) == -1) {
      printf("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(handle));
      pcap_close(handle);
      exit(1);
   }

   if (pcap_setfilter(handle, &cfilter)) {
      printf("[*] Unable to set pcap filter!  (%s)\n", pcap_geterr(handle));
   } else {
      pcap_freecode(&cfilter); // filter code not needed after setfilter
   }

   // set up dump mode now as appropriate
   if (mode & MODE_DUMP ) {
      printf("[*] Writing traffic to %s%s.*, rolling every %d %s\n",
          dpath, dump_file_prefix, (int)roll_point, rollover_names[(int)roll_type]);
      dump_file_open();
   }

   /* B0rk if we see an error... */
   if (strlen(errbuf) > 0) {
      printf("[*] Error errbuf: %s \n", errbuf);
      pcap_close(handle);
      exit(1);
   }

   if(drop_privs_flag) {
      printf("[*] Dropping privs...\n\n");
      drop_privs();
   }

   bucket_keys_NULL();

   alarm(TIMEOUT);
   if (read_file) {
      printf("[*] Reading packets...\n");
   } else {
      printf("[*] Sniffing...\n");
   }

   roll_time_last = time(NULL);
   pcap_loop(handle,-1,got_packet,NULL);

   game_over();
   return(0);
}
