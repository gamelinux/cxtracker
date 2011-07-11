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

#include "format.h"

#include <string.h>
#include <time.h>


/*
 * Structure for custom output formats
 */
typedef struct _format_s {
    void                (*func)(FILE *, const struct _connection *, const char *);
    char                *prefix;
    struct _format_s    *next;
} format_t;

format_t     *custom = NULL;

void format_function_append(format_t **head, void (*func)(FILE *, const struct _connection *, char *), char *prefix);
void format_write_cxid(FILE *fd, const connection *cxt, const char *prefix);
void format_write_time_start(FILE *fd, const connection *cxt, const char *prefix);
void format_write_time_end(FILE *fd, const connection *cxt, const char *prefix);
void format_write_time_duration(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_protocol(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_family(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_source(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_source_hex(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_source_numeric(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_destination(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_destination_hex(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_destination_numeric(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_port_source(FILE *fd, const connection *cxt, const char *prefix);
void format_write_ip_port_destination(FILE *fd, const connection *cxt, const char *prefix);
void format_write_packets_source(FILE *fd, const connection *cxt, const char *prefix);
void format_write_packets_destination(FILE *fd, const connection *cxt, const char *prefix);
void format_write_bytes_source(FILE *fd, const connection *cxt, const char *prefix);
void format_write_bytes_destination(FILE *fd, const connection *cxt, const char *prefix);
void format_write_tcp_flags_source(FILE *fd, const connection *cxt, const char *prefix);
void format_write_tcp_flags_destination(FILE *fd, const connection *cxt, const char *prefix);
void format_write_pcap_offset_start(FILE *fd, const connection *cxt, const char *prefix);
void format_write_pcap_offset_end(FILE *fd, const connection *cxt, const char *prefix);
void format_write_custom(FILE *fd, const connection *cxt, const char *prefix);

void format_options()
{
    fprintf(stdout, " Format Options:\n");
    fprintf(stdout, "  %%cxd          unique cxtracker ID\n");
    fprintf(stdout, "  %%stm          start time [unix timestamp])\n");
    fprintf(stdout, "  %%etm          end time [unix timestamp]\n");
    fprintf(stdout, "  %%dur          duration [seconds]\n");
    fprintf(stdout, "  %%ver          IP family\n");
    fprintf(stdout, "  %%pro          protocol\n");
    fprintf(stdout, "  %%sin          source IP [IPv4 = integer, IPv6 = literal]\n");
    fprintf(stdout, "  %%sip          source IP [IPv4/IPv6 = literal]\n");
    fprintf(stdout, "  %%six          source IP [IPv4/IPv6 = hex\n");
    fprintf(stdout, "  %%din          destination IP [IPv4 = integer, IPv6 = literal]\n");
    fprintf(stdout, "  %%dip          destination IP [IPv4/IPv6 = literal]\n");
    fprintf(stdout, "  %%dix          destination IP [IPv4/IPv6 = hex\n");
    fprintf(stdout, "  %%spt          source port\n");
    fprintf(stdout, "  %%dpt          destination port\n");
    fprintf(stdout, "  %%spk          total packets sent from the source IP during the session\n");
    fprintf(stdout, "  %%dpk          total packets sent from the destination IP during the session\n");
    fprintf(stdout, "  %%sby          total bytes send from the source IP during the session\n");
    fprintf(stdout, "  %%dby          total bytes send from the destination IP during the session\n");
    fprintf(stdout, "  %%sfl          cumulative source IP TCP flags sent during the session\n");
    fprintf(stdout, "  %%dfl          cumulative destination IP TCP flags sent during the session\n");
    fprintf(stdout, "  %%spo          pcap file offset of start packet in session\n");
    fprintf(stdout, "  %%epo          pcap file offset of first byte after last packet in session\n");
}

void format_validate(const char *format)
{
  /*
  */

    const char *fp_s = format;
    const char *fp_e = format;
    void (*func)(FILE *, const struct _connection *, char *) = NULL;
    int match = 0;

    int format_length = strlen(format);

    while ( (fp_e-format) < format_length )
    {
        // check if it's time to match
        if ( strncmp(fp_e, "%", 1) == 0 )
        {
            if ( strncmp(fp_e, "%cxd", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_cxid;
            }
            else if ( strncmp(fp_e, "%stm", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_time_start;
            }
            else if ( strncmp(fp_e, "%etm", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_time_end;
            }
            else if ( strncmp(fp_e, "%dur", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_time_duration;
            }
            else if ( strncmp(fp_e, "%ver", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_family;
            }
            else if ( strncmp(fp_e, "%pro", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_protocol;
            }
            else if ( strncmp(fp_e, "%sin", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_source_numeric;
            }
            else if ( strncmp(fp_e, "%sip", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_source;
            }
            else if ( strncmp(fp_e, "%six", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_source_hex;
            }
            else if ( strncmp(fp_e, "%din", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_destination_numeric;
            }
            else if ( strncmp(fp_e, "%dip", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_destination;
            }
            else if ( strncmp(fp_e, "%dix", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_destination_hex;
            }
            else if ( strncmp(fp_e, "%spt", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_port_source;
            }
            else if ( strncmp(fp_e, "%dpt", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_ip_port_destination;
            }
            else if ( strncmp(fp_e, "%spk", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_packets_source;
            }
            else if ( strncmp(fp_e, "%dpk", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_packets_destination;
            }
            else if ( strncmp(fp_e, "%sby", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_bytes_source;
            }
            else if ( strncmp(fp_e, "%dby", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_bytes_destination;
            }
            else if ( strncmp(fp_e, "%sfl", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_tcp_flags_source;
            }
            else if ( strncmp(fp_e, "%dfl", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_tcp_flags_destination;
            }
            else if ( strncmp(fp_e, "%spo", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_pcap_offset_start;
            }
            else if ( strncmp(fp_e, "%epo", 4) == 0 )
            {
                match = 4;
                func = (void *)&format_write_pcap_offset_end;
            }
        }

        if ( match > 0 )
        {
            char *prefix = NULL;

            // check if we have prefix
            if ( fp_e > fp_s )
            {
                prefix = malloc(sizeof(char) * (fp_e - fp_s + 1));
                if ( NULL == prefix )
                {
                    fprintf(stderr, "FATAL: Unable to allocate memory for the custom formatter!\n");
                    exit(1);
                }

                strncpy(prefix, fp_s, fp_e-fp_s);
            }
            else
                prefix = strdup("");

            fp_e += match;
            fp_s = fp_e;

            format_function_append(&custom, func, prefix);

            match = 0;
        }
        else
            fp_e++;
    }

    // check if we have prefix
    if ( fp_e > fp_s )
    {
        char *prefix = malloc(sizeof(char) * (fp_e - fp_s + 1));
        if ( NULL == prefix )
        {
            fprintf(stderr, "FATAL: Unable to allocate memory for the custom formatter!\n");
            exit(1);
        }

        strncpy(prefix, fp_s, fp_e-fp_s);

        format_function_append(&custom, (void *)&format_write_custom, prefix);
    }
}

void format_function_append(format_t **head, void (*func)(FILE *, const struct _connection *, char *), char *prefix)
{
    format_t *iter = *head;
    format_t *item;


    item = malloc(sizeof(format_t));

    if ( NULL == item )
    {
        fprintf(stderr, "FATAL: Unable to allocate memory for the custom formatter!\n");
        exit(1);
    }

    item->func = (void *)func;
    item->prefix = prefix;


    if ( NULL == iter )
    {
        *head = item;
    }
    else
    {
        while (NULL != iter->next)
            iter = iter->next;

        iter->next = item;
    }
}

void format_write(FILE *fd, const connection *cxt)
{
    const format_t *iter = custom;

    // run through our custom format table
    while (iter != NULL)
    {
        iter->func(fd, cxt, iter->prefix);
        iter = iter->next;
    }

    // finish off the line
    fprintf(fd, "\n");
}


//
// DEDICATED FORMAT FUNCTIONS
//

void format_write_cxid(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%ld%09ju", prefix, cxt->start_time, cxt->cxid);
}

void format_write_time_start(FILE *fd, const connection *cxt, const char *prefix)
{
    char t[80];

    strftime(t, 80, "%F %H:%M:%S", gmtime(&cxt->start_time));
    fprintf(fd, "%s%s", prefix, t);
}

void format_write_time_end(FILE *fd, const connection *cxt, const char *prefix)
{
    char t[80];

    strftime(t, 80, "%F %H:%M:%S", gmtime(&cxt->last_pkt_time));
    fprintf(fd, "%s%s", prefix, t);
}

void format_write_time_duration(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%ld", prefix, cxt->last_pkt_time - cxt->start_time);
}

void format_write_ip_family(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%d", prefix, ip_family_get(&cxt->s_ip));
}

void format_write_ip_protocol(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%u", prefix, cxt->proto);
}

void format_write_ip_source_numeric(FILE *fd, const connection *cxt, const char *prefix)
{
    char ip_s[IP_ADDRMAX];

    if ( ip_ntop(&cxt->s_ip, ip_s, IP_ADDRMAX, IP_NUMERIC_DEC) )
        perror("Something died in ip_ntop for src");

    fprintf(fd, "%s%s", prefix, ip_s);
}

void format_write_ip_source(FILE *fd, const connection *cxt, const char *prefix)
{
    char ip_s[IP_ADDRMAX];

    if ( ip_ntop(&cxt->s_ip, ip_s, IP_ADDRMAX, 0) )
        perror("Something died in ip_ntop for src");

    fprintf(fd, "%s%s", prefix, ip_s);
}

void format_write_ip_source_hex(FILE *fd, const connection *cxt, const char *prefix)
{
    char ip_s[IP_ADDRMAX];

    if ( ip_ntop(&cxt->s_ip, ip_s, IP_ADDRMAX, IP_NUMERIC_HEX) )
        perror("Something died in ip_ntop for src");

    fprintf(fd, "%s%s", prefix, ip_s);
}

void format_write_ip_destination_numeric(FILE *fd, const connection *cxt, const char *prefix)
{
    char ip_s[IP_ADDRMAX];

    if ( ip_ntop(&cxt->d_ip, ip_s, IP_ADDRMAX, IP_NUMERIC_DEC) )
        perror("Something died in ip_ntop for dest");

    fprintf(fd, "%s%s", prefix, ip_s);
}

void format_write_ip_destination(FILE *fd, const connection *cxt, const char *prefix)
{
    char ip_s[IP_ADDRMAX];

    if ( ip_ntop(&cxt->d_ip, ip_s, IP_ADDRMAX, 0) )
        perror("Something died in ip_ntop for dest");

    fprintf(fd, "%s%s", prefix, ip_s);
}

void format_write_ip_destination_hex(FILE *fd, const connection *cxt, const char *prefix)
{
    char ip_s[IP_ADDRMAX];

    if ( ip_ntop(&cxt->d_ip, ip_s, IP_ADDRMAX, IP_NUMERIC_HEX) )
        perror("Something died in ip_ntop for dest");

    fprintf(fd, "%s%s", prefix, ip_s);
}

void format_write_ip_port_source(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%u", prefix, ntohs(cxt->s_port));
}

void format_write_ip_port_destination(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%u", prefix, ntohs(cxt->d_port));
}

void format_write_packets_source(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%ju", prefix, cxt->s_total_pkts);
}

void format_write_packets_destination(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%ju", prefix, cxt->d_total_pkts);
}

void format_write_bytes_source(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%ju", prefix, cxt->s_total_bytes);
}

void format_write_bytes_destination(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%ju", prefix, cxt->d_total_bytes);
}

void format_write_tcp_flags_source(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd,"%s%u", prefix, cxt->s_tcpFlags);
}

void format_write_tcp_flags_destination(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd,"%s%u", prefix, cxt->d_tcpFlags);
}

void format_write_pcap_offset_start(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%lld", prefix, (long long int)cxt->start_offset);
}

void format_write_pcap_offset_end(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s%lld", prefix, (long long int)cxt->start_offset);
}

void format_write_custom(FILE *fd, const connection *cxt, const char *prefix)
{
    fprintf(fd, "%s", prefix);
}

void format_clear()
{
    format_t *iter = custom;

    // clean up our custom formatter
    while (NULL != iter)
    {
        if ( iter->prefix )
            free(iter->prefix);

        custom = iter;

        iter = iter->next;

        free(custom);
    }
}
