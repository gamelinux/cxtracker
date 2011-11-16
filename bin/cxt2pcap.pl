#!/usr/bin/perl -w
# ----------------------------------------------------------------------
# cxt2pcap.pl - Carve a session from a cxtracker indexed pcap
#
# Copyright (C) 2010-2011, Edward Fjellskål <edwardfjellskaal@gmail.com>
#                          Ian Firns        <firnsy@securixlive.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# ----------------------------------------------------------------------

use strict;
use warnings;
use Getopt::Long qw/:config auto_version auto_help/;

=head1 NAME

 cxt2pcap.pl - Carve a session from a cxtracker indexed pcap

=head1 VERSION

0.0.1

=head1 SYNOPSIS

 $ cxt2pcap.pl [options]

 OPTIONS:

 -r                : pcap file too read from
 -w                : pcap file to write too
 --proto           : protocol
 --src-ip          : Source IP
 --dst-ip          : Destination IP
 --src-port        : Source Port
 --dst-port        : Destination Port
 -s                : Byteoffset on where to start carving
 -e                : Byteoffset on where to end carving
 -v|--verbose      : Verbose output
 -d|--debug        : Enables debug output

 EXAMPLES:

 cxt2pcap.pl -r /tmp/big.pcap -s 1238374 -e 1833344 --src-ip 10.0.0.1 --src-port 1031 --dst-ip 10.0.0.5 --dst-port 80 --proto 6 -w /tmp/mysession.pcap

=cut

my $DEBUG             = 1;
my $VERBOSE           = 1;

my ($R_PCAP, $W_PCAP, $BPF, $BS, $BE, $FH_PCAP) = qq();
my ($SRC_IP, $DST_IP, $SRC_PORT, $DST_PORT, $PROTO) = qq();
use constant SEEK_SET  => 0;
use constant SEEK_CUR  => 1;
use constant SEEK_END  => 2;

# commandline overrides config & defaults
Getopt::Long::GetOptions(
    'r=s'                    => \$R_PCAP,
    'w=s'                    => \$W_PCAP,
    'proto=s'                => \$PROTO,
    'src-ip=s'               => \$SRC_IP,
    'dst-ip=s'               => \$DST_IP,
    'src-port=s'             => \$SRC_PORT,
    'dst-port=s'             => \$DST_PORT,
    's=s'                    => \$BS,
    'e=s'                    => \$BE,
    'v|verbose'              => \$VERBOSE,
    'd|debug'                => \$DEBUG,
);

print "[*] cxt2pcap starting...\n" if ($VERBOSE||$DEBUG);

if ( -e $R_PCAP ) {
   print "[*] Opening $R_PCAP\n" if ($VERBOSE||$DEBUG);
   open(RFILE,$R_PCAP) || die ("[E] Failed to open: $R_PCAP !");
   binmode RFILE;
   seek(RFILE,0,SEEK_SET);
   read(RFILE,$FH_PCAP,24);
}

if( ! -f $W_PCAP || ! -s $W_PCAP ){
   print "[*] Opening > $W_PCAP\n" if ($VERBOSE||$DEBUG);
   open(WFILE,">$W_PCAP") || die ("[E] Unable to open file $W_PCAP");
   binmode WFILE;
}else{
   #print "Opening >> $W_PCAP\n" if ($VERBOSE||$DEBUG);
   #open(WFILE,">>$W_PCAP") || die("[E] Unable to open file $W_PCAP");
   #binmode WFILE;
   die("[E] Unable to open file $W_PCAP");
}

# SET
seek(RFILE,$BS,SEEK_SET);
sysseek(WFILE,0,SEEK_END);

my $BUFFER = qq();
my $PLENGTH = $BE - $BS;

#READ+FILTER
my $pktHdrFormat = checkFileHdr($FH_PCAP);
while (!eof(RFILE)) {
  my $PKTBUFFER = qq();
  my $pktHdr;

  read(RFILE, $pktHdr, 16);
  print "[D] Read 16 bytes...\n" if $DEBUG;
  my ($pktSecond,$pktMicroSecond,$capturedPktLen,$actualPktLen) = unpack($pktHdrFormat, $pktHdr);
  #print "$pktSecond,$pktMicroSecond,$capturedPktLen,$actualPktLen\n";
  if (my $rl = read(RFILE, $PKTBUFFER, $capturedPktLen) != $capturedPktLen ) {
     print "[W] Failed to read pkt data: $capturedPktLen/$rl:$!\n";
     last;
  }
  my $tproto = unpack("C", substr($PKTBUFFER, 23,1));
  print "$tproto\n";
  if ($tproto == 6 && $PROTO == 6) {
     $BUFFER .= "$pktHdr$PKTBUFFER" if processTCPPkt($PKTBUFFER);
  } elsif ($tproto == 17 && $PROTO == 17) {
     $BUFFER .= $pktHdr . $PKTBUFFER if processUDPPkt($PKTBUFFER);
  } elsif ($tproto == 1 && $PROTO == 1) {
     $BUFFER .= $pktHdr . $PKTBUFFER if processICMPPkt($PKTBUFFER);
  }
  if (tell RFILE > $BE) {
     print "[*] Last byte position in READ reached ($BE)\n" if ($VERBOSE||$DEBUG);
     last;
  }
}

print "[*] " . tell RFILE; print " > $BE\n" if ($VERBOSE||$DEBUG);

# WRITE
my $BUFFLENGTH=length($BUFFER);
print "[D] Writing session to $W_PCAP ($BUFFLENGTH Bytes)\n" if ($VERBOSE||$DEBUG);
syswrite(WFILE,"$FH_PCAP",24);
syswrite(WFILE,$BUFFER,$BUFFLENGTH) || die ("[E] Failed to write session to $W_PCAP!");

# END
close(RFILE);
close(WFILE);

sub checkFileHdr {
   my $fHdr = shift;
   my $signature = unpack("N", substr($fHdr,0,4));
   if ($signature == 0xa1b2c3d4) {
      return "NNNN";
   } elsif ($signature == 0xd4c3b2a1) {
      return "VVVV";
   } else {
      die "[E] Unknown PCAP Header Format!";
   }
}

sub processTCPPkt {
   my $pktBuf   = shift;
   my $srcip    = substr($pktBuf, 26,4);
   my $dstip    = substr($pktBuf, 30,4);
   my $srcport  = substr($pktBuf, 34,2);
   my $dstport  = substr($pktBuf, 36,2);
   my $binstr = "$srcip$srcport$dstip$dstport";
   printSession ($binstr);
   my @B = unpack("C*", $binstr);
   $srcip = "$B[0].$B[1].$B[2].$B[3]";
   $dstip = "$B[6].$B[7].$B[8].$B[9]";
   $srcport = $B[4]*256+$B[5];
   $dstport = $B[10]*256+$B[11];
   if (( $srcip eq $SRC_IP && $dstip eq $DST_IP ) || ( $srcip eq $DST_IP && $dstip eq $SRC_IP )) {
      if (( $srcport eq $SRC_PORT && $dstport eq $DST_PORT ) || ( $srcport eq $DST_PORT && $dstport eq $SRC_PORT )) {
         print "[D] Got matching TCP packet\n" if $DEBUG;
         return 1;
      }
   }
   return 0;
}

sub processUDPPkt {
   # Work in progress
   my $pktBuf   = shift;
   my $srcip    = substr($pktBuf, 26,4);
   my $dstip    = substr($pktBuf, 30,4);

   if (( $srcip eq $SRC_IP && $dstip eq $DST_IP ) || ( $srcip eq $DST_IP && $dstip eq $SRC_IP )) {
      return 1;
   }
   return 0;
}

sub processICMPPkt {
   # Work in progress
   my $pktBuf   = shift;
   my $srcip    = substr($pktBuf, 26,4);
   my $dstip    = substr($pktBuf, 30,4);

   if (( $srcip eq $SRC_IP && $dstip eq $DST_IP ) || ( $srcip eq $DST_IP && $dstip eq $SRC_IP )) {
      return 1;
   }
   return 0;
}

sub printSession {
   my $session = shift;
   my @B = unpack("C*", $session);
   printf "%d.%d.%d.%d:%d --> %d.%d.%d.%d:%d\n",
      $B[0], $B[1],$B[2],$B[3], $B[4]*256+$B[5], $B[6],$B[7],$B[8],$B[9], $B[10]*256+$B[11];
}
