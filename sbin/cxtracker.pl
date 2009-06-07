#!/usr/bin/perl -w

use strict;
use warnings;
use Data::Dumper;
use Net::Pcap;
use FindBin;
use Getopt::Long qw/:config auto_version auto_help/;
use constant ETH_TYPE_IP        => 0x0800;
use constant SYNACK             => 0x12;

BEGIN {

    # list of NetPacket:: modules
    my @modules = map { "NetPacket::$_" } qw/Ethernet IP ARP ICMP TCP UDP/;
    my $bundle  = 0;

    MODULE:
    for my $module (@modules) {

        # try to use installed version first
        eval "use $module";
        next MODULE unless($@);

        if($ENV{'DEBUG'}) {
            warn "$module is not installed. Using bundled version instead\n";
        }

        # use bundled version instead
        local @INC = ("$FindBin::Bin/../lib");
        eval "use $module";
        die $@ if($@);
        $bundle++;
    }

    if($ENV{'DEBUG'} and $bundle) {
        warn "Run this command to install missing modules:\n";
        warn "\$ perl -MCPAN -e'install NetPacket'\n";
    }
}

=head1 NAME

cxtracker.pl - inspired by Huginn

=head1 VERSION

0.1

=head1 SYNOPSIS

 $ cxtracker.pl [options]

 OPTIONS:

 --dev|-d       : network device (default: eth0)
 --debug        : enable debug messages (default: 0 (disabled))
 --help         : this help message
 --version      : show cxtracker.pl version

=cut

our $VERSION       = 0.1;
our $DEBUG         = 0;
our $TIMEOUT       = 5;
my $DEVICE         = q(wlan0);
my $session        = {};
#$LOGFILE           = $conf->{log_file}              || $LOGFILE;
#$PIDFILE           = $conf->{pid_file}              || $PIDFILE;
$LOGFILE           = q(/var/log/cxtracker.log)
$PIDFILE           = q(/var/run/cxtracker.pid)
my %ERROR          = (
    lookup_net     => q(Unable to look up device information for %s - %s),
    create_object  => q(Unable to create packet capture on device %s - %s),
    compile_object => q(Unable to compile packet capture filter),
    loop           => q(Unable to perform packet capture),
);

GetOptions(
    'dev|d=s'       => \$DEVICE,
    'debug=s'         => \$DEBUG,
);

# Signal handlers
use vars qw(%sources);
$SIG{"HUP"}   = \&dump_active_sessions;
$SIG{"INT"}   = sub { game_over() };
$SIG{"TERM"}  = sub { game_over() };
$SIG{"QUIT"}  = sub { game_over() };
$SIG{"KILL"}  = sub { game_over() };
$SIG{"ALRM"}  = sub { end_sessions(); alarm $TIMEOUT; };
alarm $TIMEOUT;

warn "Starting cxtracker.pl...\n";

warn "Creating object\n" if $DEBUG;
my $PCAP = create_object($DEVICE);

warn "Compiling Berkeley Packet Filter\n" if $DEBUG;
filter_object($PCAP);

# Preparing stats
my %info = ();
my %stats = ();
Net::Pcap::stats ($PCAP, \%stats);
$stats{timestamp} = time;
$stats{tot_sessions} = $stats{tcp_sessions} = $stats{udp_sessions} = $stats{icmp_sessions} = $stats{other_sessions} = 0;

print "src_ip, src_port, dst_ip, dst_port, ip_type, src_byte, src_packets, dst_byte, dst_packets, src_flags, dst_flags, start_timestamp, last_timestamp, tot_time\n" if $DEBUG >0;

# Prepare to meet the Daemon
if ( $DAEMON ) {
        print "Daemonizing...\n";
        chdir ("/") or die "chdir /: $!\n";
        open (STDIN, "/dev/null") or die "open /dev/null: $!\n";
        open (STDOUT, "> $LOGFILE") or die "open > /dev/null: $!\n";
        defined (my $dpid = fork) or die "fork: $!\n";
        if ($dpid) {
                # Write PID file
                open (PID, "> $PIDFILE") or die "open($PIDFILE): $!\n";
                print PID $dpid, "\n";
                close (PID);
                exit 0;
        }
        setsid ();
        open (STDERR, ">&STDOUT");
}

warn "Looping over object\n" if $DEBUG;
Net::Pcap::loop($PCAP, -1, \&packet, '') or die $ERROR{'loop'};

exit;

=head1 FUNCTIONS

=head2 packet

 Callback function for C<Net::Pcap::loop>.

 * Strip ethernet encapsulation of captured packet 
 * Decode contents of IP packet contained within captured ethernet packet
 * Checks for ip->{proto} and extracts the nessesary data for tracking 
   the IP session.

=cut

sub packet {
    my ($user_data, $header, $packet) = @_;
    my $tstamp   = time;
    my $eth      = NetPacket::Ethernet->decode($packet); 

    # Check if IP ( also ETH_TYPE_IPv6 ?)
    if ( $eth->{type} == ETH_TYPE_IP){
        # We should now have us an IP packet... good!
        my $ethernet = NetPacket::Ethernet::strip($packet);
        my $ip       = NetPacket::IP->decode($ethernet);
        my $src_ip   = $ip->{'src_ip'};
        my $dst_ip   = $ip->{'dest_ip'};
        my $length   = $ip->{'len'} - $ip->{'hlen'};
        my $tcpflags = 0;

        # We need for key:
        # $src_ip:$src_port:$dst_ip:$dst_port
        # We need for stats:
        # ip_type, src_byte/dst_byte, src_packets/dst_packet, timestamps

        # Check if this is a TCP packet
        if($ip->{proto} == 6) {
            # Collect necessary info from TCP packet
            my $tcp      = NetPacket::TCP->decode($ip->{'data'});
            my $src_port = $tcp->{'src_port'};
            my $dst_port = $tcp->{'dest_port'};
            $tcpflags    = $tcp->{'flags'};
            session_tracking($src_ip, $src_port, $dst_ip, $dst_port, $ip->{proto}, $length, $tcpflags, $tstamp);
        }
        # Check if this is a UDP packet
        elsif ($ip->{proto} == 17) {
            # Collect necessary info from UDP packet
            my $udp       = NetPacket::UDP->decode($ip->{'data'});
            my $src_port  = $udp->{'src_port'};
            my $dst_port  = $udp->{'dest_port'};
            session_tracking($src_ip, $src_port, $dst_ip, $dst_port, $ip->{proto}, $length, $tcpflags, $tstamp);
        }
        # Check if this is a ICMP packet
        elsif($ip->{proto} == 1) {
            # NetPacket::ICMP is missing id and sequence field. Extract id to use as port
            my $icmp       = NetPacket::ICMP->decode($ip->{'data'});
            my ($id, $data) = unpack("na*", $icmp->{'data'});
            my $src_port  = $id;
            my $dst_port  = $id;
            session_tracking($src_ip, $src_port, $dst_ip, $dst_port, $ip->{proto}, $length, $tcpflags, $tstamp);
        }else{
            my $src_port  = my $dst_port = $ip->{proto};
            session_tracking($src_ip, $src_port, $dst_ip, $dst_port, $ip->{proto}, $length, $tcpflags, $tstamp);
        }
        return;
    }
}

=head2

 This modules takes the relevant info from an IP(TCP,UDP or ICMP) packet
 and tries to track it on packets, bytes, tcpflags and time.

=cut

sub session_tracking {
    my ($src_ip, $src_port, $dst_ip, $dst_port, $type, $length, $tcpflags, $tstamp) = @_;

    # Update initial src
    if ($session->{"$type:$src_ip:$src_port:$dst_ip:$dst_port"}) {
        $session->{"$type:$src_ip:$src_port:$dst_ip:$dst_port"}{src_flags}      |= $tcpflags;
        $session->{"$type:$src_ip:$src_port:$dst_ip:$dst_port"}{src_byte}        = +$length;
        $session->{"$type:$src_ip:$src_port:$dst_ip:$dst_port"}{src_packets}    += 1;
        $session->{"$type:$src_ip:$src_port:$dst_ip:$dst_port"}{last_timestamp}  = $tstamp;
        print "Updateing: $type:$src_ip:$src_port:$dst_ip:$dst_port\n" if $DEBUG > 2;
    }
    # Update inital dst
    elsif ($session->{"$type:$dst_ip:$dst_port:$src_ip:$src_port"}) {
        $session->{"$type:$dst_ip:$dst_port:$src_ip:$src_port"}{dst_flags}      |= $tcpflags;
        $session->{"$type:$dst_ip:$dst_port:$src_ip:$src_port"}{dst_byte}        = +$length;
        $session->{"$type:$dst_ip:$dst_port:$src_ip:$src_port"}{dst_packets}    += 1;
        $session->{"$type:$dst_ip:$dst_port:$src_ip:$src_port"}{last_timestamp}  = $tstamp;
        print "Updateing: $type:$dst_ip:$dst_port:$src_ip:$src_port\n" if $DEBUG > 2;
    }
    # Then this has to be a new connection...
    else {
        print "New      : $type:$src_ip:$src_port:$dst_ip:$dst_port\n" if $DEBUG>0;
        add_session_stat($type);
        $session->{"$type:$src_ip:$src_port:$dst_ip:$dst_port"} = {
                     ip_type         => $type,
                     src_ip          => $src_ip,
                     src_port        => $src_port,
                     dst_ip          => $dst_ip,
                     dst_port        => $dst_port,
                     src_byte        => $length,
                     src_packets     => '1',
                     dst_byte        => '0',
                     dst_packets     => '0',
                     src_flags       => $tcpflags,
                     dst_flags       => 0x00,
                     start_timestamp => $tstamp,
                     last_timestamp  => $tstamp,
                     };
    }
    return;
}

=head2 end_sessions

 This sub marks sessions as ENDED on different criterias:

 Default TCP initial timeout 	               10 seconds
 Default TCP ongoing timeout 	                2 hours
 TCP timeout after RST received either way 	5 seconds
 TCP timeout after ACK after FIN each way 	5 seconds
 TCP timeout after ICMP error 	                5 seconds
 Default UDP initial timeout 	               60 seconds
 Default UDP ongoing timeout 	               10 seconds
 UDP timeout after ICMP error 	               10 seconds
 Default ICMP initial timeout 	               10 seconds
 Default ICMP ongoing timeout 	               60 seconds
 ICMP timeout after ICMP error 	               10 seconds
 Default other initial timeout 	              100 seconds
 Default other ongoing timeout 	              100 minutes

=cut

sub end_sessions {
    my $now = time;
    while ( my ($key, $values) = each(%$session) ) {
    print "Checking : $key\n" if $DEBUG > 1;
        # TCP
        if ($session->{$key}{ip_type} == 6 ) {
           # FIN from both sides
           if ($session->{"$key"}{src_flags} & FIN && $session->{"$key"}{dst_flags} & FIN ) {
               export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 5 ;
           }
           # RST from eather side
           elsif ($session->{"$key"}{src_flags} & RST || $session->{"$key"}{dst_flags} & RST ) {
               export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 5 ;
           }
           # if not a TCP 3-way handshake complete
           elsif ( !($session->{"$key"}{src_flags} & SYNACK) || !($session->{"$key"}{dst_flags} & SYNACK) ) {
               export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 10 ;
           }
           # Ongoing timout
           elsif ($session->{"$key"}{src_flags} & SYNACK && $session->{"$key"}{dst_flags} & SYNACK ) {
               export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 120 ;
           }
           return;
        }
        # UDP
        elsif ($session->{"$key"}{ip_type} == 17 ) {
            if ( !$session->{"$key"}{dst_packets} > 0 ) {
                export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 10 ;
            }else{
                export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 60 ;
            }
            return;
        }
        # ICMP
        elsif ($session->{"$key"}{ip_type} == 1 ) {
            if ( !$session->{"$key"}{dst_packets} > 0 ) {
                export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 10 ;
            }else{
                export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 60 ;
            }
            return;
        }
        # ALL OTHER IP->{TYPE}
        else { 
            if ( !$session->{"$key"}{dst_packets} > 0 ) {
                export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 100 ;
            }else{
                export_session($key,1) if ($now - $session->{"$key"}{last_timestamp}) > 600 ;
            }
            return;
        }
        return;
    }
}

=head2 export_session

 Prints out the ended sessions or status of active sessions.
 Takes %$session of sessions as input along with $delete.
 If $delete is 1, the session gets removed from %$session.
 If $delete is 0, the session is not removed from %$session.

=cut

sub export_session {
    my ($key, $delete) = @_;
    my $tot_time = $session->{$key}{last_timestamp} - $session->{$key}{start_timestamp};
    # Put session to log/db
    # For now - print STDOUT. And later make it all in one print statement!
    # * To have it work with sguil - the file name should be stats.$DEVICE.time; Output format in file should be:
    #   CNX-ID| ISO START TIME | ISO END TIME |tot_time|ip_type|src_ip|src_port|dst_ip|dst_port|src_packets|src_byte|dst_packets|dst_byte|src_flags|dst_flags 
    # Format:
    # src_ip,src_port,dst_ip,dst_port,ip_type,src_byte,src_packets,dst_byte,dst_packets,src_flags,dst_flags,start_timestamp,last_timestamp,tot_time
    print "Ending   : " if ($DEBUG > 1 && $delete == 1);
    print "Status   : " if ($DEBUG > 1 && $delete == 0);
    print "$session->{$key}{src_ip}, ";
    print "$session->{$key}{src_port}, ";
    print "$session->{$key}{dst_ip}, ";
    print "$session->{$key}{dst_port}, ";
    print "$session->{$key}{ip_type}, ";
    print "$session->{$key}{src_byte}, ";
    print "$session->{$key}{src_packets}, ";
    print "$session->{$key}{dst_byte}, ";
    print "$session->{$key}{dst_packets}, ";
    print "$session->{$key}{src_flags}, ";
    print "$session->{$key}{dst_flags}, ";
    print "$session->{$key}{start_timestamp}, ";
    print "$session->{$key}{last_timestamp}, ";
    print "$tot_time\n";
    delete $session->{$key} if $delete;
    return;
}

=head2 dump_stats

 Prints out statistics.

=cut

sub dump_stats {
    my %d = %info;
    my %ds = %stats;
    Net::Pcap::stats ($PCAP, \%stats);
    $stats{"timestamp"} = time;
    my $droprate = 0;
    $droprate = ( ($stats{ps_drop} * 100) / $stats{ps_recv}) if $stats{ps_recv} > 0;
    print "\n $stats{timestamp} Stats:\n";
    print " [Packets received:$stats{ps_recv}]  [Packets dropped:$stats{ps_drop}] [Droprate:$droprate%]  [Packets dropped by interface:$stats{ps_ifdrop}]\n";
    print " [Total IP Sessions: $stats{tot_sessions}] [TCP Sessions: $stats{tcp_sessions}] [UDP Sessions: $stats{udp_sessions}] [ICMP Sessions: $stats{icmp_sessions}] [Other Sessions: $stats{other_sessions}]\n";
}

=head2 dump_active_sessions

 Dumps all active sessions/connections in $%sessions

=cut

sub dump_active_sessions {
    my $total = scalar(keys(%$session));
    print "\nDumping $total active sessions:\n" if $DEBUG > 2;
    while ( my ($key, $values) = each(%$session) ) {
        export_session($key,0);
    }
}

=head2 lookup_net

 Look up network address information about network 
 device using Net::Pcap::lookupnet - This also acts as a 
 check on bogus network device arguments that may be 
 passed to the program as an argument

=cut

sub lookup_net {
    my $dev = shift;
    my($err, $address, $netmask);

    Net::Pcap::lookupnet(
        $dev, \$address, \$netmask, \$err
    ) and die sprintf $ERROR{'lookup_net'}, $dev, $err;

    warn "lookup_net : $address, $netmask\n" if($DEBUG);
    return $address, $netmask;
}

=head2 create_object

 Create packet capture object on device

=cut

sub create_object {
    my $dev = shift;
    my($err, $object);
    my $promisc = 1;    

    $object = Net::Pcap::open_live($dev, 1500, $promisc, 0, \$err)
              or die sprintf $ERROR{'create_object'}, $dev, $err;
    warn "create_object : $dev\n" if($DEBUG);
    return $object;
}

=head2 compile_object

 Compile and set packet filter for packet capture object.

=cut

sub filter_object {
    my $object = shift;
    my $netmask = q(0);
    my $filter;
    my $BPF = q(ip);

    Net::Pcap::compile(
        $object, \$filter, $BPF, 0, $netmask
    ) and die $ERROR{'compile_object_compile'};

    Net::Pcap::setfilter($object, $filter)
        and die $ERROR{'compile_object_setfilter'};
    warn "filter_object : $netmask, $filter\n" if($DEBUG);
}


=head2 add_session_stat

 Updates sessions stats. Input is ip type.

=cut

sub add_session_stat {
    my $type = shift;
    $stats{"tot_sessions"}       += 1;
    if ($type == 6) {
        $stats{"tcp_sessions"}   += 1;
    }
    elsif ($type == 17) {
        $stats{"udp_sessions"}   += 1;
    }
    elsif ($type == 1) {
        $stats{"icmp_sessions"}   += 1;
    }
    else{
        $stats{"other_sessions"} += 1;
    }
}

=head2 game_over

 Terminates the program in a sainfull way.

=cut

sub game_over {
    dump_active_sessions();
    dump_stats();
    warn " Closing device: $DEVICE\n";
    Net::Pcap::close($PCAP);
    exit 0;
}

=head1 AUTHOR

 Edward Fjellskaal

=head1 COPYRIGHT

 This library is free software, you can redistribute it and/or modify
 it under the same terms as Perl itself.

=cut
