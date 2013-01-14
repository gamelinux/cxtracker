#!/usr/bin/perl -w
#
# Copyright (C) 2010 - 2013, Edward Fjellskål <edward.fjellskaal@gmail.com>
# Copyright (C) 2011 - 2013, Ian Firns <firnsy@securixlive.com>
#
# This file is a part of cxtracker: https://github.com/gamelinux/cxtracker
#
use strict;
use warnings;
use POSIX qw(setsid);
use DateTime;
use Getopt::Long qw/:config auto_version auto_help/;
use Sys::Hostname;
use DBI;

=head1 NAME

cxtracker2db.pl - Load session metadata from cxtracker into a db

=head1 VERSION

0.2

=head1 SYNOPSIS

 $ cxtracker2db.pl [options]

 OPTIONS:

 --dir          : set the dir to monitor for session files
 --daemon       : enables daemon mode
 --hostname     : spesify the hostname
 --debug        : enable debug messages (default: 0 (disabled))
 --help         : this help message
 --version      : show cxtracker2db.pl version
 --format       : "indexed" or "standard" pcap and database format?

=cut

our $VERSION       = 0.2;
our $DEBUG         = 0;
our $DAEMON        = 0;
our $FORMAT        = "any";
our $INPUTFORMAT   = 0;
our $TIMEOUT       = 5;
our $HOSTNAME      = hostname;
my  $SDIR          = "";
my  $FDIR          = "";
my  $LOGFILE       = q(/var/log/cxtracker2db.log);
my  $PIDFILE       = q(/var/run/cxtracker2db.pid);
our $DB_NAME       = "cxtracker";
our $DB_HOST       = "127.0.0.1";
our $DB_PORT       = "3306";
our $DB_USERNAME   = "cxtracker";
our $DB_PASSWORD   = "cxtracker";
our $DBI           = "DBI:mysql:$DB_NAME:$DB_HOST:$DB_PORT";
our $AUTOCOMMIT    = 0;
my $SANCP_DB       = {};

GetOptions(
   'dir=s'         => \$SDIR,
   'hostname=s'    => \$HOSTNAME,
   'debug=s'       => \$DEBUG,
   'daemon'        => \$DAEMON,
   'format=s'      => \$FORMAT
);

if ($SDIR eq "") {
   $SDIR = "/nsm_data/$HOSTNAME/session/";
   $FDIR = "$SDIR/failed";
} else {
   $FDIR = "$SDIR/failed";
}

check_dir($SDIR);
check_dir($FDIR);

# Signal handlers
use vars qw(%sources);
$SIG{"HUP"}   = \&recreate_view_table;
$SIG{"INT"}   = sub { game_over() };
$SIG{"TERM"}  = sub { game_over() };
$SIG{"QUIT"}  = sub { game_over() };
$SIG{"KILL"}  = sub { game_over() };
#$SIG{"ALRM"}  = sub { dir_watch(); alarm $TIMEOUT; };

warn "[*] Starting cxtracker2db.pl...\n";

# Prepare to meet the world of Daemons
if ( $DAEMON ) {
   print "[*] Daemonizing...\n";
   chdir ("/") or die "chdir /: $!\n";
   open (STDIN, "/dev/null") or die "open /dev/null: $!\n";
   open (STDOUT, "> $LOGFILE") or die "open > $LOGFILE: $!\n";
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

warn "[*] Connecting to database...\n";
my $dbh = DBI->connect($DBI,$DB_USERNAME,$DB_PASSWORD, {RaiseError => 1, mysql_auto_reconnect=>1}) or die "$DBI::errstr";
# Make todays table, and initialize the session view table
setup_db();

# Start dir_watch() which looks for new session files and put them into db
warn "[*] Looking for session data in: $SDIR \n" if $DEBUG;
dir_watch();
exit;

=head1 FUNCTIONS

=head2 dir_watch

 This sub looks for new session data in a dir.
 Takes $dir to watch as input.

=cut

sub dir_watch {
   #infinite loop
   while (1) {
      my @FILES;
      # Open the directory
      if( opendir( DIR, $SDIR ) ) {
         # Find session files in dir (stats.eth0.1229062136)
         while( my $FILE = readdir( DIR ) ) {
            next if( ( "." eq $FILE ) || ( ".." eq $FILE ) );
            next unless ($FILE =~ /^stats\..*\.\d{10}$/);
            push( @FILES, $FILE ) if( -f "$SDIR$FILE" );
         }
         closedir( DIR );
      }
      foreach my $FILE ( @FILES ) {
         my $result = get_session ("$SDIR$FILE");
         if ($result == 1) {
            rename ("$SDIR$FILE", "$FDIR$FILE") or warn "[*] Couldn't move $SDIR$FILE to $FDIR$FILE: $!\n";
         }
         unlink("$SDIR$FILE") if $result == 0; 
      }
      # Dont pool files to often, or to seldom...
      sleep $TIMEOUT;                    
   }   
}

=head2 get_session

 This sub extracts the session data from a session data file.
 Takes $file as input parameter.

=cut

sub get_session {
   my $SFILE = shift;
   my $result = 0;
   my %signatures;
   if (open (FILE, $SFILE)) {
      print "[*] Found session file: ".$SFILE."\n" if $DEBUG;
      # Verify the data in the session files
      LINE:
      while (my $line = readline FILE) {
         chomp $line;
         $line =~ /^\d{19}/;
         unless($line) {
            warn "[*] Error: Not valid session start format in: '$SFILE'";
            next LINE;
         }
         my @elements = split/\|/,$line;
         if (@elements == 15) {
            if ($FORMAT eq "indexed") {
             warn "[*] Error: Not valid Nr. of session args for format: '$FORMAT' in: '$SFILE'";
             next LINE;
            } elsif ($INPUTFORMAT == 0) {
               $INPUTFORMAT = 1;
               if ($FORMAT eq "any") {
                  #the user gave us no guidance on format
                  #we are now getting guidance from the
                  #input file for the first time
                  #construct the db accordingly
                  #as it had previously been waiting on this.
                  $FORMAT = "standard";
                  setup_db();
               }
            }
         } elsif (@elements == 20) {
            if ($FORMAT eq "standard") {
               if($INPUTFORMAT == 0) {
                  $INPUTFORMAT = 2;
               }
               #warn "[*] Reading indexed input as standard in: '$SFILE'";
            } elsif ($INPUTFORMAT == 0) {
               $INPUTFORMAT = 2;
               if ($FORMAT eq "any") {
                  #the user gave us no guidance on format
                  #we are now getting guidance from the
                  #input file for the first time
                  #construct the db accordingly
                  #as it had previously been waiting on this.
                  my $tablename = get_table_name();
                  my $tableformat = check_table_format($tablename);
                  #check if we need to roll indexed or standard
                  if($tableformat == 1) {
                     $FORMAT = "standard";
                  } else {
                     $FORMAT = "indexed";
                  }
                  #$FORMAT = "indexed";
                  setup_db();
               }
            }
         } else {
            warn "[*] Error: Not valid Nr. of session args format in: '$SFILE'";
            next LINE;
         }
         # Things should be OK now to send to the DB
         $result = put_session2db($line);
      }
      close FILE;
   }
   return $result;
}

=head2 ip_is_ipv6

 Check if an IP address is version 6
 returns 1 if true, 0 if false

=cut

sub ip_is_ipv6 {
    my $ip = shift;

    # Count octets
    my $n = ($ip =~ tr/:/:/);
    return (0) unless ($n > 0 and $n < 8);

    # $k is a counter
    my $k;

    foreach (split /:/, $ip) {
        $k++;

        # Empty octet ?
        next if ($_ eq '');

        # Normal v6 octet ?
        next if (/^[a-f\d]{1,4}$/i);

        # Last octet - is it IPv4 ?
        if ($k == $n + 1) {
            next if (ip_is_ipv4($_));
        }

        print "[*] Invalid IP address $ip";
        return 0;
    }

    # Does the IP address start with : ?
    if ($ip =~ m/^:[^:]/) {
        print "[*] Invalid address $ip (starts with :)";
        return 0;
    }

    # Does the IP address finish with : ?
    if ($ip =~ m/[^:]:$/) {
        print "[*] Invalid address $ip (ends with :)";
        return 0;
    }

    # Does the IP address have more than one '::' pattern ?
    if ($ip =~ s/:(?=:)//g > 1) {
        print "[*] Invalid address $ip (More than one :: pattern)";
        return 0;
    }

    return 1;
}

=head2 expand_ipv6

 Expands a IPv6 address from short notation

=cut

sub expand_ipv6 {

   my $ip = shift;

   # Keep track of ::
   $ip =~ s/::/:!:/;

   # IP as an array
   my @ip = split /:/, $ip;

   # Number of octets
   my $num = scalar(@ip);

   # Now deal with '::' ('000!')
   foreach (0 .. (scalar(@ip) - 1)) {

      # Find the pattern
      next unless ($ip[$_] eq '!');

      # @empty is the IP address 0
      my @empty = map { $_ = '0' x 4 } (0 .. 7);

      # Replace :: with $num '0000' octets
      $ip[$_] = join ':', @empty[ 0 .. 8 - $num ];
      last;
   }

   # Now deal with octets where there are less then 4 enteries
   my @ip_long = split /:/, (lc(join ':', @ip));
   foreach (0 .. (scalar(@ip_long) -1 )) {

      # Next if we have our 4 enteries
      next if ( $ip_long[$_] =~ /^[a-f\d]{4}$/ );

      # Push '0' until we match
      while (!($ip_long[$_] =~ /[a-f\d]{4,}/)) {
         $ip_long[$_] =~ s/^/0/;
      }
   }

   return (lc(join ':', @ip_long));
}

=head2 sanitize_table_name

 Takes a string and makes it MySQL table friendly...

=cut

sub sanitize_table_name {
   my $string = shift;
   $string =~ s/[^A-Za-z_]/_/g;
   return $string;
}

=head2 put_session2db

 takes a session line as input and stores it in DB

=cut

sub put_session2db {
   my $SESSION = shift;
   my $tablename = get_table_name();
   my $ip_version = 2; # AF_INET

   # Check if table exists, if not create and make new session view table
   if ( ! checkif_table_exist($tablename) ) {
      new_session_table($tablename);
      recreate_view_table();
   }

  my( $cx_id, $s_t, $e_t, $tot_time, $ip_type, $src_dip, $src_port,
       $dst_dip, $dst_port, $src_packets, $src_byte, $dst_packets, $dst_byte, 
       $src_flags, $dst_flags, $ip_versionb, $s_file, $s_byte, 
       $e_file, $e_byte) = split /\|/, $SESSION, 20;

  if ( ip_is_ipv6($src_dip) || ip_is_ipv6($dst_dip) ) {
      $src_dip = expand_ipv6($src_dip);
      $dst_dip = expand_ipv6($dst_dip);
      $src_dip = "INET_ATON6(\'$src_dip\')";
      $dst_dip = "INET_ATON6(\'$dst_dip\')";
      $ip_version = 10; # AF_INET6
  } else {
     if ($INPUTFORMAT == 2) {
       $src_dip = "INET_ATON(\'$src_dip\')";
       $dst_dip = "INET_ATON(\'$dst_dip\')";
     }
  }

   my ($sql, $sth);

   if ($FORMAT eq "standard") {
      eval{
   
         $sql = qq[                                                 
                INSERT INTO $tablename (                           
                   sid,sessionid,start_time,end_time,duration,ip_proto, 
                   src_ip,src_port,dst_ip,dst_port,src_pkts,src_bytes,
                   dst_pkts,dst_bytes,src_flags,dst_flags,ip_version
                ) VALUES (                                         
                   '$HOSTNAME','$cx_id','$s_t','$e_t','$tot_time',
                   '$ip_type',$src_dip,'$src_port',$dst_dip,'$dst_port',
                   '$src_packets','$src_byte','$dst_packets','$dst_byte',
                   '$src_flags','$dst_flags','$ip_version'
                )];
   
         $sth = $dbh->prepare($sql);
         $sth->execute;
         $sth->finish;
      };
   }

   if ($FORMAT eq "indexed") {
      eval{
   
         $sql = qq[                                                 
                INSERT INTO $tablename (                           
                   sid,sessionid,start_time,end_time,duration,ip_proto, 
                   src_ip,src_port,dst_ip,dst_port,src_pkts,src_bytes,
                   dst_pkts,dst_bytes,src_flags,dst_flags,ip_version,
                   s_file,s_byte,e_file,e_byte
                ) VALUES (                                         
                   '$HOSTNAME','$cx_id','$s_t','$e_t','$tot_time',
                   '$ip_type',$src_dip,'$src_port',$dst_dip,'$dst_port',
                   '$src_packets','$src_byte','$dst_packets','$dst_byte',
                   '$src_flags','$dst_flags','$ip_version','$s_file',
                   '$s_byte','$e_file','$e_byte'
                )];
   
         $sth = $dbh->prepare($sql);
         $sth->execute;
         $sth->finish;
      };
   }

   if ($@) {
      # Failed
      return 1;
   }
   return 0;
}

=head2 setup_db

 Create todays table if it dont exist (session_hostname_date).
 Make a new view of all session_% tables.

=cut

sub setup_db {
   my $tablename = get_table_name();                   #
   my $tableformat = check_table_format($tablename);
   print "[*] tableformat: $tableformat\n" if $DEBUG;
   my $sessiontables = find_session_tables();              #
   print "[*] session tables: $sessiontables\n" if $DEBUG;
   if ($sessiontables) {      
       if(($tableformat == 2) && ($FORMAT eq "standard")) {
           die("[E] ERROR: Database Format mismatch!\n");
        }
        if(($tableformat == 1) && ($FORMAT eq "indexed")) {
           die("[E] ERROR: Database format mismatch!\n");
        }
        if(($tableformat == 0) && ($FORMAT eq "any")) {
           if ($INPUTFORMAT == 0) {
               #there's neither input nor argument
               #to specify what kind.
               #and therefor no harm in waiting.
               return;
           }
           if ($INPUTFORMAT == 1) {
               $FORMAT = "standard";
           }
           if ($INPUTFORMAT == 2) {
               $FORMAT = "indexed";
           }
       }
   }

   new_session_table($tablename);
   delete_viewed_session_table();
   $sessiontables = find_session_tables();
   print "[*] session tables2: $sessiontables\n" if $DEBUG;
   view_session_tables($sessiontables);
   return;
}

=head2 check_table_format

 Checks to see if table is indexed.  Returns 1 if table is standard, 
 2 if table is indexed, 0 if table does not exist.

=cut

sub check_table_format {
   my ($tablename) = shift;
   my $tableformat = 0;    

   if(checkif_table_exist($tablename)) {
       my ($sql, $sth);
#      $sql = "SHOW COLUMNS FROM $tablename LIKE 's_file'";
       $sql = "SELECT * FROM $tablename WHERE 1=0";
       $sth = $dbh->prepare($sql);
       $sth->execute;
#      my $tester = $sth->{'NAME'};
       my $cols = @{$sth->{NAME}}; # or NAME_lc if needed 
       print "[*] cols = $cols\n" if $DEBUG;       
#      print "\n tester = $tester \n";
       if($cols == 21) {
           $tableformat = 2;
       }
       else {
           $tableformat = 1;
       }
   }
   return $tableformat;
}

=head2 new_session_table

 Creates a new session_$hostname_$date table
 Takes $hostname and $date as input.

=cut

sub new_session_table {
   my ($tablename) = shift;
   my ($sql, $sth);

   return 0 if ($FORMAT eq "any");

   if ($FORMAT eq "standard") {
       $sql = "                                               \
         CREATE TABLE IF NOT EXISTS $tablename              \
         (                                                  \
         sid           INT(10) UNSIGNED           NOT NULL, \
         sessionid     BIGINT(20) UNSIGNED        NOT NULL, \
         start_time    DATETIME                   NOT NULL, \
         end_time      DATETIME                   NOT NULL, \
         duration      INT(10) UNSIGNED           NOT NULL, \
         ip_proto      TINYINT UNSIGNED           NOT NULL, \
         src_ip        DECIMAL(39,0) UNSIGNED,              \
         src_port      SMALLINT UNSIGNED,                   \
         dst_ip        DECIMAL(39,0) UNSIGNED,              \
         dst_port      SMALLINT UNSIGNED,                   \
         src_pkts      INT UNSIGNED               NOT NULL, \
         src_bytes     INT UNSIGNED               NOT NULL, \
         dst_pkts      INT UNSIGNED               NOT NULL, \
         dst_bytes     INT UNSIGNED               NOT NULL, \
         src_flags     TINYINT UNSIGNED           NOT NULL, \
         dst_flags     TINYINT UNSIGNED           NOT NULL, \
         ip_version    TINYINT UNSIGNED           NOT NULL, \
         PRIMARY KEY (sid,sessionid),                       \
         INDEX src_ip (src_ip),                             \
         INDEX dst_ip (dst_ip),                             \
         INDEX dst_port (dst_port),                         \
         INDEX src_port (src_port),                         \
         INDEX start_time (start_time)                      \
         ) ENGINE=InnoDB                                    \
      ";
   }

   if ($FORMAT eq "indexed") {
      $sql = "                                                \
         CREATE TABLE IF NOT EXISTS $tablename              \
         (                                                  \
         sid           INT(10) UNSIGNED           NOT NULL, \
         sessionid     BIGINT(20) UNSIGNED        NOT NULL, \
         start_time    DATETIME                   NOT NULL, \
         end_time      DATETIME                   NOT NULL, \
         duration      INT(10) UNSIGNED           NOT NULL, \
         ip_proto      TINYINT UNSIGNED           NOT NULL, \
         src_ip        DECIMAL(39,0) UNSIGNED,              \
         src_port      SMALLINT UNSIGNED,                   \
         dst_ip        DECIMAL(39,0) UNSIGNED,              \
         dst_port      SMALLINT UNSIGNED,                   \
         src_pkts      INT UNSIGNED               NOT NULL, \
         src_bytes     INT UNSIGNED               NOT NULL, \
         dst_pkts      INT UNSIGNED               NOT NULL, \
         dst_bytes     INT UNSIGNED               NOT NULL, \
         src_flags     TINYINT UNSIGNED           NOT NULL, \
         dst_flags     TINYINT UNSIGNED           NOT NULL, \
         ip_version    TINYINT UNSIGNED           NOT NULL, \
         s_file        VARCHAR(15)                NOT NULL, \
         s_byte        BIGINT UNSIGNED            NOT NULL, \
         e_file        VARCHAR(15)                NOT NULL, \
         e_byte        BIGINT UNSIGNED            NOT NULL, \
         PRIMARY KEY (sid,sessionid),                       \
         INDEX src_ip (src_ip),                             \
         INDEX dst_ip (dst_ip),                             \
         INDEX dst_port (dst_port),                         \
         INDEX src_port (src_port),                         \
         INDEX start_time (start_time)                      \
         ) ENGINE=InnoDB                                    \
      ";
   }

   eval{
      $sth = $dbh->prepare($sql);
      $sth->execute;
      $sth->finish;
   };

   if ($@) {
      # Failed
      return 1;
   }
   return 0;
}

=head2 find_session_tables
 
 Find all session_% tables

=cut

sub find_session_tables {
   my ($sql, $sth);
   my $tables = q();
   $sql = q(SHOW TABLES LIKE 'session_%');
   $sth = $dbh->prepare($sql);
   $sth->execute;
   while (my @array = $sth->fetchrow_array) {
      my $table = $array[0];
      $tables = "$tables $table,";
   }
   $sth->finish;
   $tables =~ s/,$//;
   return $tables;
}

=head2 delete_viewed_session_table

 Deletes the session viewed table if it exists.

=cut

sub delete_viewed_session_table {
   my ($sql, $sth);
   eval{
      $sql = "DROP VIEW IF EXISTS session";
      $sth = $dbh->prepare($sql);
      $sth->execute;
      $sth->finish;
   };     
   if ($@) {
      # Failed
      warn "[*] Drop viewed session table failed...\n" if $DEBUG;
      return 1;
   }
   warn "[*] Dropped viewed session table...\n" if $DEBUG;
   return 0;
}

=head2 view_session_tables

 Creates a new session view table

=cut

sub view_session_tables {
   my $tables = shift;
   print "[*] tables: $tables\n" if $DEBUG;
   my ($sql, $sth);

   if ($FORMAT eq "standard") {
       eval {
       warn "[*] Creating session VIEW\n" if $DEBUG;
         my $sql = "                                              \
         CREATE VIEW session AS SELECT                            \
         sid,sessionid,start_time,end_time,duration,ip_proto,     \
         src_ip,src_port,dst_ip,dst_port,src_pkts,src_bytes,      \
         dst_pkts,dst_bytes,src_flags,dst_flags,ip_version        \
         FROM $tables                                             \
         ";
         $sth = $dbh->prepare($sql);
         $sth->execute;
         $sth->finish;
      };
   }

   if ($FORMAT eq "indexed") {
       eval {
       warn "[*] Creating session VIEW\n" if $DEBUG;
         my $sql = "                                              \
         CREATE VIEW session AS SELECT                            \
         sid,sessionid,start_time,end_time,duration,ip_proto,     \
         src_ip,src_port,dst_ip,dst_port,src_pkts,src_bytes,      \
         dst_pkts,dst_bytes,src_flags,dst_flags,ip_version,       \
         s_file,s_byte,e_file,e_byte                              \
         FROM $tables                                             \
         ";
         $sth = $dbh->prepare($sql);
         $sth->execute;
         $sth->finish;
      };
   }
   if ($@) {
      # Failed
      warn "[*] Create session VIEW table failed!\n" if $DEBUG;
      return 1;
   }
   return 0;
}

=head2 get_table_name

 makes a table name, format: session_$HOSTNAME_$DATE

=cut

sub get_table_name {
   my $DATE = `date --iso`;
   $DATE =~ s/\-//g;
   $DATE =~ s/\n$//;
   my $tablename = "session_" . sanitize_table_name($HOSTNAME) . "_" . "$DATE";
   return $tablename;
}

=head2 checkif_table_exist

 Checks if a table exists. Takes $tablename as input and
 returns 1 if $tablename exists, and 0 if not.

=cut

sub checkif_table_exist {
    my $tablename = shift;
    my ($sql, $sth);
    eval { 
       $sql = "select count(*) from $tablename where 1=0";
       $dbh->do($sql);
    };
    if ($dbh->err) {
       warn "Table $tablename does not exist.\n" if $DEBUG;
       return 0;
    }
    else{
       return 1;
    }
}

=head2 recreate_view_table

 Recreates the view table.

=cut

sub recreate_view_table {
   my $sessiontables = find_session_tables();
   delete_viewed_session_table();
   view_session_tables($sessiontables);
}

=head2

 Checks sanity of Dirs

=cut

sub check_dir {
   my $DIR = shift;
   if (-e $DIR) {
      print "[*] The directory $DIR exists.\n" if $DEBUG;
   } else {
      print "[E] ERROR: The directory $DIR does not exist!\n";
      exit 1;
   }
   if (-r $DIR) {
      print "[*] The directory $DIR is readable.\n" if $DEBUG;
   } else {
      print "[E] ERROR: The directory $DIR is not readable!\n";
      exit 1;
   }
   if (-w $DIR) {
      print "[*] The directory $DIR is writable.\n" if $DEBUG;
   } else {
      print "[E] ERROR: The directory $DIR is not writable!\n";
      exit 1;
   }
}

=head2 game_over

 Terminates the program in a sainfull way.

=cut

sub game_over {
    warn "[*] Terminating...\n";
    $dbh->disconnect;
    unlink ($PIDFILE);
    exit 0;
}

=head1 AUTHOR

 Edward Fjellskaal

=head1 COPYRIGHT

 This library is free software, you can redistribute it and/or modify
 it under the same terms as Perl itself.

=cut
