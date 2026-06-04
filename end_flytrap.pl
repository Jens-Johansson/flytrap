#!/usr/bin/perl
# ============================================================
# end_flytrap.pl  
#
# Disarm the flytrap and ban the bots
#
# * Reads the access log for 404 traffic that accumulated
#   while the trap was armed.
#
# * Finds the top N offenders above the hit threshold.
#
# * Updates .htaccess with new + renewed IP bans, expires
#   old bans past the retention window.
#
# * Renames the directory back so the forum is live again.
#
# Cron:  10 */6 * * *  /path/to/end_flytrap.pl
# [run 10 minuters after arming it; assuming 10 minute window]
# ============================================================

use strict;
use warnings;

use FindBin     qw($RealBin);
use Time::Local qw(timegm timelocal);
use POSIX       qw(strftime);

my $cfg = do "$RealBin/flytrap_config.pl";

# Shortcuts
my $FORUM_DIR             = $cfg->{FORUM_DIR};
my $ARMED_SUFFIX          = $cfg->{ARMED_SUFFIX};
my $SWAP_SUFFIX           = $cfg->{SWAP_SUFFIX};
my $ACCESS_LOG            = $cfg->{ACCESS_LOG};
my $LOG_FILE              = $cfg->{LOG_FILE};
my $TIMESTAMP_FILE        = $cfg->{TIMESTAMP_FILE};
my $FORUM_URL_PATH        = $cfg->{FORUM_URL_PATH};
my $TOP_OFFENDERS         = $cfg->{TOP_OFFENDERS};
my $HIT_THRESHOLD         = $cfg->{HIT_THRESHOLD};
my $CONSOLIDATE_MASK      = $cfg->{CONSOLIDATE_MASK};
my $CONSOLIDATE_THRESHOLD = $cfg->{CONSOLIDATE_THRESHOLD};
my $TRAP_WINDOW_MINS      = $cfg->{TRAP_WINDOW_MINS};
my $TRAP_LATENCY_MINS     = $cfg->{TRAP_LATENCY_MINS};
my $BAN_DURATION_DAYS     = $cfg->{BAN_DURATION_DAYS};
my $FLYTRAP_START         = $cfg->{FLYTRAP_START};
my $FLYTRAP_END           = $cfg->{FLYTRAP_END};

my $armed_dir = $FORUM_DIR . $ARMED_SUFFIX;
my $swap_dir = $FORUM_DIR . $SWAP_SUFFIX;
my $htaccess = "$armed_dir/.htaccess";

# Month name ? number (for Apache log timestamp parsing)
my %MON = (
  Jan=>0, Feb=>1, Mar=>2, Apr=>3, May=>4, Jun=>5,
  Jul=>6, Aug=>7, Sep=>8, Oct=>9, Nov=>10, Dec=>11
);

#
# Determine the trap window / when it was armed
#

my $armed_at;
if (open(my $fh, '<', $TIMESTAMP_FILE)) {
  chomp($armed_at = <$fh>);
  close($fh);
  $armed_at =~ s/\D//g;    # keep only digits
  log_msg("Trap was armed at epoch $armed_at (from timestamp file).");
}
if (!$armed_at || $armed_at !~ /^\d+$/) {
  # Fallback: assume the trap was armed TRAP_WINDOW_MINS ago
  $armed_at = time() - ($TRAP_WINDOW_MINS * 60);
  log_msg("WARNING: Timestamp file missing or unreadable, assuming trap window of $TRAP_WINDOW_MINS minutes.");
}

my $cutoff_epoch = $armed_at;   # only count log entries at/after this

$cutoff_epoch += $TRAP_LATENCY_MINS * 60;

log_msg("Narrowing the capture window by $TRAP_LATENCY_MINS minutes to exclude human traffic");

#
# Parse access log for 404 traffic in the trap window
#

log_msg("Parsing $ACCESS_LOG for 404s since epoch $cutoff_epoch ...");

my %ip_hits;
my $log_fh;

unless (open($log_fh, '<', $ACCESS_LOG)) {
  log_msg("ERROR: Cannot open $ACCESS_LOG: $!");
  exit 1;
}

while (my $line = <$log_fh>) {
  # Apache combined log format:
  # 1.2.3.4 - - [04/Jun/2026:14:30:00 -0700] "GET /path HTTP/1.1" 404 209 ...
  if ($line =~ m{
    ^(\S+)              # IP address
    \s+\S+\s+\S+\s+     # ident, authuser
    \[([^\]]+)\]        # [timestamp]
    \s+"(\S+)\s+(\S+)   # "METHOD path
    \s+[^"]*"           #  protocol"
    \s+(\d+)            # status code
  }x) {
    my ($ip, $ts_str, $method, $path, $status) = ($1, $2, $3, $4, $5);
  
    next unless $status eq '404';
  
    # Optional URL-path filter
    if ($FORUM_URL_PATH ne '' && index($path, $FORUM_URL_PATH) != 0) {
        next;
    }
  
    my $entry_epoch = parse_apache_ts($ts_str);
    next unless defined $entry_epoch;
    next unless $entry_epoch >= $cutoff_epoch;
  
    $ip_hits{$ip}++;
  }
}
close($log_fh);

log_msg("Found " . scalar(keys %ip_hits) . " distinct IPs with 404s in trap window.");

# 
# Find top offenders (the ones above threshold)
# 

my @offenders = sort { $ip_hits{$b} <=> $ip_hits{$a} }
                grep { $ip_hits{$_} >= $HIT_THRESHOLD }
                keys %ip_hits;

# Cap at TOP_OFFENDERS
if (@offenders > $TOP_OFFENDERS) {
  @offenders = @offenders[0 .. $TOP_OFFENDERS - 1];
}

if (@offenders) {
  log_msg("Above $HIT_THRESHOLD accesses and only the top $TOP_OFFENDERS, " .
        scalar(@offenders) . " unique IP addresses"); 
} else {
  log_msg("No IPs exceeded threshold of $HIT_THRESHOLD hits.");
}

#
# Consolidate offenders into CIDR blocks where possible
#

my %subnet_bucket;    # "1.2.3" => [ ip1, ip2, ... ]
my %is_consolidated;  # ip => 1  if absorbed into a CIDR rule

unless ($CONSOLIDATE_MASK == 24) {
  log_msg("ERROR: Have sadly only implemented consolidation for /24 nets");
  exit 1;    
}

# Group IPs by /24 prefix
for my $ip (@offenders) {
  my @octets = split /\./, $ip;
  my $prefix = join('.', @octets[0 .. 2]);   # first 3 octets for /24
  push @{ $subnet_bucket{$prefix} }, $ip;
}

my @consolidated_rules;  # CIDR entries to emit

for my $prefix (sort keys %subnet_bucket) {
  my $members = $subnet_bucket{$prefix};
  
  if (@$members >= $CONSOLIDATE_THRESHOLD) {
    # Whole /24 block is blocked  emit one CIDR rule
    my $cidr = "$prefix.0/$CONSOLIDATE_MASK";
    push @consolidated_rules, $cidr;
    log_msg("Consolidated " . scalar(@$members) . " IPs into $cidr");
    # Mark all member IPs as absorbed
    $is_consolidated{$_} = 1 for @$members;
  }
}

# Remaining individual IPs that weren't consolidated
my @individual_ips = grep { !$is_consolidated{$_} } @offenders;

#
# Read .htaccess
#

my $ht_content = '';

if (-f $htaccess) {
  open(my $fh, '<', $htaccess) or do {
      log_msg("ERROR: Cannot read $htaccess: $!");
      exit 1;
  };
  { local $/; $ht_content = <$fh>; }
  close($fh);
  # Normalise line endings
  $ht_content =~ s/\r\n?/\n/g;
  log_msg("Read .htaccess (" . length($ht_content) . " bytes).");
} else {
  log_msg("WARNING: $htaccess does not exist, will create a new one.");
}

#
# Extract existing FLYTRAP section & parse bans
#

my %bans;   # ip => epoch  (when the ban was added/renewed)

if ($ht_content =~ /\Q$FLYTRAP_START\E\n(.*?)\n\Q$FLYTRAP_END\E/s) {
  my $body = $1;
  # Each ban is stored as a pair of lines:
  #   # 2026-06-04T13:00:00 192.168.1.100       [ or 192.168.1.0/24   ! ]
  #   Require not ip 192.168.1.100
  # We extract timestamp + IP from the comment line.
  for my $ln (split /\n/, $body) {
    if ($ln =~ /^#\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+(\S+)/) {
        my ($ts_str, $ip) = ($1, $2);
        my $epoch = parse_iso_ts($ts_str);
        if (defined $epoch) {
            $bans{$ip} = $epoch;
        }
    }
  }
  log_msg("Parsed " . scalar(keys %bans) . " existing ban(s) from FLYTRAP section.");
} else {
  log_msg("No existing FLYTRAP section found, will create one.");
}

#
# Expire old bans and old IPs that may have been absorbed into CIDR rules above
#

my $expiry_epoch = time() - ($BAN_DURATION_DAYS * 86400);

for my $ip (keys %bans) {
  if ($bans{$ip} < $expiry_epoch) {
    log_msg("Expiring ban for $ip (since " . strftime("%Y-%m-%dT%H:%M:%S", localtime($bans{$ip})) . ")");
    delete $bans{$ip};
  }
}

for my $key (keys %bans) {
  next if $key =~ m{/};   # skip existing CIDR entries, only inspect plain IPs
  for my $cidr (@consolidated_rules) {
    if (ip_in_cidr($key, $cidr)) {
      log_msg("Absorbing $key into $cidr (was banned since " . strftime("%Y-%m-%dT%H:%M:%S", localtime($bans{$key})) . ")");
      delete $bans{$key};
      last;   # one CIDR match is enough
    }
  }
}

log_msg("After expiry / CIDR absorption sweep: " . scalar(keys %bans) . " ban(s) remain.");

#
# Merge in new offenders, with current timestamp
#

my $now = time();

#for my $ip (@offenders) {
for my $ip (@consolidated_rules, @individual_ips) {
  if (exists $bans{$ip}) {
    log_msg("Renewing ban for $ip (was " . strftime("%Y-%m-%dT%H:%M:%S", localtime($bans{$ip})) . ")");
  } else {
    log_msg("NEW ban for $ip");
  }
  $bans{$ip} = $now;   # stamp with current time
}

#
# Build the new FLYTRAP section w appropriate .htaccess directives
#

my $section = "$FLYTRAP_START\n";
$section   .= 
'<IfModule mod_setenvif.c>
  # Block user-agents matching patterns
  SetEnvIfNoCase User-Agent ".*bot.*" bad_bot
  SetEnvIfNoCase User-Agent ".*crawler.*" bad_bot
  SetEnvIfNoCase User-Agent ".*spider.*" bad_bot
</IfModule>
<RequireAll>
Require all granted
Require not env bad_bot
';

# Emit bans
for my $ip (sort { ip_sort_key($a) cmp ip_sort_key($b) } keys %bans) {
  my $ts = strftime("%Y-%m-%dT%H:%M:%S", localtime($bans{$ip}));
  $section .= "# $ts $ip\n";
  $section .= "Require not ip $ip\n";
}

$section .= "</RequireAll>\n";
$section .= "ErrorDocument 403 \"403\"\n";
$section .= $FLYTRAP_END;

#
# Splice the section into .htaccess
#

if ($ht_content =~ /\Q$FLYTRAP_START\E.*?\Q$FLYTRAP_END\E/s) {
  # Replace existing section
  $ht_content =~ s/\Q$FLYTRAP_START\E.*?\Q$FLYTRAP_END\E/$section/s;
} else {
  # No section yet  prepend at the very top of the file
  $ht_content = "$section\n\n$ht_content";
}

#
# Write back .htaccess atomically, via temp file
#

my $tmp = "$htaccess.tmp.$$";

open(my $wfh, '>', $tmp) or do {
  log_msg("ERROR: Cannot write $tmp: $!");
  exit 1;
};
print $wfh $ht_content;
close($wfh);

# Preserve original file permissions (if the file existed)
if (-f $htaccess) {
  my $mode = (stat($htaccess))[2] & 07777;
  chmod($mode, $tmp);
}

rename($tmp, $htaccess) or do {
  log_msg("ERROR: Cannot rename $tmp -> $htaccess: $!");
  unlink $tmp;
  exit 1;
};

log_msg("Wrote .htaccess with " . scalar(keys %bans) . " IP ban(s).");

#
# Disarm the trap (rename directory back)
#

if (-d $swap_dir) {
  log_msg("ERROR: $swap_dir already exists");
  exit 1;
} else {
  if (rename($FORUM_DIR, $swap_dir)) {
    log_msg("SWAPPED: $FORUM_DIR -> $swap_dir");
  } else {
    log_msg("ERROR: Cannot rename $FORUM_DIR -> $swap_dir: $!");
    exit 1;
  }
}

if (-d $armed_dir) {
  if (rename($armed_dir, $FORUM_DIR)) {
    log_msg("DISARMED: $armed_dir -> $FORUM_DIR  (forum is LIVE again)");
  } else {
    log_msg("ERROR: Cannot rename $armed_dir -> $FORUM_DIR: $!");
    exit 1;
  }
} else {
  if (-d $FORUM_DIR) {
    log_msg("WARNING: $armed_dir not found but $FORUM_DIR exists, inconsistent state, please check manually");
  } else {
    log_msg("ERROR: Neither $armed_dir nor $FORUM_DIR exists. Something is very wrong.");
    exit 1;
  }
}

#
# Get rid of the timestamp file, marking forum as running/ trap disarmed
#
unlink $TIMESTAMP_FILE;

#
# Some helper subs
#

# Parse Apache log timestamp into UTC epoch or undef
#   Eg "04/Jun/2026:14:30:00 -0700" bla bla bla
sub parse_apache_ts {
  my ($s) = @_;
  if ($s =~ m{(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})}) {
    my ($dd,$mon,$yyyy,$hh,$mm,$ss,$sign,$oh,$om) =
     ($1, $2,  $3,  $4, $5, $6, $7,  $8, $9);
    return undef unless exists $MON{$mon};
    my $epoch = eval {
      timegm($ss, $mm, $hh, $dd, $MON{$mon}, $yyyy)
    };
    return undef if $@;
    my $tz_off = ($oh * 3600 + $om * 60) * ($sign eq '-' ? -1 : 1);
    return $epoch - $tz_off;          # convert log-local ? UTC
  }
  return undef;
}

# Parse ISO timestamp to localtime epoch or undef
#   eg "2026-06-04T14:30:00"
sub parse_iso_ts {
  my ($s) = @_;
  if ($s =~ /(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
    my ($yyyy,$mon,$dd,$hh,$mm,$ss) = ($1,$2,$3,$4,$5,$6);
    return eval {
      timelocal($ss, $mm, $hh, $dd, $mon - 1, $yyyy)
    };
  }
  return undef;
}

# log + also to STDERR
sub log_msg {
  my ($msg) = @_;
  my $ts    = strftime("%Y-%m-%d %H:%M:%S", localtime);
  my $line  = "[$ts] [DISARM]  $msg\n";
  print STDERR $line;
  if (open(my $fh, '>>', $LOG_FILE)) {
    print $fh $line;
    close($fh);
  }
}

# sorting on numeric ip
sub ip_sort_key {
  my $addr = shift;
  my ($ip, $mask) = split m{/}, $addr;
  my @o = split /\./, $ip;
  return sprintf("%03d.%03d.%03d.%03d/%02d", $o[0], $o[1], $o[2], $o[3], $mask // 32);
}

# check if this IP is within a particular CIDR
sub ip_in_cidr {
  my ($ip, $cidr) = @_;
  my ($net, $bits) = split m{/}, $cidr;
  $bits //= 32;
  my @ip_oct  = split /\./, $ip;
  my @net_oct = split /\./, $net;
  return 0 if @ip_oct != 4 || @net_oct != 4;
  
  my $ip_int  = ($ip_oct[0]  << 24) | ($ip_oct[1]  << 16) | ($ip_oct[2]  << 8) | $ip_oct[3];
  my $net_int = ($net_oct[0] << 24) | ($net_oct[1] << 16) | ($net_oct[2] << 8) | $net_oct[3];
  my $mask    = $bits == 0 ? 0 : (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
  
  return ($ip_int & $mask) == ($net_int & $mask);
}
