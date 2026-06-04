#!/usr/bin/perl
# ============================================================
# arm_flytrap.pl  
#
# Arm the trap
#
# Renames the forum directory so Apache returns 404 for every
# request.  
#
# Bots are gonna bot... and keep hammering
# Humans are more likely to shrug and come back later
#
# Cron:  0 */6 * * *  /path/to/arm_flytrap.pl
# ============================================================

use strict;
use warnings;

use FindBin qw($RealBin);
use POSIX qw(strftime);
use File::Path qw(make_path);

my $cfg = do "$RealBin/flytrap_config.pl";

# Shortcuts
my $FORUM_DIR         = $cfg->{FORUM_DIR};
my $ARMED_SUFFIX      = $cfg->{ARMED_SUFFIX};
my $SWAP_SUFFIX       = $cfg->{SWAP_SUFFIX};
my $LOG_FILE          = $cfg->{LOG_FILE};
my $TIMESTAMP_FILE    = $cfg->{TIMESTAMP_FILE};
my $FORUM_URL_PATH    = $cfg->{FORUM_URL_PATH};

my $armed_dir = $FORUM_DIR . $ARMED_SUFFIX;
my $swap_dir = $FORUM_DIR . $SWAP_SUFFIX;

#
# Sanity checks
#

unless (-d $FORUM_DIR) {
  log_msg("ERROR: Forum directory $FORUM_DIR not found. Already armed or misconfigured?");
  exit 1;
}

unless (-d $swap_dir) {
  log_msg("ERROR: Swap (dummy empty) forum directory $swap_dir not found. Misconfigured?");
  exit 1;
}

if (-d $armed_dir) {
  log_msg("ERROR: Armed directory $armed_dir exists. Inconsistent state, investigate manually.");
  exit 1;
}

#
# Arm the trap
#

if (rename($FORUM_DIR, $armed_dir)) {
  log_msg("ARMED: $FORUM_DIR -> $armed_dir");
} else {
  log_msg("ERROR: rename($FORUM_DIR, $armed_dir) failed: $!");
  exit 1;
}

if (rename($swap_dir, $FORUM_DIR)) {
  log_msg("ARMED: $swap_dir -> $FORUM_DIR");
} else {
  log_msg("ERROR: rename($swap_dir, $FORUM_DIR) failed: $!");
  exit 1;
}

#
# Record when armed
#

my $ts_dir = $TIMESTAMP_FILE;
$ts_dir =~ s{/[^/]+$}{};
die "nowhere to write timestamp" unless -d $ts_dir;
#make_path($ts_dir) unless -d $ts_dir;

if (open(my $fh, '>', $TIMESTAMP_FILE)) {
  print $fh time() . "\n";
  close($fh);
} else {
  log_msg("WARNING: Could not write timestamp file $TIMESTAMP_FILE: $!");
}

#
# Write to log file
#

sub log_msg {
  my ($msg) = @_;
  my $ts  = strftime("%Y-%m-%d %H:%M:%S", localtime);
  my $line = "[$ts] [ARM] $msg\n";
  print STDERR $line;
  if (open(my $fh, '>>', $LOG_FILE)) {
  print $fh $line;
  close($fh);
   }
 }
