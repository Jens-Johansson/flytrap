# 
# flytrap_config.pl
#
# Some config variables common to the trap arm/end (disarm) scripts
#
# Enter full paths if this is to be invoked via cron
#

{
  # How many of the top offender IPs to consider for ban
  TOP_OFFENDERS   => 4096,
  
  # Minimum hits in the trap window to be considered an offender
  HIT_THRESHOLD   => 50,
  
  # Minutes the trap stays armed (should match cron offset, this is
  # the fallback value in case window cannot be extracted/
  # calculated from the timestamp file)
  TRAP_WINDOW_MINS => 10,
  
  # Wait this amount of minutes to start considering traffic
  # Theory being that a normal human would give up after this time
  TRAP_LATENCY_MINS => 2,
  
  ###
  #
  # could consider having some php scripts for posting stuff symlinked or emulated
  # as a safeguard for people who have spent a lot of time on an edit page crafting a post
  # 
  # posting.php?etc => "you have posted the following, spam traffic control scheme in progress, 
  # please don't navigate away from this page, instead carefully copypaste the text below: "
  #
  # Donno
  #
  ###
  
  # Consolidate "Require not" blocks into X.Y.Z.0/24 (or whatever CIDR)
  #
  # Subnet size to consolidate at (have only (barely) implemented /24)
  CONSOLIDATE_MASK      => 24,  
  # ALlowed sparseness, i.e., if '16', then 16 offending IPs in the same /24 is enough 
  # to nuke the whole /24
  CONSOLIDATE_THRESHOLD => 16,
  
  # Days before an IP ban expires
  BAN_DURATION_DAYS => 7,
  
  # Paths to stuff
  # The normal (live) directory where phpBB is served from
  # when the trap is disarmed (i.e., during normal operation)
  FORUM_DIR       => '/home/PUT_HOSTING_PROVIDER_USERNAME_HERE/PUT_FORUM_DIRECTORY_NAME_HERE',
  
  # Suffix appended when the trap is armed (directory is renamed)
  ARMED_SUFFIX   => '-disabled',
  
  # suffix on empty dir which should become renamed as the forum 
  # dir (it just has a .htaccess that returns the three 
  # characters "404" for 404 and a blank index.html)
  SWAP_SUFFIX        => '-swap',
  
  # Apache access log, combined format
  ACCESS_LOG      => '/home/PUT_HOSTING_PROVIDER_USERNAME_HERE/logs/PUT_FORUM_DIRECTORY_NAME_HERE/https/access.log',
  
  #
  # And what about http logs? Relevant? Well let's start here
  #
  
  # Own log file
  LOG_FILE        => '/home/PUT_HOSTING_PROVIDER_USERNAME_HERE/flytrap.log',
  
  # Timestamp file  
  # arm_flytrap.pl writes the epoch when arming
  # end_flytrap.pl reads it to determine the analysis window
  TIMESTAMP_FILE  => '/home/PUT_HOSTING_PROVIDER_USERNAME_HERE/flytrap_armed_at',
  
  
  # URL path filter
  # Only count log entries whose request path starts WITH this.
  # Set to '' to count ALL 404 traffic
  FORUM_URL_PATH  => '/',
  
  # Markers to bracket the flytrap-managed section of .htaccess
  FLYTRAP_START   => '##### FLYTRAP_START #####',
  FLYTRAP_END     => '##### FLYTRAP_END #####',
}
