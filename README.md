# flytrap
Block aggressive scrapers from a phpBB install on Dreamhost

Install by copying the files to e.g. ~, setting up the shadow "trap" forum directory, editing the config file, and then editing crontab

It works by: 

## arm_flytrap.pl
* Arming the trap by swapping out the forum directory so everything gets a 404 error

We then wait (courtesy of cron) and after eg ten minutes run

## end_flytrap.pl

* Observing which IPs have kept keep hammering the site with requests (telltale bot behavior, human users might give up)
* Applying some configurable filtering criteria to this set of IPs
* Editing .htaccess to block the most aggressive bots

There is a provision in end_flytrap.pl to expire blocks after a predetermined time

There is also some code to collapse a range of IPs into a CIDR X.X.X.0/24 spec

The forum this was written for sits in a separate subdomain, under a separate user, if that's not the case this may need some adapting 

The shadow / "trap" directory could eg. have a .htaccess and an empty index.hmtl (so Dreamhost doesn't display the "site not ready" page). The .htaccess could eg have one line with just:

```ErrorDocument 404 "404 come back later"```

No warranties implied, there could be bugs, make backups of stuff befroe activating, buyer beware

It's perl so it's self documenting

