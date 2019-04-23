# Usage

```
Usage: rbl2shorewall.py [-h] [-4 /etc/shorewall/blrules] [-6 /etc/shorewall6/blrules] [-z ppp] [-f]
```

Convert MyIP.MS and SpamHaus RBL blacklists to shorewall and shorewall6 blrules files

Optional arguments:
 * -h, --help  
   Show this help message and exit
 * -4 /etc/shorewall/blrules, --shorewall4-blrules /etc/shorewall/blrules  
   Shorewall IPv4 blrules file path (default: /root/rbl2shorewall/blrules\_4)
 * -6 /etc/shorewall6/blrules, --shorewall6-blrules /etc/shorewall6/blrules  
   Shorewall IPv6 blrules file path (default: /root/rbl2shorewall/blrules\_6)
 * -z ppp, --net-zone ppp  
   Shorewall public zone name (default: net)
 * -f, --force  
   Overwrite already existing files (default: False)


# Features:

 * SpamHaus DROP/EDROP/DROPv6: https://www.spamhaus.org/drop/
 * MyIP.MS Full Blacklist (ZIP): https://myip.ms/browse/blacklist
 * Support both IPv4 and IPv6
 * Sanitize addresses using [Python ipaddress module](https://docs.python.org/3/library/ipaddress.html)
 * Optimize by dropping addresses already part of an excluded subnet
 * Use mutltiprocessing to accelerate optimization
 * Black formatted
 * Pylint 10/10 with very few inline ignores
 * Included crontab example to use in production
