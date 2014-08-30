Riversist
=========

Riversist is an application that monitors network traffic 
using libpcap for malicious traffic based on various blacklists.
Once a malicious IP has been identified, a to-be-specified
executable is called. This allows you to e.g. insert a firewall
rule to block traffic from this IP.

For more config options, please see riversist.conf.dist

Support has been implemented for:
- [Project Honey Pot](http://www.projecthoneypot.org)

Support planned for:
- [Spamhaus](http://www.spamhaus.org/)
- [Stopforumspam](http://www.stopforumspam.com/) (via [Tornevall DNSBL](https://dnsbl.tornevall.org/?do=usage))
- [Sorbs](http://www.sorbs.net/)
- Other generic dnsbl's
- And more?

## Getting started
```
export GOPATH=`pwd`/riversist/
mkdir -p riversist/{src,bin,pkg}
cd riversist/src
git clone git@github.com:Freeaqingme/RiverSist.git riversist
go get code.google.com/p/gcfg
go get code.google.com/p/gopacket
go install riversist
../bin/riversist --conf riversist/riversist.conf.dist
```
