# sauron
A rudimentary network monitor written in python, which uses CouchDB as the persistance method and arp-scan data to act.

I had no real reason to write this program. I just wanted to code in python and work with CouchDB. This application, when
configured by a cron job to read in arp-scan data on a routine basis, will keep the record of machines on the subnet
persistent and alert you if certain conditions are met, such as if a new unrecognized machine joins the subnet, or
if a machine that hasn't joined in a while suddenly re-joins, or if you manually configure this application to alert you
when a specific device joins or leaves the network.

This is an original project coded entirely by me, though I have lifted some snippets of code from other sites in relation
to CouchDB. Any similarities to other applications are purely coincidental.
