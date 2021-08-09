# get_assets
Given a domain with DNS transfer enabled or a text file containing a list of hosts (one per line) scripts connects and gets a report from webpages status (SSL, Redirects, Snapshot, Availability)

Requirements: 

Python 3.6

Selenium 

Chromedriver installed on /usr/local/bin/chromedriver 

Usage: 

get_assets.py -d <domain> -l | <domain_list> [--verbose --domain <domain> --hosts] [-v]

This will generate a folder on same directory with the domain name including a report.html file

-v enables verbose mode 

Example: 

get_assets.py -v -d mydomain.com 

given  domains_list.txt with content
domain1.com 
domain2.com 
domain3.com 


get_assets.py -l domains_list.txt


