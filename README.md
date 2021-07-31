# get_assets
Given a domain with DNS transfer enabled scripts connects and gets a report from webpages status (SSL, Redirects, Snapshot, Availability)

Requirements: 

Python 3.6

Selenium 

Chromedriver installed on /usr/local/bin/chromedriver 

Usage: 

get_assets.py [-v] -d <domain> [--verbose --domain <domain>]')

This will generate a folder on same directory with the domain name including a report.html file

-v enables verbose mode 

Example: 

get_assets.py -v -d mydomain.com 


