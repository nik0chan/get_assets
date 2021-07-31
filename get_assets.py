#!/usr/bin/python 

import re
from dns.exception import Timeout
import dns.zone
import dns.resolver
import dns.name
import requests
import getopt
import socket
import sys
import os

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from pathlib import Path

ns_servers = []
verbose = 0

def ERROR(msg): print("\033[91m {}\033[00m" .format("[ERROR] " + "\033[93m" + msg))
def WARNING(msg): print("\033[93m {}\033[00m" .format("[WARNING] " + "\033[35m" + msg))
def DEBUG(msg): print("\033[92m {}\033[00m" .format("[DEBUG] " + "\033[36m" + msg))

def url_snapshot(url,path):
# Get a web snapshot 
    try:
        verbose and DEBUG("Getting snapshot for URL: " + str(url) + " to path: " + path)
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--ignore-ssl-errors=yes")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--no-sandbox")
        verbose and chrome_options.add_argument("--verbose")
        verbose and chrome_options.add_argument('--log-path=chromium.log')
        driver = webdriver.Chrome(options=chrome_options, executable_path='/usr/local/bin/chromedriver')      
        driver.set_page_load_timeout(15)        
        driver.set_window_size(1920,1080)
        driver.get(url)
        output_file = path + str(url).replace('https://', '').replace('http://','').replace('/','')
        output_file += '.png'
        verbose and DEBUG("Ouput file: " + output_file)
        driver.save_screenshot(output_file)
        driver.close()
    except Exception as e:
        ERROR('' + str(e))
        output_file = -1
   
    return output_file

def follow(url):
# Test if an url is redirected 
    try:
      verbose and DEBUG("Analyzing " + str(url) + " URL")
      response = requests.get(url, timeout=10)
      verbose and DEBUG("STATUS CODE: " + str(response.status_code))
      verbose and DEBUG("URL: " + response.url)
            
      if response.history:
         verbose and DEBUG("URL " + url + " was redirected")
         for resp in response.history:
                verbose and DEBUG("Final URL -> " + response.url)
                return str(response.url)

      else:
         verbose and DEBUG("URL " + url + " was NOT redirected")    
         return str(response.url)
    
    except Exception as e:
        verbose and  ERROR('shit! '+str(e))
        return -1

def verify_ssl(url):
# Verify if SSL certificate for URL is correct 
    val = 0
    verbose and DEBUG('Performing SSL analysis for ' + str(url))
    if not url.startswith("https"):
        ERROR('URL is not SSL -> ' + url)
        val = -1 
    else:
        try:
            r = requests.get(url)
            if (r.status_code != requests.codes.ok):
                ERROR("Incorrect domain! status code was " + str(r.status_code))
                val = -2 
        except Exception as error:
            if "doesn't match" in str(error):
                ERROR("Certificate doesn't match URL name")
                val = -3
            if "certificate has expired" in str(error):
                ERROR("Certificate has expired")
                val = -4
            else:
                verbose and DEBUG('Certificate configured at ' + url + ' is OK')

    return val

def charset_ok(strg, search=re.compile(r'[^A-Za-z0-9.:/_-]').search):
# Verify if chars on URL are permitted 
    return not bool(search(strg))

def url_analisys(host,address):
# Performs triple analysis for URL, redirects, certificate validation, and image dump
    try:
        result = -1
        fqdn = str(host) + "." + str(address)
        if  charset_ok(fqdn):
           verbose and DEBUG('Is port 80 reachable on ' + fqdn + '?')
           http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           http_socket.settimeout(5)
           https_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           https_socket.settimeout(5)
           http_location = (fqdn,80)
           https_location = (fqdn,443)

           try: 
               http_available = http_socket.connect_ex(http_location)
           except socket.timeout:
               http_available = -1
               DEBUG('Unable to connect to ' + fqdn + 'using 80 (http) port')
           
           try: 
               https_available = https_socket.connect_ex(https_location)
           except socket.timeout:
               https_available = -1
               DEBUG('Unable to connect to ' + fqdn + 'using 443 (http) port')

           DEBUG('HTTP:' + str(http_available) + ' HTTPS: ' + str(https_available))

           if http_available==0 or https_available==0: 
               url = "http://" + fqdn
               ssl_status = -1 
               verbose and DEBUG("Inspecting: " + url )
                        
               final_url=follow(url)
               if final_url != -1 : 
                  ssl_status=verify_ssl(final_url)
                  snapshot_file = url_snapshot(url,str(address) + '/snapshots/')
                  result=str(url) + ',' + str(ssl_status) + ',' + str(final_url) + ',' + './snapshots/' + fqdn + '.png'
               
               else:
                  verbose and DEBUG('Skipping ' + fqdn + ' due to unable to connect to 80 nor 443 port')
                  result = -1 
        else:
            WARNING('Skipping ' + str(fqdn) + ' due incorrect character found')

    except Exception as e:
        print('Error',e)

    return result    

def dns_zone_xfer(address):
# Retrieves all host entries form domain on a dictionary 
    hosts = {}
    verbose and DEBUG("Identifying nameservers")
    ns_answer = dns.resolver.resolve(address, 'NS')
    for server in ns_answer:
        verbose and DEBUG("NS found: "+str(server))
        verbose and DEBUG("Identifying A entries")
        ip_answer = dns.resolver.resolve(server.target, 'A')
        for ip in ip_answer:
            verbose and DEBUG("IP for " + str(server) +  " is " + str(ip))
            try:
                verbose and DEBUG("Performing zone transfer over: " + str(ip) + " IP")
                zone = dns.zone.from_xfr(dns.query.xfr(str(ip), address))
                for host in zone:
                    hosts[str(host)]=address
                    
            except Exception as e:
                verbose and ERROR("NS " + str(server) + "refused zone transfer, are you sure you have permission to transfer DNS zone?")

        continue
    return hosts

def generate_report(input_csv,output_html):
# Generate html report file from csv 
# Requires style file (table.css) with T1 class definition for table formatting

    old_target = sys.stdout
    sys.stdout = open(output_html,'w')
    print("<!DOCTYPE html>")
    print("<html>")
    print("<head>")
    print("<link rel='stylesheet' href='table.css'>")
    print("</head>")
    print("<body>")

    print("<table class='t1'>")

    print("<thead>")
    print("<tr><th>ORIGINAL URL</th><th>CERTIFICATE STATUS</th><th>FINAL URL</th><th>SNAPSHOT</th></tr>")
    print("</thead>")

    infile = open(input_csv,"r")

    for line in infile:
        row = line.split(",")
        url_from = row[0]
        cert_status = row[1]
        url_to = row[2]
        snapshot = row[3]

        print("<tr>")
        print("<td>%s</td>" % url_from)
        if(cert_status == "0"):
            print("<td>OK</td>")
        elif (cert_status == "-1"):
            print("<td>KO - No certificate</td>")
        elif (cert_status == "-2"):
            print("<td>KO - NON SSL ERROR</td>")
        elif (cert_status == "-3"):
            print("<td>KO - Incorrect name</td>")            
        elif (cert_status == "-4"):
            print("<td>KO - Incorrect name</td>")   

        print("<td>%s</td>" % url_to)
        print("<td><img src='%s' alt='No preview available'></td>" % snapshot)
        print("</tr>")

    print("</table>")
    print("</body>")
    print("</html>")

    sys.stdout.close()
    sys.stdout = old_target
    verbose and DEBUG('Report generated a file: ' + output_html)

# Main 

try: 
    opts, args = getopt.getopt(sys.argv[1:],"vd:",["verbose","domain="])

except getopt.GetoptError: 
    ERROR('Error unexpected input')
    print('Usage: get_assets.py [-v] -d <domain> [--verbose --domain <domain>]')
    sys.exit(2) 

for opt, arg in opts: 
    if opt in ('-v','--verbose'): 
        verbose=1
        DEBUG('Verbose mode ON')          
    elif opt in ("-d", "--domain"):
        domain = arg

try: domain   
except NameError:
    ERROR('Missing domain.')
    print('Usage: get_assets.py [-v] -d <domain> [--verbose --domain <domain>]')
    sys.exit(2)

# Create folders structure
Path(domain).mkdir(parents=True, exist_ok=True)
Path(domain+"/snapshots").mkdir(parents=True, exist_ok=True)
os.popen('cp table.css ' + domain) 

# Obtain domzins from zone_transfer
sites_list=dns_zone_xfer(domain)

csv_file = domain + "/report.csv"
report_file = domain + "/report.html"
f = open(csv_file,'w')
for site in sites_list:
    result=url_analisys(site,sites_list[site])    
    if result != -1:
       f.write(result + "\n")
f.close()
generate_report(csv_file,report_file) 

