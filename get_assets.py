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

# Test SSL
from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError

import json

# Snapshot web
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.service import Service

# FS operations
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
        chrome_options.add_argument('--disable-dev-shm-usage') 
        verbose and chrome_options.add_argument("--verbose")
        verbose and chrome_options.add_argument('--log-path=chromium.log')

        service = ChromeService(executable_path="chromedriver", port=6666)
        driver = webdriver.Chrome(service=service,options=chrome_options)
        driver.get("https://www.google.com")
        driver.set_page_load_timeout(30)        
        driver.set_window_size(1366,768)
        driver.get(url)
        output_file = str(url).replace('https://', '').replace('http://','').replace('/','')
        output_file += '.png'
        verbose and DEBUG("Ouput file: " + output_file)
        driver.save_screenshot(path + output_file)
        driver.close()
    except Exception as e:
        ERROR('' + str(e))
        output_file = -1
   
    return output_file

def follow(url):
# Test if an url is redirected 
    try:
      verbose and DEBUG("Analyzing " + str(url) + " URL")
      headers = {'User-Agent': 'Mozilla/5.0 (MyOS; MyArch) get_assets/1.0 (KHTML, like Gecko) Selenium/Chromium/some_version',
                 'referer': str(url)  
      }  
      response = requests.get(url, timeout=10, headers=headers)
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
    verbose and DEBUG('TEST 3: Performing SSL analysis for ' + str(url))
    url = "https://" + url
    try:       
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
                   'referer': str(url)
        }
        r = requests.get(url, headers=headers)
        if (r.status_code != requests.codes.ok):
            ERROR("FAIL: Incorrect domain! status code was " + str(r.status_code))
            val = -1 
        else:
            verbose and DEBUG('Certificate configured at ' + url + ' is OK')

    except Exception as error:
        if "doesn't match" in str(error):
            ERROR("FAIL: Certificate doesn't match domain name")
            val = -2
        elif "certificate has expired" in str(error):
            ERROR("FAIL: Certificate has expired")
            val = -3
        elif "Errno 111" in str(error):
            ERROR("FAIL: Connection refused")
            val = -4
        else: 
            ERROR("FAIL: Unknown error: " + str(error))
            val = -5
    
    return val

def charset_ok(strg, search=re.compile(r'[^A-Za-z0-9:./_-]').search):
# Verify if chars on URL are permitted 
    verbose and DEBUG('Testing charset for ' + strg)
    return not bool(search(strg))

def url_analisys(fqdn,folder_path):
# Performs test for URL, redirects, certificate validation, and image dump
    try:
        result = -1
        if  charset_ok(fqdn):
           http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           http_socket.settimeout(5)
           https_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           https_socket.settimeout(5)
           http_location = (fqdn,80)
           https_location = (fqdn,443)

           verbose and DEBUG('TEST 1: Has ' + fqdn + ' DNS resolution and 80 port is reachable ?')
           try: 
               http_available = http_socket.connect_ex(http_location)
           except socket.gaierror:
               verbose and ERROR('FAIL: DNS resolution not found for ' + fqdn + '?')
               result=str(fqdn) + ',-1,DNS ERROR,,,'
           except socket.timeout:
               http_available = -1
               verbose and DEBUG('FAIL: Unable to connect to ' + fqdn + 'using 80 (http) port')
      
           verbose and DEBUG('YES: ' + fqdn + ' is reachable via 80 port')    
           verbose and DEBUG('TEST 2: Is port 443 reachable on ' + fqdn + '?')
           try: 
               https_available = https_socket.connect_ex(https_location)
               verbose and DEBUG('YES: port 443 is reachable')
               ssl_status=verify_ssl(fqdn)     # Verify SSL Status 
           except socket.timeout:
               https_available = -1
               verbose and DEBUG('Unable to connect to ' + fqdn + 'using 443 (http) port')

           if http_available==0 or https_available==0: 
               url = "http://" + fqdn
               verbose and DEBUG('TEST 4: Is ' + url + ' a final URL or is redirected ?')
               verbose and DEBUG("Finding final URL for: " + url )

               final_url=follow(url)
               if final_url != -1 :                   
                  verbose and DEBUG('TEST 5: Getting webpage snapshot')
                  snapshot_file = url_snapshot(url,folder_path + '/snapshots/')
                  verbose and DEBUG("File stored on: " + snapshot_file)
                  secure, insecure = vulnerable_cipher(str(fqdn))
                  result=str(fqdn) + ',' + str(ssl_status) + ',' + str(final_url) + ',' + 'snapshots/' + snapshot_file + ',' + secure + ',' + insecure
               
               else:
                  verbose and DEBUG('Skipping ' + fqdn + ' due to unable to connect to 80 nor 443 port')
                  result = -1 
        else:
            WARNING('Skipping ' + str(fqdn) + ' due incorrect character found')

    except Exception as e:
        verbose and ERROR("Error ocurred analysing " + str(fqdn) + " site")
        verbose and ERROR(str(e))
        result=str(fqdn) + ',-1,DNS ERROR,,,'

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
  
    infile = open(input_csv,"r")

    print("<!DOCTYPE html>")
    print("<html>")
    print("<head>")
    print("<meta content='text/html;charset=utf-8' http-equiv='Content-Type'>")
    print("<meta content='utf-8' http-equiv='encoding'>")
    print("<link rel='stylesheet' href='table.css'>")
    print("<title>Domain hosts</title>", )
    print("</head>")
    print("<body>")
    print("<div class='middle'>")
    print("  <img class=logo src=logo.png alt='LOGO'>")
    print("  <span class='title'>Nik0chaN's web analysis report </span>")
    print("</div>")
    print("<div class='wrapper'>")
    print(" <div class='table'>")
    print("     <div class='row header blue'>")
    print("         <div class='cell'>ORIGINAL URL</div>")
    print("         <div class='cell'>CERTIFICATE STATUS</div>")
    print("         <div class='cell'>SECURE CYPHERS</div>")
    print("         <div class='cell'>INSECURE CYPHERS</div>")
    print("         <div class='cell'>FINAL URL</div>")
    print("         <div class='cell'>SNAPSHOT</div>")
    print("     </div> <!-- End row header -->")

    for line in infile:
        row = line.split(",")
        url_from = row[0]
        cert_status = row[1]
        url_to = row[2]
        snapshot = row[3]
        secure = row[4]
        insecure = row[5]

        print("     <div class='row'>")
        print("         <div class='cell' data-title='ORIGINAL URL'>%s</div>" % url_from)
        if(cert_status == "0"):
            print("         <div class='cell' data-title='CERTIFICATE STATUS'> <B>OK</B><BR>")
            context = ssl.create_default_context()
            with socket.create_connection((url_from, '443')) as sock:
                with context.wrap_socket(sock, server_hostname=url_from) as ssock:
                    cert = ssock.getpeercert()  
                    print("<br><b> CERTIFICATE NAMES</b> <br>")    
                    for san in cert['subjectAltName']:
                        print(san[1] + '<br>')
                    print("<br><B>CERTIFICATE ISSUER:</B> <br>")    
                    issuer = dict(item[0] for item in cert['issuer'])            
                    print(issuer['organizationName']+'<br>')
                    print("<br><B>Certificate expires on:</B><br>")    
                    print(cert['notAfter'])
                    print("</div>")
                    print("            <div class='cell' data-title='CIPHER SECURITY'> <B> CIPHER SEGURS ACCEPTATS:</B>")
                    print("            <br>" + secure)
                    print("            </div>")
                    print("            <div class='cell' data-title='CIPHER INSECURITY'> <B> CIPHER INSEGURS ACCEPTATS:</B>")
                    print("            <br>" + insecure)
                    print("            </div>")
        elif (cert_status == "-1"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Incorrect domain</div>")
        elif (cert_status == "-2"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Name error</div>")
        elif (cert_status == "-3"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Expired</div>")
        elif (cert_status == "-4"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Refused connection</div>")
        elif (cert_status == "-5"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Unknown error </div>")

        print("         <div class='cell' data-title='FINAL URL'>%s</div>" % url_to)
        print("         <div class='cell' data-title='ORIGINAL URL'><img src='%s' alt='No preview available' class='img'></div>" % snapshot)
        print("     </div><!-- End row -->") # Row
    print(" </div><!-- End table -->")  # Table 
    print("</div><!-- End Wrapper -->")  # Wrapper
    print("</body>")
    print("</html>")

    sys.stdout.close()
    sys.stdout = old_target
    verbose and DEBUG('Report generated a file: ' + output_html)


def get_hosts_from_file(file):
    verbose and DEBUG("Reading host file from " + file)
    hosts = {}
    f = open(file,'r')
    lines = f.read().splitlines()
    for host in lines:
        hosts[host]=""

    return hosts

def vulnerable_cipher(fqdn):
    # Function that checks all the ciphers the url accepts, then it creates a string with all the secure ones and another with the vulnerable ones
    # First we use sslscan feature, that give us the info we need about the ciphers in the host. Grep to reduce the info into an auxiliar .txt
    #list = os.system("sslscan " + fqdn + "| grep 'Accepted\|Preferred' > /tmp/codecs.txt")
    list = os.system("sslscan --no-check-certificate --no-cipher-details --no-ciphersuites --no-compression --no-groups --no-heartbleed --no-renegotiation " + fqdn + " |  grep enabled | tr '\n' > /tmp/protocols.txt")
    file = open("/tmp/protocols.txt", "r")
    # Strings that will save the secure codecs and the vulnerables ones
    secure = insecure = "" 
    # For every line in the file we check the version: If version > TLSv1.2 its insecure
    verbose and DEBUG("TEST 6: Checking certificate cyphers")
    for cipher in file:
        #if "TLSv1.1" in cipher or "TLSv1.0" in cipher or "SSLv3" in cipher:
        #    insecure = insecure + cipher
        # sslscan also format the output when it finds and insecure cipher using the yellow color, that matches 33m, so if we get that in the input we
        # can consider it also not secure at all
        #else:
        verbose and DEBUG("Analyzing: " + cipher) 
        if "32m" in cipher:
            secure = secure + cipher[0:cipher.find(' ')]
        else:
            insecure = insecure + cipher[0:cipher.find(' ')]

    verbose and DEBUG("SECURE CYPHERS: " + str(secure))
    verbose and DEBUG("NON SECURE CYPHERS: " + str(insecure))
    file.close()
    return secure, insecure

# Main 
try: 
    opts, args = getopt.getopt(sys.argv[1:],"vd:l:u:p:",["verbose","domain=","report_path"])

except getopt.GetoptError: 
    ERROR('Error unexpected input')
    print('Usage: get_assets.py [-v] [-d <domain> | -l <host file list> | -u <single URL>] [--verbose --domain <domain> --host <host file list>] [ -p <path> | --report_path <path> ]')
    sys.exit(2) 

for opt, arg in opts: 
    if opt in ('-v','--verbose'): 
        verbose=1
        DEBUG('Verbose mode ON')          
    elif opt in ("-d", "--domain"):
        domain = arg
    elif opt in ("-l", "--hosts"):
        hosts_list = arg
    elif opt in ("-u", "--url"): 
        url = arg
    elif opt in ("-p", "--report_path"):
        base_path = arg

try: 
    domain  
    verbose and DEBUG("Domain set, performing zone_transfer query") 
    folder_path = base_path + "/" + domain
    sites_list=dns_zone_xfer(domain)                # Obtain hosts from zone_transfer
    
except NameError: 
    # No domain analysis
    try: 
        hosts_list
        verbose and DEBUG("Host list set, performing text file list analysis")
        folder_path = base_path + "/" + hosts_list
        sites_list=get_hosts_from_file(hosts_list)  # Obtain hosts from file

    except NameError: 
        # No domain analysis, no site list analysis
        try: 
            verbose and DEBUG("URL is set, performing single URL analysis")
            sites_list = url.split() 
            folder_path = base_path + "/" + url
            verbose and DEBUG("URL is set, performing single URL analysis")

        except NameError: 
            # No domain analysis, no site list analysys, no URL analysis, FAIL! 
            ERROR('Nor domain, hosts list, or URL options are set you must to specify one of them')
            print('Usage: get_assets.py [-v] [-d <domain> | -l <host file list>] [--verbose --domain <domain> --host <host file list>] [ -p <path> | --report_path <path> --url <URL>]')
            sys.exit(2)

# Create folders structure
Path(folder_path).mkdir(parents=True, exist_ok=True)
Path(folder_path+"/snapshots").mkdir(parents=True, exist_ok=True)

#os.popen('cp table.css ' + folder_path) 
#os.popen('cp logo.png ' + folder_path)
csv_file = folder_path + "/report.csv"
report_file = folder_path + "/report.html"

verbose and DEBUG("Starting tests")
f = open(csv_file,'w')
for site in sites_list:
    verbose and DEBUG("Testing site: " + site)
    result=url_analisys(site,folder_path)    
    verbose and DEBUG("Site analysis finished to " + site + " result was: " + str(result))
    if result != -1:
       f.write(result + "\n")

f.close()
verbose and DEBUG("Generting report")
generate_report(csv_file,report_file)
verbose and DEBUG("Report finished") 
