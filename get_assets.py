#!/usr/bin/python
import re
from dns.exception import Timeout
import dns.zone
import dns.resolver
import dns.name
import json
import requests
import getopt
# DNS Resolution
import socket
import sys
import os
import argparse

# SSL Renegotiation (Lecagy)
import urllib3
from urllib3.util.ssl_ import create_urllib3_context

# Test SSL
from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError

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

class CustomHttpAdapter (requests.adapters.HTTPAdapter):
    # "Transport adapter" that allows us to use custom ssl_context.

    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_context=self.ssl_context)

def get_legacy_session():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
    session = requests.session()
    session.mount('https://', CustomHttpAdapter(ctx))
    return session

def url_snapshot(url, path):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--ignore-ssl-errors=yes")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument('--disable-dev-shm-usage')
        verbose and chrome_options.add_argument("--verbose")
        verbose and chrome_options.add_argument('--log-path=chromium.log')

        service = ChromeService(executable_path="chromedriver", port=6666)
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        driver.set_page_load_timeout(30)
        driver.set_window_size(1366, 768)
        output_file = str(url).replace('https://', '').replace('http://', '').replace('/', '') + '.png'
        verbose and DEBUG("Output file: " + output_file)
        driver.save_screenshot(path + output_file)
        verbose and DEBUG("TEST 5 (GET URL SNAPSHOT) STORED ON: " + path + output_file)
        return output_file
    except Exception as e:
        ERROR(str(e))
        raise

def follow(url):
# Test if an url is redirected
    final_url = "UNABLE TO DETERMINE"
    try:
      verbose and DEBUG("Analyzing " + str(url) + " URL")
      headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
                 'referer': str(url)
      }
      response = requests.get(url, timeout=30,headers=headers)
      verbose and DEBUG("STATUS CODE: " + str(response.status_code))
      verbose and DEBUG("URL: " + response.url)

      if response.history:
         verbose and DEBUG("URL " + url + " was redirected")
         for resp in response.history:
                verbose and DEBUG("TEST 4 (GET FINAL URL) -> " + response.url)
                final_url = str(response.url)
      else:
         verbose and DEBUG("URL " + url + " was NOT redirected")
         return str(response.url)

    except Exception as error:
        if "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in str(error):
            response=get_legacy_session().get(url)
            verbose and DEBUG("URL " + url + " was NOT redirected")
            finral_url = response.url
        else:
           verbose and ERROR('UNEXPECTED ERROR', +str(e))

    return response.url

def verify_ssl(url):
# Verify if SSL certificate for URL is correct
    val = 0
    certnames = 'UNABLE TO DETERMINE'
    issuer = 'UNABLE TO DETERMINE'
    expiry = 'UNABLE TO DETERMINE'

    verbose and DEBUG('TEST 3.1: Performing SSL analysis for ' + str(url))
    #url = "https://" + url
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
                'referer': 'https://' + str(url)
        }
        r = requests.get('https://' + str(url), headers=headers)
        if (r.status_code != requests.codes.ok):
            ERROR("FAIL: Incorrect domain! status code was " + str(r.status_code))
            val = -1
        else:
            context = ssl.create_default_context()
            with socket.create_connection((url, '443')) as sock:
              with context.wrap_socket(sock, server_hostname=url) as ssock:
                  cert = ssock.getpeercert()
                  certnames=""
                  for san in cert['subjectAltName']:
                        certnames = certnames + san[1] + ' '
                  issuer = dict(item[0] for item in cert['issuer'])
                  issuer = str(issuer['organizationName']).replace(',', '')
                  expiry = cert['notAfter']

            verbose and DEBUG('Certificate configured at ' + url + ' is OK')
            verbose and DEBUG('Certificate names ' + str(certnames))
            verbose and DEBUG('Issuer ' + str(issuer))
            verbose and DEBUG('Not valid after ' + expiry)

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
        elif "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in str(error):
            verbose and WARNING("UPS: Unsafe renegotation is disabled on server workarrounding")
            ctx = create_urllib3_context()
            ctx.load_default_certs()
            ctx.options |= 0x4  # ssl.OP_LEGACY_SERVER_CONNECT

            with urllib3.PoolManager(ssl_context=ctx) as http:
               r = http.request("GET", url)
               if (r.status == 200 or r.status==301):
                   verbose and DEBUG("SSL connection OK")
                   val = 0
                   with socket.create_connection((url, '443')) as sock:
                     with ctx.wrap_socket(sock, server_hostname=url) as ssock:
                       cert = ssock.getpeercert()
                       certnames=""
                       for san in cert['subjectAltName']:
                          certnames = certnames + san[1] + ' '
                       issuer = dict(item[0] for item in cert['issuer'])
                       issuer = str(issuer['organizationName']).replace(',', '')
                       expiry = cert['notAfter']

                   verbose and DEBUG('Certificate configured at ' + url + ' is OK')
                   verbose and DEBUG('Certificate names ' + str(certnames))
                   verbose and DEBUG('Issuer ' + str(issuer))
                   verbose and DEBUG('Not valid after ' + expiry)
               else:
                   ERROR("FAIL: Unsafe renegotation disabled")
                   val = -5
        else:
            ERROR("FAIL: Unknown error: " + str(error))
            val = -99

    return str(val), certnames, issuer, expiry

def charset_ok(strg, search=re.compile(r'[^A-Za-z0-9:./_-]').search):
# Verify if chars on URL are permitted
    verbose and DEBUG('Testing charset for ' + strg)
    return not bool(search(strg))

def url_analisys(fqdn,folder_path):
# Performs test for URL, redirects, certificate validation, and image dump
    ssl_status = "KO"
    final_url = "UNABLE TO DETERMINE"
    snapshot_file = ""
    secure = "UNABLE TO DETERMINE"
    insecure = "UNABLE TO DETERMINE"
    certnames = "UNABLE TO DETERMINE"
    issuer = "UNABLE TO DETERMINE"
    expiry = "UNABLE TO DETERMINE"
    http_available = 0
    https_available = 0

    try:
        result = -1
        if  charset_ok(fqdn):
           # DNS ANALYSIS
           try:
             socket.getaddrinfo(fqdn,80)
             verbose and DEBUG("TEST 1 (CHECK DNS/IP RESOLUTION): OK")

             http_location = (fqdn,80)
             https_location = (fqdn,443)

             # IS PORT 80 REACHABLE
             try:
               url_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               url_socket.settimeout(5)
               http_available = url_socket.connect_ex(http_location)
               verbose and DEBUG('TEST 2 (CHECK PORT 80 REACHABLE): YES')

               # IS PORT 443 REACHABLE
               verbose and DEBUG('TEST 3 (CHECK PORT 443 REACHABLE): YES')
               try:
                  https_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  https_socket.settimeout(5)
                  https_available = https_socket.connect_ex(https_location)
                  # CHECK SSL STATUS
                  ssl_status, certnames, issuer, expiry=verify_ssl(fqdn)
                  # GET SECURE AND INSECURE CYPHERS
                  secure, insecure = vulnerable_cipher(str(fqdn))

               except socket.timeout: # check port 443 connection error
                  https_available = -1
                  verbose and WARNING('Timeout connecting to ' + fqdn + 'using 443 (http) port')

             except socket.timeout: # check port 80 connection error
               http_available = -1
               verbose and WARNING('Timeout connecting to ' + fqdn + 'using 80 (http) port')

           except Exception as error: # check dns resolution error
               if error.args[0] == '-2' :
                   ERROR('Unable to resolve name, URL analysis stopped')
               else :
                   ERROR('Unhandled Error, URL analysis stopped' + str(error))


        else: # charset test error on address
            ERROR('Skipping ' + str(fqdn) + ' due incorrect character found')


        if http_available==0 or https_available==0:
           # GET FINAL URL
           url = "http://" + fqdn
           final_url=follow(url)
           # GET WEBPAGE SNAPSHOT
           if final_url != -1 :
              snapshot_file = url_snapshot(url,folder_path + '/snapshots/')
              verbose and DEBUG("File stored on: " + snapshot_file)

    except Exception as e: # UNHANDLED EXCEPTION
        verbose and ERROR("Error ocurred analysing " + str(fqdn) + " site")

    result=str(fqdn) + ',' + str(ssl_status) + ',' + str(final_url), ',' + str(secure) + ',' + str(insecure) + ',' + str(snapshot_file) + ',' + str(certnames) + ',' + str(issuer) + ',' + str(expiry)
    verbose and DEBUG('URL analysis ended, result: ') and print(result)

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
        secure = row[3]
        insecure = row[4]
        snapshot = row[5]
        certnames = row[6]
        issuer = row[7]
        expiration = row[8]

        print("     <div class='row'>")
        print("         <div class='cell' data-title='ORIGINAL URL'>%s</div>" % url_from)
        if(cert_status == "0"):
            print("         <div class='cell' data-title='CERTIFICATE STATUS'> <B>OK</B><BR>")
            print("              <br><b> CERTIFICATE NAMES</b> <br>")
            for san in certnames.split():
                print('                ' + san + '<br>')

            print("<br><B>CERTIFICATE ISSUER:</B> <br>")
            print(issuer+ '<br>')
            print("<br><B>Certificate expires on:</B><br>")
            print(expiration)
            print("</div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'>")
            for cipher in secure.split():
              print("            <br>" + cipher)
            print("            </div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'>")
            for cipher in insecure.split():
              print("            <br>" + cipher)
            print("            </div>")
        elif (cert_status == "-1"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Incorrect domain</div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
        elif (cert_status == "-2"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Name error</div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
        elif (cert_status == "-3"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Expired</div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
        elif (cert_status == "-4"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Refused connection</div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
        elif (cert_status == "-5"):
            print("         <div class='cell_ko' data-title='CERTIFICATE STATUS'>KO, Unknown error </div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")
            print("            <div class='cell' data-title='CIPHER SECURITY'></div>")

        print("         <div class='cell' data-title='FINAL URL'>%s</div>" % url_to)

        if (snapshot == "UNABLE TO TEST"):
           print("         <div class='cell' data-title='ORIGINAL URL'>NO PREVIEW AVAILABLE</div>")
        else:
           print("         <div class='cell' data-title='ORIGINAL URL'><img src='snapshots/%s' alt='PREVIEW' class='img'></div>" % snapshot)

        print("     </div><!-- End row -->") # Row
    # EOF For
    print(" </div><!-- End table -->")  # Table
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

    print(hosts)
    return hosts

def vulnerable_cipher(fqdn):
    # Function that checks all the ciphers the url accepts, then it creates a string with all the secure ones and another with the vulnerable ones
    # First we use sslscan feature, that give us the info we need about the ciphers in the host. Grep to reduce the info into an auxiliar .txt
    list = os.system("sslscan --no-check-certificate --no-cipher-details --no-ciphersuites --no-compression --no-groups --no-heartbleed --no-renegotiation " + fqdn + " |  grep enabled | tr '\n' > /tmp/protocols.txt")
    file = open("/tmp/protocols.txt", "r")
    # Strings that will save the secure codecs and the vulnerables ones
    secure = insecure = ""
    verbose and DEBUG("TEST 3.2: Checking certificate cyphers")
    for cypher in file:
        verbose and DEBUG("Analyzing: " + cypher)
        # 32m = green color
        if "32m" in cypher:
            secure = secure + cypher[0:cypher.find(' ')] + ' '
        else:
            insecure = insecure + cypher[0:cypher.find(' ')] + ' '

    verbose and DEBUG("SECURE CYPHERS: " + str(secure))
    verbose and DEBUG("NON SECURE CYPHERS: " + str(insecure))
    file.close()
    return secure, insecure

def parse_arguments():
    # Argument Parsing
    parser = argparse.ArgumentParser(description='Web Security Analyzer')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('-d', '--domain', help='Domain for zone transfer')
    parser.add_argument('-l', '--host_list', help='File containing list of hosts')
    parser.add_argument('-u', '--url', help='Single URL analysis')
    parser.add_argument('-p', '--report_path', default='/reports', help='Path for the report')

    return parser.parse_args()

def main():
    report_path = "/reports"
    args = parse_arguments()

    #print('Usage: get_assets.py [-v] [-d <domain> | -l <host file list>] [--verbose --domain <domain> --host <host file list>] [ -p <path> | --report_path <path> --url <URL>]')
    verbose = 0
    if args.verbose:
        print('Verbose mode is ON')
        verbose = 1
    if args.domain:
        verbose and DEBUG("Performing zone transfer for domain " + args.domain)
        try:
          verbose and DEBUG("Domain set, performing zone_transfer query")
          sites_list=dns_zone_xfer(args.domain)
        except NameError:
          ERROR("Error on domain")

    if args.host_list:
        verbose and DEBUG("Performing analysis for hosts from file " + args.host_list)
        try:
          verbose and DEBUG("Host list set, performing text file list analysis using file")
          sites_list=get_hosts_from_file(args.host_list)
        except NameError:
          ERROR("Error on host list")

    if args.url:
        print('Performing analysis for single URL:', args.url)
        try:
          verbose and DEBUG("URL is set, performing single URL analysis on " + args.url)
          sites_list = args.url.split()
        except NameError:
          ERROR("Error on site list")

    verbose and DEBUG("Report will be stored on " + args.report_path)

    # Create folders structure
    DEBUG("Destination report path " + args.report_path)
    Path(args.report_path).mkdir(parents=True, exist_ok=True)
    Path(args.report_path+"/snapshots").mkdir(parents=True, exist_ok=True)

    csv_file = args.report_path + "/report.csv"
    report_file = args.report_path + "/index.html"

    verbose and DEBUG("Starting tests")
    f = open(csv_file,'w')
    for site in sites_list:
      verbose and DEBUG("Testing site: " + site)
      if(len(site) >= 3):
        result=url_analisys(site,report_path)
        verbose and DEBUG("Site analysis finished to " + site + " result was: " + str(result))
        if result != -1:
          f.write(''.join(result) + '\n')
      else:
        verbose and DEBUG("Skipping site due incorrect lenght")
      verbose and DEBUG("--------------------------------------------------------------------")

    f.close()
    verbose and DEBUG("Generting report")
    os.popen('cp table.css ' + report_path)
    os.popen('cp logo.png ' + report_path)
    generate_report(csv_file,report_file)
    verbose and DEBUG("Report finished")

if __name__ == "__main__":
    main()
