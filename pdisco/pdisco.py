#!/usr/bin/env python
# Author: Jesse Nebling (@bashexplode)

from __future__ import print_function
import argparse
import sublist3r
import pwhois
import pdnslookup
import sys
from multiprocessing.dummy import Pool as ThreadPool
import threading
from netaddr import *
import xlsxwriter
import socket
import whois
import time
import re

screenlock = threading.Semaphore(value=1)

class excelwriter:
    def __init__(self, whoisdata, subdata, client):
        self.whoisdata = whoisdata
        self.subdomaindata = subdata
        self.clientname = client.title()
        self.filename = '%s External Footprint and Recon.xlsx' % self.clientname

    def create(self):
        # Workbook creation
        workbook = xlsxwriter.Workbook(self.filename)
        footprint = workbook.add_worksheet('External Footprint')
        outofscope = workbook.add_worksheet('Out-of-Scope Hosts')

        # Formatting
        footprint.set_column(0, 0, 32)
        footprint.set_column(1, 1, 44)
        footprint.set_column(2, 2, 34)
        footprint.set_column(3, 3, 47)
        footprint.set_column(4, 4, 40)
        footprint.set_column(5, 5, 30)
        footprint.set_column(6, 6, 33)
        footprint.set_column(7, 7, 36)
        footprint.set_column(8, 8, 36)
        footprint.hide_gridlines(2)
        footprint.set_zoom(70)
        footprint.set_tab_color('yellow')
        footprint.freeze_panes(4, 0)

        outofscope.set_column(0, 0, 49)
        outofscope.set_column(1, 1, 55)
        outofscope.hide_gridlines(2)
        outofscope.set_zoom(70)
        outofscope.set_tab_color('red')

        format = workbook.add_format({'font_name': 'Arial', 'font_size': 10})
        a1 = workbook.add_format({'font_name': 'Arial', 'font_size': 10, 'bold': True, 'underline': True})
        boldcenterwrapred = workbook.add_format({'font_name': 'Arial', 'font_size': 10, 'bold': True, 'font_color': 'red', 'text_wrap': True})
        boldcenterwrapred.set_align('center')
        boldcenterwrapred.set_align('vcenter')
        bolditalic = workbook.add_format({'font_name': 'Arial', 'font_size': 10, 'bold': True, 'italic': True})
        checkcolumn = workbook.add_format()
        checkcolumn.set_bottom(3)
        bolditalicred = workbook.add_format({'font_name': 'Arial', 'font_size': 10, 'bold': True, 'font_color': 'red', 'italic': True})
        tableheader = workbook.add_format({'font_name': 'Arial', 'font_size': 10, 'bold': True, 'text_wrap': True, 'font_color': 'white'})
        tableheader.set_align('center')
        tableheader.set_border(7)
        tableheader.set_top()
        tableheader.set_bottom()
        tableheader.set_right()
        tableheader.set_left()
        tableheader.set_bg_color('#003366')
        tablecell = workbook.add_format({'font_name': 'Arial', 'font_size': 10})
        tablecell.set_border(7)
        tablecell.set_top()
        tablecell.set_bottom()
        tablecell.set_right()
        tablecell.set_left()

        # Writing out template
        outofscope.write('A1', 'Please list any IP addresses and hosts that should not be tested at all ('
                               'out-of-scope) and/or any systems that should be given special attention (i.e. manual '
                               'testing only/no automated vulnerability scanning)', bolditalicred)
        outofscope.write('A2', 'Out-of-Scope IP Address / Range / Domain Name', tableheader)
        outofscope.write('B2', 'Notes', tableheader)
        for x in range(2, 14):
            for y in range(0, 2):
                outofscope.write(x, y, '', tablecell)

        footprint.write('A1', '%s Penetration Testing' % self.clientname, a1)
        footprint.write('A2', 'External Penetration Testing - Footprinting Exercise', format)
        footprint.write('A4', 'Please check off in this column if you OWN the range/domain in each row.', boldcenterwrapred)
        footprint.write('A5', 'X', boldcenterwrapred)
        footprint.write('B5', 'IP ranges discovered querying public databases (e.g. ARIN, APNIC, RIPE).', bolditalic)
        footprint.write('A6', '', checkcolumn)
        footprint.write('B6', 'IP Range', tableheader)
        footprint.write('C6', 'CIDR', tableheader)
        footprint.write('D6', 'Organization/Customer', tableheader)
        footprint.write('E6', 'Network Name', tableheader)
        footprint.write('F6', 'Country', tableheader)
        footprint.write('G6', 'RIR Database', tableheader)
        footprint.write('H6', 'URL', tableheader)
        footprint.write('I6', 'Associated Email', tableheader)

        # Footprint data table maths
        datarow = 6
        whoisdatarowtotal = len(self.whoisdata)
        subdomaintablerowstart = datarow + whoisdatarowtotal + 2
        subdomaindatastart = subdomaintablerowstart + 2
        subdomainrowtotal = len(self.subdomaindata)
        missingtablerowstart = subdomaindatastart + subdomainrowtotal + 3

        footprint.write(subdomaintablerowstart, 0, 'X', boldcenterwrapred)
        footprint.write(subdomaintablerowstart, 1, 'Domain names identified by querying public resources (e.g. Internic, Network Solutions, Google) and using Linux command line tools (all IP addresses should have a corresponding entry in the IP range table):', bolditalic)
        footprint.write(subdomaintablerowstart + 1, 0, '', checkcolumn)
        footprint.write(subdomaintablerowstart + 1, 1, 'Domain Name', tableheader)
        footprint.write(subdomaintablerowstart + 1, 2, 'How Found', tableheader)
        footprint.write(subdomaintablerowstart + 1, 3, 'IP Address', tableheader)
        footprint.write(subdomaintablerowstart + 1, 4, '%s Hosted Range (within ranges above)?' % self.clientname, tableheader)
        footprint.write(subdomaintablerowstart + 1, 5, 'RIR Database', tableheader)
        footprint.write(missingtablerowstart, 1, 'Please add any additional IP addresses and hosts that were not listed above during footprint analysis:', bolditalicred)
        footprint.write(missingtablerowstart + 1, 1, 'Missing IP Address / Range / Domain Name', tableheader)
        footprint.write(missingtablerowstart + 1, 2, 'Notes', tableheader)
        for x in range(missingtablerowstart + 2, missingtablerowstart + 18):
            for y in range(1, 3):
                footprint.write(x, y, '', tablecell)

        # Write data
        for index, cidr in enumerate(self.whoisdata.keys()):
            footprint.write(datarow + index, 0, '', checkcolumn)
            footprint.write(datarow + index, 1, self.whoisdata[cidr]['range'], tablecell)
            footprint.write(datarow + index, 2, cidr, tablecell)
            footprint.write(datarow + index, 3, self.whoisdata[cidr]['org'], tablecell)
            footprint.write(datarow + index, 4, self.whoisdata[cidr]['netname'], tablecell)
            footprint.write(datarow + index, 5, self.whoisdata[cidr]['country'], tablecell)
            footprint.write(datarow + index, 6, self.whoisdata[cidr]['rir'], tablecell)
            footprint.write(datarow + index, 7, self.whoisdata[cidr]['inetnumurl'], tablecell)
            footprint.write(datarow + index, 8, self.whoisdata[cidr]['email'], tablecell)

        for index, subdomain in enumerate(self.subdomaindata.keys()):
            footprint.write(subdomaindatastart + index, 0, '', checkcolumn)
            footprint.write(subdomaindatastart + index, 1, subdomain, tablecell)
            footprint.write(subdomaindatastart + index, 2, 'Automated Subdomain Scraper', tablecell)
            footprint.write(subdomaindatastart + index, 3, self.subdomaindata[subdomain]['ip'], tablecell)
            footprint.write(subdomaindatastart + index, 4, self.subdomaindata[subdomain]['inranges'], tablecell)
            footprint.write(subdomaindatastart + index, 5, self.subdomaindata[subdomain]['rir'], tablecell)

        # Insert blank lines for additional findings
        footprint.write(datarow + whoisdatarowtotal, 0, '', checkcolumn)
        for y in range(1, 9):
            footprint.write(datarow + whoisdatarowtotal, y, '', tablecell)

        footprint.write(subdomaindatastart + subdomainrowtotal, 0, '', checkcolumn)
        for y in range(1, 6):
            footprint.write(subdomaindatastart + subdomainrowtotal, y, '', tablecell)

        workbook.close()
        print("[+] %s has been created! Now delete anything that obviously isn't %s's range." % (self.filename, self.clientname))


class Main:
    def __init__(self, verbose, threads, updatelacnicdb, ripe, lacnic, afrinic, apnic, arin):
        self.threads = threads
        self.pool = ThreadPool(int(self.threads))
        self.verbose = verbose
        self.whoisdata = None
        self.dnslookups = None
        self.updatelacnicdb = updatelacnicdb
        self.ripe = ripe
        self.lacnic = lacnic
        self.afrinic = afrinic
        self.apnic = apnic
        self.arin = arin

    def whoistrycatch(self, query, whoisurl):
        whoisclient = whois.NICClient()
        try:
            whoisdata = whoisclient.whois(query, whoisurl, 0).split('\n')
            return whoisdata
        except (ConnectionResetError, socket.timeout, socket.error):
            try:
                time.sleep(5)
                whoisdata = whoisclient.whois(query, whoisurl, 0).split('\n')
                return whoisdata
            except (ConnectionResetError, socket.timeout, socket.error):
                try:
                    time.sleep(5)
                    whoisdata = whoisclient.whois(query, whoisurl, 0).split('\n')
                    return whoisdata
                except (ConnectionResetError, socket.timeout, socket.error):
                    print("[!] Failed whois connection 3 times, sorry")

    def pullwhoisdb(self, host):
        db = "ARIN"
        ip = self.dnslookups[host]["ip"]
        fullwhoisdata = []
        whoisdata = self.whoistrycatch(ip, "whois.arin.net")
        for line in whoisdata:
            if line and not re.match('^%', line):
                fullwhoisdata.append(line)
        if 'Network is unreachable' in fullwhoisdata or 'No route to host' in fullwhoisdata:
            if self.verbose:
                screenlock.acquire()
                print("[-] whois.arin.net is unreachable. Check network connection & try again.")
                screenlock.release()
        else:
            if self.verbose:
                screenlock.acquire()
                print("[+] Found Record for %s" % (ip))
                screenlock.release()
            for line in fullwhoisdata:
                if 'OrgId:' in line:
                    db = ' '.join(line.split()[1:]).rstrip()

        if "inranges" not in self.dnslookups[host].keys():
            if db.lower() != "arin" and db.lower() != "ripe" and db.lower() != "afrinic" and db.lower() != "lacnic" and db.lower() != "apnic":
                self.dnslookups[host]["inranges"] = "No - Registered under: " + db
                self.dnslookups[host]["rir"] = "ARIN"
            else:
                self.dnslookups[host]["inranges"] = "No"
                self.dnslookups[host]["rir"] = db

        return

    def run(self):
        print("[*] Initiating whois lookup.")
        whoisexec = pwhois.Main(self.verbose, False, self.pool, self.updatelacnicdb, self.ripe, self.lacnic, self.afrinic, self.apnic, self.arin)
        self.whoisdata, domain = whoisexec.run()
        clientname = domain.split('.')[0]
        print("[+] Completed whois lookup for %s." % clientname.title())
        if self.updatelacnicdb:
            sys.exit()

        print("[*] Initiating subdomain lookup with sublist3r.")
        silent = not self.verbose
        subdomains = sublist3r.main(domain, self.threads, None, False, silent=silent, verbose=self.verbose, enable_bruteforce=False,
                   engines=None)
        print("[+] Completed subdomain lookup with sublist3r.")

        print("[*] Performing DNS lookup on subdomains discovered.")
        subdnslookup = pdnslookup.DNSLookup(subdomains, self.verbose, self.pool)
        self.dnslookups = subdnslookup.execute()
        print("[+] Completed DNS lookups.")

        print("[*] Discovering whois data for subdomains and correlating with previously obtained whois data.")
        for host in self.dnslookups.keys():
            for cidr in self.whoisdata.keys():
                if IPAddress(self.dnslookups[host]["ip"]) in IPNetwork(cidr):
                    self.dnslookups[host]["inranges"] = "Yes - " + cidr
                    self.dnslookups[host]["rir"] = self.whoisdata[cidr]["rir"]
        self.pool.map(self.pullwhoisdb, self.dnslookups.keys())
        print("[+] Completed data correlation and additional whois lookups.")

        output = excelwriter(self.whoisdata, self.dnslookups, clientname)
        output.create()

    def banner(self):
        print("""
           .ed'''''' "^^^^**mu__
         -"                  ""*m__
       ."             mwu___      "Ns
      /               ug___"9*u_     "q_
     d  3             ,___"9*u_"9w_    "u_
     $  *             ,__"^m,_"*s_"q_    9_
    .$  ^c            __"9*,_"N_ 9u "s    "M
    d$L  4.           ''^m__"q_"*_ 4_ b    `L
    $$$$b ^ceeeee.    "*u_ 9u "s ?p 0_ b    9p
    $$$$P d$$$$F $ $  *u_"*_ 0_`k 9p # `L    #
    3$$$F "$$$$b   $  s 5p 0  # 7p # ]r #    0
     $$P"  "$$b   .$  `  B jF 0 jF 0 jF 0    t  Pacifist Toolkit
      *c    ..    $$     " d  @ jL # jL #    d  pdisco.py
        %ce""    $$$  m    " d _@ jF 0 jF    0  Jesse Nebling (@bashexplode)
         *$e.    ***  jm*      # jF g" 0    jF
          $$$      4  __a*" _    " J" 0     @
         $"'$=e....$  "__a*^"_s   " jP    _0
         $  *=%4.$ L  ""__a*@"_w-        j@
         $   "%*ebJL  '''__a*^"_a*     _p"
          %..      4  ^^''__m*"     _y"
           $$$e   z$  e*^F""      __*"
            "*$c  "$          __a*"
              '''*$$______aw*^''
              """
              )


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Passive Discovery and Footprinting Tool')
        # parser.add_argument('-x', '--proxy', default=False, help='Specify SOCKS5 proxy (i.e. 127.0.0.1:8123)')
        parser.add_argument('-v', '--verbose', default=False, action='store_true',
                            help='Output in verbose mode while script runs')
        parser.add_argument('-r', '--ripe', default=False, action='store_true',
                            help='Query RIPE NCC (Europe / Middle East / Central Asia)')
        parser.add_argument('-l', '--lacnic', default=False, action='store_true',
                            help='Query LACNIC (Latin America & Caribbean)')
        parser.add_argument('-f', '--afrinic', default=False, action='store_true',
                            help='Query AfriNIC (Africa)')
        parser.add_argument('-p', '--apnic', default=False, action='store_true',
                            help='Query APNIC (Asia / Pacific)')
        parser.add_argument('-a', '--arin', default=False, action='store_true',
                            help='Query ARIN (North America)')
        parser.add_argument('-A', '--all', default=False, action='store_true',
                            help='Query All RIR databases')
        parser.add_argument('-u', '--updatelacnicdb', default=False, action='store_true',
                            help='Update LACNIC database')
        parser.add_argument('-T', '--threads', default=1, help='Specify how many threads to use. [Default = 1]')

        args = parser.parse_args()
        if not (args.ripe or args.lacnic or args.afrinic or args.apnic or args.arin or args.all):
            parser.error('[!] Please select a RIR database with -r (RIPE), -l (LACNIC), -f (AfriNIC), -p (APNIC), '
                         '-a (ARIN), or all with -A.')
            sys.exit()

        if args.all:
            ripe = True
            lacnic = True
            afrinic = True
            apnic = True
            arin = True
        else:
            ripe = args.ripe
            lacnic = args.lacnic
            afrinic = args.afrinic
            apnic = args.apnic
            arin = args.arin

        go = Main(args.verbose, args.threads, args.updatelacnicdb, ripe, lacnic, afrinic, apnic, arin)
        go.banner()
        go.run()
    except KeyboardInterrupt:
        print("[!] Caught ctrl+c, aborting . . . ")
        sys.exit()

