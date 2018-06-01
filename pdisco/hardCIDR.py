#!/usr/bin/env python

# A python version of the script hardCIDR.sh by Jason Ashton (@ninewires)
# A tool to enumerate CIDRs by querying RIRs & BGP ASN prefix lookups
# Currently queries: ARIN, RIPE NCC, APNIC, AfriNIC, LACNIC
#
# Queries are made for the Org name, network handles, org handles, customer handles,
# BGP prefixes, PoCs with target email domain, and 'notify' email address - used by
# some RIRs.
#
# Note that several RIRs currently limit query results to 256 or less, so large
# target orgs may not return all results.
#
# LACNIC only allows query of ASN or IP address blocks & cannot search for Org names
# directly. The entire DB as been downloaded to a separate file for queries to this RIR.
# The file will be periodically updated to maintain accurate information.
#
# Output saved to two csv files - one for org & one for PoCs
# A txt file is also output with a full list of enumerated CIDRs
#
# Author: Jesse Nebling (@bashexplode)

from __future__ import print_function
import sys
import argparse
import os
import urllib
import subprocess
import time
import re
from netaddr import *
import random
import telnetlib
import socket
from multiprocessing.dummy import Pool as ThreadPool
import threading

screenlock = threading.Semaphore(value=1)
combined_whoisresults = {}  # Dict to consolidate results from all modules


def cmdline(command):  # was annoyed at os.system output so pulled this
    process = subprocess.Popen(
        args=command,
        stdout=subprocess.PIPE,
        shell=True
    )
    return process.communicate()[0]


class WhoISparser:
    def __init__(self, verbose, pool, name, whoisurl, rir, inetnumurl, emaildomain):
        self.verbose = verbose
        self.name = name
        self.whoisurl = whoisurl
        self.inetnumurl = inetnumurl
        self.rir = rir
        self.emaildomain = emaildomain
        self.fullwhoisdata = None
        self.netnamelist = []
        self.pool = pool
        self.emaillist = []
        self.sanilist = []

    def initializewhoisdata(self):
        if self.verbose:
            print("[*] Enumerating CIDRs for %s Org Names via %s" % (self.name, self.rir))

        self.fullwhoisdata = cmdline(
            "whois -h %s '%s' | grep -v '%s' | sed 1,4d | sed '$d'" % (self.whoisurl, self.name, '%')).split('\n')
        if 'No entries found' in self.fullwhoisdata:
            if self.verbose:
                print("[-] No %s records found for %s." % (self.rir, self.name))
        elif 'Network is unreachable' in self.fullwhoisdata or 'No route to host' in self.fullwhoisdata:
            if self.verbose:
                print("[-] %s is unreachable. Check network connection & try again." % self.whoisurl)
        else:
            if self.verbose:
                print("[+] Found %s Records for %s" % (self.rir, self.name))

    def inetexec(self, line):
        if 'inetnum' in line:
            inet = ' '.join(line.split()[1:])
            cidr = None
            org = None
            netname = None
            country = None
            email = None
            singlewhoisdata = cmdline("whois -h %s '%s' | grep -v '%s'" % (self.whoisurl, inet, '%')).split('\n')
            inetnumhtml = inet.replace(' ', '%20').replace('-', '%2D').replace(',', '%2C').replace('.',
                                                                                                   '%2E').replace(
                '&', '%26')
            inetnumurl = self.inetnumurl.replace("{URLDATA}", inetnumhtml)
            for sline in singlewhoisdata:
                if 'descr' in sline:
                    org = ' '.join(sline.split()[1:])
                    break

            for sline in singlewhoisdata:
                if 'e-mail' in sline or 'notify' in sline:
                    if self.emaildomain:
                        if self.emaildomain.lower() in sline.lower():
                            email = sline.split()[1].rstrip()
                if 'netname' in sline:
                    netname = ' '.join(sline.split()[1:])
                    if netname not in self.netnamelist:
                        self.netnamelist.append(netname)

            for sline in singlewhoisdata:
                if 'country' in sline:
                    country = sline.split()[1].upper()
                    break

            try:
                cidr = str((iprange_to_cidrs(inet.split('-')[0], inet.split('-')[1]))[0])
            except core.AddrFormatError:
                if self.verbose:
                    print("[!] %s is not a range or is formatted incorrectly" % inet)

            dictentry = BuildResultDict(cidr, inet, org, netname, inetnumurl, country, self.rir, email,
                                        self.verbose)
            dictentry.build()

    def inetlookup(self):
        self.pool.map(self.inetexec, self.fullwhoisdata)

    def emailsearch(self, line):
        if 'e-mail' in line or 'notify' in line:
            if self.emaildomain.lower() in line.lower() or self.name.lower() in line.lower():
                self.sanilist.append(line.split()[1].rstrip())
        if self.emaildomain.lower() in line.lower():
            self.sanilist.append(line.split()[1].rstrip())

    def emailexec(self, email):
        self.fullwhoisdata = cmdline(
            "whois -h %s -i ny '%s' | grep -v '%s' | sed 1,4d | sed '$d'" % (self.whoisurl, email, '%')).split(
            '\n')
        self.pool.map(self.inetexec, self.fullwhoisdata)

    def emaillookup(self):
        self.pool.map(self.emailsearch, self.fullwhoisdata)

        for email in self.sanilist:
            if email not in self.emaillist:
                self.emaillist.append(email)

        self.pool.map(self.emailexec, self.emaillist)

    def netnamelookup(self):
        for netname in self.netnamelist:
            self.fullwhoisdata = cmdline(
                "whois -h %s '%s' | grep -v '%s' | sed 1,4d | sed '$d'" % (self.whoisurl, netname, '%')).split('\n')
            self.inetlookup()


class RIPE:
    def __init__(self, verbose, pool, cname):
        self.verbose = verbose
        self.cname = cname
        self.whoisname = "whois.ripe.net"
        self.rir = "RIPE NCC"
        self.inetnumurl = "https://apps.db.ripe.net/search/lookup.html?source=ripe&key={URLDATA}&type=inetnum"
        self.pool = pool

    def run(self):
        for name in self.cname:
            whois = WhoISparser(self.verbose, self.pool, name, self.whoisname, self.rir, self.inetnumurl, None)
            whois.initializewhoisdata()
            whois.inetlookup()


class APNIC:
    def __init__(self, verbose, pool, cname, cemail):
        self.verbose = verbose
        self.cname = cname
        self.whoisname = "whois.apnic.net"
        self.rir = "APNIC"
        self.inetnumurl = "http://wq.apnic.net/apnic-bin/whois.pl?searchtext={URLDATA}"
        self.cemail = cemail
        self.pool = pool

    def run(self):
        for name in self.cname:
            whois = WhoISparser(self.verbose, self.pool, name, self.whoisname, self.rir, self.inetnumurl, self.cemail)
            whois.initializewhoisdata()
            whois.inetlookup()
            whois.emaillookup()
            # whois.netnamelookup()


class AfriNIC:
    def __init__(self, verbose, pool, cname, cemail):
        self.verbose = verbose
        self.cname = cname
        self.whoisname = "whois.afrinic.net"
        self.rir = "AfriNIC"
        self.inetnumurl = "http://www.afrinic.net/en/services/whois-query/{URLDATA}"
        self.cemail = cemail
        self.pool = pool

    def run(self):
        for name in self.cname:
            whois = WhoISparser(self.verbose, self.pool, name, self.whoisname, self.rir, self.inetnumurl, self.cemail)
            whois.initializewhoisdata()
            whois.inetlookup()
            whois.emaillookup()
            # whois.netnamelookup()


class LACNIC:
    def __init__(self, verbose, pool, cname, cemail, routesrvs, datafile):
        self.verbose = verbose
        self.cname = cname
        self.rir = "LACNIC"
        self.cemail = cemail
        self.routesrvs = routesrvs
        self.datafile = datafile
        self.pool = pool
        self.lutype = None

    def singlelookup(self, whoisdata, lookuplist):
        for lookupitem in lookuplist:
            for index, line in enumerate(whoisdata):
                if lookupitem.lower() in line.lower():
                    singlewhoisdata = []
                    org = None
                    netname = None
                    country = None
                    if self.lutype == 'email':
                        for x in range(1, 20):
                            singlewhoisdata.append(whoisdata[index - x])
                        for x in range(1, 10):
                            singlewhoisdata.append(whoisdata[index + x])
                    else:
                        for x in range(1, 4):
                            singlewhoisdata.append(whoisdata[index - x])
                        for x in range(1, 9):
                            singlewhoisdata.append(whoisdata[index + x])

                    for sline in singlewhoisdata:
                        if 'owner:' in sline:
                            org = ' '.join(sline.split()[1:])
                            break

                    for sline in singlewhoisdata:
                        if 'ownerid:' in sline:
                            netname = ' '.join(sline.split()[1:])
                        if self.lutype == 'email':
                            if ('@' + self.cemail).lower() in line.lower():
                                email = sline.split()[1]

                    for sline in singlewhoisdata:
                        if 'country:' in sline:
                            country = sline.split()[1].upper()
                            break

                    if self.lutype == 'email' or self.lutype == 'inetnum':
                        url = 'http://lacnic.net/cgi-bin/lacnic/whois?lg=EN&query={URLDATA}'
                        for sline in singlewhoisdata:
                            if 'inetnum:' in sline:
                                cidr = sline.split()[1]
                                if '/32' in cidr:
                                    inetnum = str(IPNetwork(cidr).network)
                                else:
                                    inetnum = str(IPNetwork(cidr).network) + " - " + str(IPNetwork(cidr).broadcast)
                                inetnumhtml = inetnum.replace(' ', '%20').replace('-', '%2D').replace(',',
                                                                                                      '%2C').replace(
                                    '.', '%2E').replace('&', '%26')
                                inetnumurl = url.replace("{URLDATA}", inetnumhtml)
                                dictentry = BuildResultDict(cidr, inetnum, org, netname, inetnumurl, country, self.rir,
                                                            email, self.verbose)
                                dictentry.build()
                    if self.lutype == 'asn':
                        url = "http://bgp.he.net/{URLDATA}#_asinfo"

                        try:
                            tn = telnetlib.Telnet(random.choice(self.routesrvs), '23', timeout=10)
                            tn.write("show ip bgp regexp %s\n" % lookupitem[2:])
                            tn.write("\n")
                            tn.write("exit\n")
                            telnetdata = tn.read_all().split()
                            time.sleep(3)
                            ranges = []
                            for ipadd in telnetdata:
                                if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$",
                                            ipadd) or re.match(
                                        r"^i([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$", ipadd):
                                    if 'i' in ipadd:
                                        ranges.append(ipadd[1:])
                                    else:
                                        ranges.append(ipadd)

                            if ranges:
                                for cidradd in ranges:
                                    cidr = cidradd
                                    inetnum = str(IPNetwork(cidr).network) + " - " + str(IPNetwork(cidr).broadcast)
                                    inetnumhtml = lookupitem.replace(' ', '%20').replace('-', '%2D').replace(',',
                                                                                                             '%2C').replace(
                                        '.', '%2E').replace(
                                        '&', '%26')
                                    inetnumurl = url.replace("{URLDATA}", inetnumhtml)

                                    dictentry = BuildResultDict(cidr, inetnum, org, netname, inetnumurl, country, self.rir,
                                                                email, self.verbose)
                                    dictentry.build()
                        except (socket.timeout, socket.error):
                            if self.verbose:
                                screenlock.acquire()
                                print("\t[!] Connection timed out or refused for ASN %s. Skipping." % lookupitem)
                                screenlock.release()
                            pass

    def run(self):
        for name in self.cname:
            if self.verbose:
                print("[*] Enumerating CIDRs for %s Org Names via %s" % (name, self.rir))
            with open(self.datafile) as f:
                whoisdata = list(filter(None, f.read().split('\n')))

            owners = []
            inet = []
            asn = []
            emails = []
            saniarray = []

            for line in whoisdata:
                if 'owner:' in line:
                    if name.lower() in line.lower():
                        owners.append(line)
                if ('@' + self.cemail).lower() in line.lower():
                    emails.append(str(line.split()[1]))

            if owners or emails:
                if self.verbose:
                    print("[+] Found LACNIC Records for %s" % name)
                if owners:
                    for index, line in enumerate(whoisdata):
                        for owner in owners:
                            if owner.lower() in line.lower():
                                for x in range(1, 5):
                                    if 'inetnum' in whoisdata[index - x]:
                                        inet.append(line.strip()[1:])
                                    if 'aut-num' in whoisdata[index - x] and 'N/A' not in whoisdata[index - x]:
                                        asn.append(line.strip()[1:])

                    if inet:
                        for inetnum in inet:
                            if inetnum not in saniarray:
                                saniarray.append(inetnum)
                        inet = saniarray
                        saniarray = []

                        self.lutype = 'inetnum'
                        # query by inetnum
                        self.singlelookup(whoisdata, inet)

                    if asn:
                        for asnnum in asn:
                            if asnnum not in saniarray:
                                saniarray.append(asnnum)
                        asn = saniarray
                        saniarray = []
                        self.lutype = 'asn'
                        self.singlelookup(whoisdata, asn)

                if emails:
                    for email in emails:
                        if email not in saniarray:
                            saniarray.append(email)
                    emails = saniarray
                    self.lutype = 'email'
                    self.singlelookup(whoisdata, emails)

            else:
                if self.verbose:
                    print("[-] No LACNIC Records found for %s" % name)


class LACNICupdate():
    # class to update the local LACNIC data file
    #
    # LACNIC published rate-limits:
    #   100 queries every 5 minutes
    #   1000 queries every 60 minutes
    #
    # The high side of these rates is one query every 3.6s, so we
    # will sleep for 4s between queries to remain under the limit.
    #
    # At the time of this script creation, the update will take
    # approximately 28hrs to complete.
    #
    # There is currently no mechanism to monitor the connection state
    # nor ability to resume a crashed update.
    def __init__(self, verbose, datafile, datafilebu):
        self.datafile = datafile
        self.datafilebu = datafilebu
        self.verbose = verbose

    def u_term(self):
        print("[!] Caught ctrl+c, removing all tmp files and restoring old data file.")
        os.remove(self.datafile)
        os.rename(self.datafilebu, self.datafile)
        sys.exit()

    def run(self):
        # Backup existing file in case things get janky
        if self.verbose:
            print("[*] Backing up existing data file in case something goes wrong.")
        if os.path.isfile(self.datafile) and os.path.isfile(self.datafilebu):
            os.remove(self.datafilebu)
        elif os.path.isfile(self.datafile):
            os.rename(self.datafile, self.datafilebu)
        else:
            print("[!] %s not found in this directory. Continuing without backup." % self.datafile)

        # Get all assigned/allocated ranges
        if self.verbose:
            print("[*] Downloading LACNIC delegation list.")
        fulldata = urllib.urlopen("http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest")
        cleandata = []
        for line in fulldata:
            if "assigned" or "allocated" in line:
                cleandata.append(line.split("|")[3])

        if self.verbose:
            print("[*] Querying LACNIC for all published ranges.")
            print("    *** This is going to take a while ***")

        total = len(cleandata)

        for index, irange in enumerate(cleandata):
            with open(self.datafile, "a") as f:
                f.write("\nRange=%s" % irange)
                whoisdata = cmdline(
                    "whois -h whois.lacnic.net '%s' | grep -v '%s' | sed 1,4d | sed '$d'" % (irange, '%')).split('\n')
                for line in whoisdata:
                    f.write(line + '\n')
                f.write("\n################################################################################\n")
                print("[*] %s of %s ranges complete." % (index, total))
            time.sleep(4)

        if self.verbose:
            print("[+] LACNIC DB pull complete.")
        sys.exit()


class ARIN:
    def __init__(self, verbose, pool, cname, cemail, ccopts, routesrvs):
        self.verbose = verbose
        self.cname = cname
        self.whoisname = "whois.arin.net"
        self.rir = "ARIN"
        self.inetnumurl = "http://www.afrinic.net/en/services/whois-query/{URLDATA}"
        self.cemail = cemail
        self.countrycodes = ["AX", "AF", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU",
                             "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA",
                             "BW", "BV", "BR", "IO", "BN", "BG", "BF", "BI", "KH", "CM", "CA", "CV", "KY", "CF", "TD",
                             "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI", "HR", "CU", "CW", "CY",
                             "CZ", "DK", "DJ", "DM", "DO", "EC", "EG", "SV", "GQ", "ER", "EE", "ET", "FK", "FO", "FJ",
                             "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD", "GP",
                             "GU", "GT", "GG", "GN", "GW", "GY", "HT", "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID",
                             "IR", "IQ", "IE", "IM", "IL", "IT", "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KP", "KR",
                             "KW", "KG", "LA", "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MK", "MG", "MW",
                             "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX", "FM", "MD", "MC", "MN", "ME",
                             "MS", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", "NU", "NF",
                             "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR",
                             "QA", "RE", "RO", "RU", "RW", "SH", "BL", "KN", "LC", "MF", "PM", "VC", "WS", "SM", "ST",
                             "SA", "SN", "RS", "SC", "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES",
                             "LK", "SD", "SR", "SJ", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK",
                             "TO", "TT", "TN", "TR", "TM", "TC", "TV", "UG", "UA", "US", "AE", "GB", "UM", "UY", "UZ",
                             "VU", "VE", "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW"]
        self.ccopts = ccopts
        self.routesrvs = routesrvs
        self.pool = pool
        self.asns = []
        self.country = 'US'

    def orgsearch(self, orgs):
        org = orgs.split('"')[3]
        orghandle = orgs.split('"')[1]
        netname = None
        # get list of org networks
        orglinks = []
        fulldata = urllib.urlopen("http://whois.arin.net/rest/org/%s/nets" % orghandle)
        for line in fulldata:
            fulldata = line.split("<")
            for xline in fulldata:
                if "/rest/net/" in xline:
                    orglinks.append(xline.split(">")[1] + ".txt")

        # pull ASNs for later
        fulldata = urllib.urlopen("http://whois.arin.net/rest/org/%s/asns" % orghandle)
        for line in fulldata:
            fulldata = line.split("<")
            for xline in fulldata:
                if "/rest/asn/" in xline:
                    self.asns.append(xline.split(">")[1])

        for orglink in orglinks:
            # get cidrs for each network
            fulldata = urllib.urlopen(orglink)
            xdata = []
            for line in fulldata:
                xdata.append(line.split('\n')[0])
            for xline in xdata:
                if 'NetName' in xline:
                    if len(xline.split()) > 2:
                        netname = xline.split()[1:]
                    else:
                        netname = xline.split()[1]
                if 'Organization' in xline:
                    org = ' '.join(xline.split()[1:])
            for xline in xdata:
                if 'CIDR' in xline:
                    cidrs = xline.replace(',', '').split()[1:]
                    for cidr in cidrs:
                        if '/32' in cidr:
                            inetnum = str(IPNetwork(cidr).network)
                        else:
                            inetnum = str(IPNetwork(cidr).network) + " - " + str(IPNetwork(cidr).broadcast)
                        dictentry = BuildResultDict(cidr, inetnum, org, netname, orglink, self.country,
                                                    self.rir, None, self.verbose)
                        dictentry.build()

    def custsearch(self, custs):
        # cust = custs.split('"')[3]\
        cust = None
        custhandle = custs.split('"')[1]
        netname = None
        inetnum = None
        cidr = None
        # get list of org networks
        custlinks = []
        fulldata = urllib.urlopen("http://whois.arin.net/rest/customer/%s/nets" % custhandle)
        for line in fulldata:
            fulldata = line.split("<")
            for xline in fulldata:
                if "/rest/net/" in xline:
                    custlinks.append(xline.split(">")[1] + ".txt")

        for custlink in custlinks:
            # get cidrs for each network
            fulldata = urllib.urlopen(custlink)
            xdata = []
            for line in fulldata:
                xdata.append(line.split('\n')[0])
            for xline in xdata:
                if 'NetName' in xline:
                    if len(xline.split()) > 2:
                        netname = xline.split()[1:]
                    else:
                        netname = xline.split()[1]
                if 'Customer' in xline:
                    cust = ' '.join(xline.split()[1:])
            for yline in xdata:
                if 'CIDR' in yline and 'NetName' not in yline and 'Parent' not in yline:
                    cidrs = yline.replace(',', '').split()[1:]
                    for cidr in cidrs:
                        if '/32' in cidr:
                            inetnum = str(IPNetwork(cidr).network)
                        else:
                            inetnum = str(IPNetwork(cidr).network) + " - " + str(IPNetwork(cidr).broadcast)
                        dictentry = BuildResultDict(cidr, inetnum, cust, netname, custlink, self.country,
                                                    self.rir, None, self.verbose)
                        dictentry.build()

    def emailsearch(self, pochandle):
        neturls = []
        orgurls = []
        netname = None
        org = None
        email = None
        country = self.country
        pocs = []
        urlstream = urllib.urlopen("https://whois.arin.net/rest/poc/%s.txt" % pochandle)
        for line in urlstream:
            pocs.append(line)
        if pocs:
            for xline in pocs:
                if 'Country' in xline:
                    country = xline.split()[1]
                if 'Email' in xline:
                    email = xline.split()[1]
            urldata = urllib.urlopen("https://whois.arin.net/rest/poc/%s/nets" % pochandle)
            for yline in urldata:
                urldata = yline.split("<")
            if len(urldata) > 2:
                screenlock.acquire()
                print("\t\t[+] Found network ranges related to the email: %s." % email)
                screenlock.release()
                for zline in urldata:
                    if "handle" in zline:
                        neturls.append(zline.split(">")[1])
                for netlink in neturls:
                    netdata = urllib.urlopen(netlink + ".txt")
                    singlelookup = []
                    for line in netdata:
                        singlelookup.append(line.replace('\n', ''))
                    for xline in singlelookup:
                        if 'NetName' in xline:
                            if len(xline.split()) > 2:
                                netname = xline.split()[1:]
                            else:
                                netname = xline.split()[1]
                        if 'Organization' in xline:
                            org = ' '.join(xline.split()[1:])
                    for xline in singlelookup:
                        if 'CIDR' in xline:
                            cidrs = xline.replace(',', '').split()[1:]
                            for cidr in cidrs:
                                inetnum = str(IPNetwork(cidr).network) + " - " + str(
                                    IPNetwork(cidr).broadcast)
                                dictentry = BuildResultDict(cidr, inetnum, org, netname, netlink,
                                                            country, self.rir, email, self.verbose)
                                dictentry.build()
            else:
                if self.verbose:
                    screenlock.acquire()
                    print("\t\t[-] No network ranges related to the email %s." % email)
                    screenlock.release()

            urldata = urllib.urlopen("https://whois.arin.net/rest/poc/%s/orgs" % pochandle)
            for yline in urldata:
                urldata = yline.split("<")
            if len(urldata) > 2:
                if self.verbose:
                    screenlock.acquire()
                    print("\t\t[+] Found Orgs related to the email %s." % email)
                    screenlock.release()
                for zline in urldata:
                    if "handle" in zline:
                        orgurls.append(zline.split(">")[1])
                for orglink in orgurls:
                    orgdata = urllib.urlopen(orglink + ".txt")
                    singlelookup = []
                    for line in orgdata:
                        singlelookup.append(line.replace('\n', ''))
                    for xline in singlelookup:
                        if 'NetName' in xline:
                            if len(xline.split()) > 2:
                                netname = xline.split()[1:]
                            else:
                                netname = xline.split()[1]
                        if 'Organization' in xline:
                            org = ' '.join(xline.split()[1:])
                    for xline in singlelookup:
                        if 'CIDR' in xline:
                            cidrs = xline.replace(',', '').split()[1:]
                            for cidr in cidrs:
                                if '/32' in cidr:
                                    inetnum = str(IPNetwork(cidr).network)
                                else:
                                    inetnum = str(IPNetwork(cidr).network) + " - " + str(
                                        IPNetwork(cidr).broadcast)
                                dictentry = BuildResultDict(cidr, inetnum, org, netname,
                                                            orglink, country, self.rir, email, self.verbose)
                                dictentry.build()
            else:
                if self.verbose:
                    screenlock.acquire()
                    print("\t\t[-] No Orgs related to the email %s." % email)
                    screenlock.release()

    def runemails(self):
        # ARIN - get poc handle based on email domain
        if self.verbose:
            print("[*] Enumerating CIDRs for PoCs with the %s Email Domain via ARIN." % self.cemail)
        emails = [self.cemail]
        if self.ccopts[0] == 'y':
            if self.ccopts[1] == 'b':
                for ccode in self.countrycodes:
                    emails.append(ccode.lower() + "." + self.cemail)
            elif self.ccopts == 'a':
                for ccode in self.countrycodes:
                    emails.append(self.cemail.split('.')[0] + "." + ccode.lower())
                    emails.append(self.cemail.split('.')[0] + ".co." + ccode.lower())

        for emaildomain in emails:
            cleandata = []
            fulldata = urllib.urlopen("http://whois.arin.net/rest/pocs;domain=@%s*" % emaildomain)
            for line in fulldata:
                fulldata = line.split("<")
                for xline in fulldata:
                    if "pocRef handle" in xline:
                        cleandata.append(xline.split('"')[1])

            # validate email domains
            if cleandata:
                if self.verbose:
                    print("\t[+] Found ARIN email Records for @%s." % emaildomain)
                self.pool.map(self.emailsearch, cleandata)
            else:
                if self.verbose:
                    print("[-] No ARIN Records found for %s." % emaildomain)

    def run(self):
        for name in self.cname:
            orghtml = name.replace(' ', '%20').replace('-', '%2D').replace(',', '%2C').replace('.', '%2E').replace(
                '&', '%26')

            if self.verbose:
                print("[*] Enumerating CIDRs for %s Org Handles via ARIN" % name)

            # ARIN - get list of org networks
            # get org handles
            cleandata = []
            fulldata = urllib.urlopen("http://whois.arin.net/rest/orgs;name=%s*" % orghtml)
            for line in fulldata:
                fulldata = line.split("<")
                for xline in fulldata:
                    if "/rest/org/" in xline:
                        cleandata.append(xline)

            if cleandata:
                if self.verbose:
                    print("\t[+] Found Org Handles for %s" % name)
                self.pool.map(self.orgsearch, cleandata)
            else:
                if self.verbose:
                    print("\t[-] No Org Handles found for %s." % name)

            if self.verbose:
                print("[*] Enumerating CIDRs for %s Customer Handles via ARIN." % name)
            cleandata = []
            fulldata = urllib.urlopen("http://whois.arin.net/rest/customers;name=%s*" % orghtml)
            for line in fulldata:
                fulldata = line.split("<")
                for xline in fulldata:
                    if "/rest/customer/" in xline:
                        cleandata.append(xline)
            if cleandata:
                if self.verbose:
                    print("\t[+] Found Customer Handles for %s." % name)
                self.pool.map(self.custsearch, cleandata)
            else:
                if self.verbose:
                    print("\t[-] No Customer Handles found for %s." % name)

            # ARIN - query BGP route server
            if self.verbose:
                print("[*] Enumerating CIDRs for %s ASNs via ARIN." % name)
            if self.asns:
                if self.verbose:
                    print("\t[+] Found ASN Records for %s." % name)
                asndata = []
                asn = None
                asnnum = None
                org = None
                netname = None
                email = None
                url = "http://bgp.he.net/${asn}#_asinfo"

                for asnlink in self.asns:
                    fulldata = urllib.urlopen(asnlink)
                    for data in fulldata:
                        asndata = data.split("<")
                    for data in asndata:
                        if 'handle>AS' in data:
                            asn = data.split(">")[1]
                            asnnum = asn[2:]
                        if 'orgRef handle' in data:
                            org = data.split('"')[3]

                    try:
                        tn = telnetlib.Telnet(random.choice(self.routesrvs), '23', timeout=10)
                        tn.write("show ip bgp regexp %s\n" % asnnum)
                        tn.write("\n")
                        tn.write("\n")
                        tn.write("exit\n")
                        telnetdata = tn.read_all().split()
                        tn.close()
                        time.sleep(2)
                        ranges = []
                        for ipadd in telnetdata:
                            if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$",
                                        ipadd) or re.match(
                                    r"^i([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$", ipadd):
                                if 'i' in ipadd:
                                    ranges.append(ipadd[1:])
                                else:
                                    ranges.append(ipadd)

                        if ranges:
                            # get cidrs for each network
                            for cidradd in ranges:
                                cidr = cidradd
                                inetnum = str(IPNetwork(cidr).network) + " - " + str(IPNetwork(cidr).broadcast)
                                asnhtml = asn.replace(' ', '%20').replace('-', '%2D').replace(',', '%2C').replace(
                                    '.', '%2E').replace('&', '%26')
                                asnurl = url.replace("${asn}", asnhtml)

                                dictentry = BuildResultDict(cidr, inetnum, org, netname, asnurl, self.country, self.rir,
                                                            email, self.verbose)
                                dictentry.build()
                    except (socket.timeout, socket.error):
                        if self.verbose:
                            screenlock.acquire()
                            print("\t[!] Connection timed out or refused for ASN %s. Skipping." % asn)
                            screenlock.release()
                        pass

            else:
                if self.verbose:
                    print("[-] No ASN Records found for %s." % name)


class BuildResultDict:
    def __init__(self, cidr, inet, org, netname, inetnumurl, country, rir, email, verbose):
        self.cidr = cidr
        self.inet = inet
        self.org = org
        self.netname = netname
        self.inetnumurl = inetnumurl
        self.country = country
        self.rir = rir
        self.email = email
        self.verbose = verbose

    def build(self):
        exists = False
        for iprange in combined_whoisresults.keys():
            if IPNetwork(self.cidr) in IPNetwork(iprange):
                exists = True

        if self.email:
            if self.cidr in combined_whoisresults.keys():
                combined_whoisresults[self.cidr]["email"] = self.email

        if not exists:
            combined_whoisresults[self.cidr] = {}
            combined_whoisresults[self.cidr]["range"] = self.inet
            combined_whoisresults[self.cidr]["org"] = self.org
            combined_whoisresults[self.cidr]["netname"] = self.netname
            combined_whoisresults[self.cidr]["inetnumurl"] = self.inetnumurl
            combined_whoisresults[self.cidr]["country"] = self.country
            combined_whoisresults[self.cidr]["rir"] = self.rir
            if self.email:
                combined_whoisresults[self.cidr]["email"] = self.email
            else:
                combined_whoisresults[self.cidr]["email"] = ""
        else:
            if self.verbose:
                print("[!] %s already exists in the data dictionary." % self.cidr)


class CSVout:
    def __init__(self, filename, verbose):
        if filename.lower().endswith('.csv'):
            self.filename = filename
        else:
            self.filename = filename + '.csv'

        self.verbose = verbose
        self.QUOTE = '"'
        self.sep = ','
        self.f = open(self.filename, 'w')

    def csvlinewrite(self, row):
        self.f.write(self.joinline(row) + '\n')

    def closecsv(self):
        self.f.close()
        self.f = None

    def quote(self, value):
        if not isinstance(value, str) or not isinstance(value, unicode):
            value = str(value)
        return self.QUOTE + value + self.QUOTE

    def joinline(self, row):
        return self.sep.join([self.quote(value) for value in row])

    def write(self):
        self.csvlinewrite(['IP Range', 'CIDR', 'Organization|Customer', 'Network Name', 'Country', 'RIR Database', 'URL', "Associated Email"])
        for cidr in combined_whoisresults:
            row = [combined_whoisresults[cidr]["range"], cidr, combined_whoisresults[cidr]["org"], combined_whoisresults[cidr]["netname"], combined_whoisresults[cidr]["country"], combined_whoisresults[cidr]["rir"], combined_whoisresults[cidr]["inetnumurl"], combined_whoisresults[cidr]["email"]]
            self.csvlinewrite(row)
        self.closecsv()
        if self.verbose:
            print('[%s] Created %s' % ('*', self.filename))

class Main:
    def __init__(self, verbose, output, threads, updatelacnicdb, ripe, lacnic, afrinic, apnic, arin):
        self.routeservers = ['64.62.142.154',  # Hurricane Electric: route-server.he.net
                             '203.178.141.138',  # TELXATL: route-views.telxatl.routeviews.org
                             '207.162.219.54']  # NWAX: route-views.nwax.routeviews.org
        self.datafile = "lacnicdb.txt"
        self.datafilebu = "lacnicdb.txt.bu"
        self.uagent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36"
        self.clientname = []
        self.cemaildomain = ""
        self.countrycodeopts = []
        self.cfolder = ""

        self.verbose = verbose
        self.output = output
        self.updatelacnicdb = updatelacnicdb
        self.ripe = ripe
        self.lacnic = lacnic
        self.afrinic = afrinic
        self.apnic = apnic
        self.arin = arin
        self.threadpool = threads

    def run(self):
        # Check if the update LACNIC DB option was chosen and run updater if the user didn't mess up and pick
        # other options with it.
        if self.updatelacnicdb:
            if self.ripe or self.lacnic or self.afrinic or self.apnic or self.arin:
                print("[!] You cannot use the --updatelacnicdb flag with any query flags.")
                sys.exit()
            else:
                lupdate = LACNICupdate(self.verbose, self.datafile, self.datafilebu)
                try:
                    lupdate.run()
                except KeyboardInterrupt:
                    lupdate.u_term()

        if self.lacnic:
            if not os.path.isfile(self.datafile):
                print("[!] %s could not be located." % self.datafile)
                print("[!] %s must be created first with the -u flag, this will take about 28 hours because of rate "
                      "limiting within LACNIC." % self.datafile)
                sys.exit()

        # Get client name
        while True:
            choice = raw_input("Enter Client Name: ")
            if choice.lower() == '':
                print("Client name is empty, please try again.")
            else:
                # Check for names containing '&' or 'and' to search for both instances
                if '&' in choice:
                    print("[*] Client name contains an '&'. We will search for name with 'and' also.")
                    self.clientname.append(choice)
                    self.clientname.append(choice.replace("&", "and"))
                elif 'and' in choice:
                    print("[*] Client name contains an 'and'. We will search for name with '&' also.")
                    self.clientname.append(choice)
                    self.clientname.append(choice.replace("and", "&"))
                else:
                    self.clientname.append(choice)
                if ' ' in choice:
                    print("[*] Client name contains a space. We will search for name without spaces also.")
                    self.clientname.append(choice)
                    self.clientname.append(''.join(choice.split()))
                choice = ''
                self.cfolder = self.clientname[0]
                break

        while True:
            choice = raw_input("Does %s use any other alternative names? (i.e. PricewaterhouseCoopers, PwC) Y or N: " % self.clientname[0])
            if choice.lower() != 'y' and choice.lower() != 'n' and choice.lower() != 'yes' and choice.lower() != 'no':
                print("[!] Please choose Y or N.")
            else:
                if choice.lower() == 'y':
                    choice = ''
                    while True:
                        choice = raw_input(
                            "Please enter alternative client name for %s: " % self.clientname[0])
                        if choice.lower() == '':
                            print("Client name is empty, please try again.")
                        else:
                            # Check for names containing '&' or 'and' or space to search for both instances
                            if '&' in choice:
                                print("[*] Client name contains an '&'. We will search for name with 'and' also.")
                                self.clientname.append(choice)
                                self.clientname.append(choice.replace("&", "and"))
                            elif 'and' in choice:
                                print("[*] Client name contains an 'and'. We will search for name with '&' also.")
                                self.clientname.append(choice)
                                self.clientname.append(choice.replace("and", "&"))
                            else:
                                self.clientname.append(choice)
                            if ' ' in choice:
                                print("[*] Client name contains a space. We will search for name without spaces also.")
                                self.clientname.append(choice)
                                self.clientname.append(''.join(choice.split()))
                        break
                else:
                    break


        # Get client email domain
        while True:
            choice = raw_input("Enter Client Email Domain: ")
            if choice.lower() == '':
                print("[!] Client email domain is empty, please try again.")
            elif not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-\.]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{0,3}$", choice):
                print("[!] %s is not a valid domain format" % choice)
                print("Ex: washingtonpost.com or washington-post.com, please try again.")
            else:
                self.cemaildomain = choice
                choice = ''
                break

        # Check if country codes are used in email address
        while True:
            choice = raw_input("Does %s use country codes in email addresses? Y or N: " % self.cemaildomain)
            if choice.lower() != 'y' and choice.lower() != 'n' and choice.lower() != 'yes' and choice.lower() != 'no':
                print("[!] Please choose Y or N.")
            else:
                self.countrycodeopts.append(choice)
                if choice.lower() == 'y':
                    choice = ''
                    # Check country code position in email address
                    while True:
                        choice = raw_input(
                            "Are country codes before (B) or after (A) the domain name %s? B or A:" % self.cemaildomain)
                        if choice.lower() != 'a' and choice.lower() != 'b' and choice.lower() != 'before' and choice.lower() != 'after':
                            print("[!] Please choose B or A.")
                        else:
                            self.countrycodeopts.append(choice)
                            break
                    break
                else:
                    break

        # Run all chosen RIR queries
        if self.arin:
            if self.verbose:
                print("[*] Running ARIN queries.")
            arin = ARIN(self.verbose, self.threadpool, self.clientname, self.cemaildomain, self.countrycodeopts, self.routeservers)
            arin.run()
            arin.runemails()

        if self.ripe:
            if self.verbose:
                print("[*] Running RIPE queries.")
            ripe = RIPE(self.verbose, self.threadpool, self.clientname)
            ripe.run()

        if self.apnic:
            if self.verbose:
                print("[*] Running APNIC queries.")
            apnic = APNIC(self.verbose, self.threadpool, self.clientname, self.cemaildomain)
            apnic.run()

        if self.lacnic:
            if self.verbose:
                print("[*] Running LACNIC queries.")
            lacnic = LACNIC(self.verbose, self.threadpool, self.clientname, self.cemaildomain, self.routeservers, self.datafile)
            lacnic.run()

        if self.afrinic:
            if self.verbose:
                print("[*] Running AfriNIC queries.")
            afrinic = AfriNIC(self.verbose, self.threadpool, self.clientname, self.cemaildomain)
            afrinic.run()

        # print(combined_whoisresults)
        if self.verbose:
            print("[+] Lookup complete!")
        if self.output:
            output = CSVout(self.cfolder, self.verbose)
            output.write()
        return combined_whoisresults, self.cemaildomain


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RIR CIDR enumeration tool')
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
    # parser.add_argument('-o' '--outputfile', default=False, action='store_true', help='Creates .csv of results')
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
    output = True
    tpool = ThreadPool(int(args.threads))
    try:
        go = Main(args.verbose, output, tpool, args.updatelacnicdb, ripe, lacnic, afrinic, apnic, arin)
        go.run()
    except KeyboardInterrupt:
        print("[!] Caught ctrl+c, aborting . . . ")
        sys.exit()
