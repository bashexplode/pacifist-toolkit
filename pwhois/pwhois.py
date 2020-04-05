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
# Output saved to a csv file
#
# Author: Jesse Nebling (@bashexplode)

import whois
import sys
import argparse
from multiprocessing.dummy import Pool as ThreadPool
import threading
import re
import urllib.error as HTTPError
import urllib.request as urllib
from netaddr import *
import random
import socket
import telnetlib
import time
import os

screenlock = threading.Semaphore(value=1)
combined_whoisresults = {}  # Dict to consolidate results from all modules
verbose = False

def existcheck(inetnumurl, verbose):
    exists = False
    for iprange in list(combined_whoisresults):
        if combined_whoisresults[iprange]["inetnumurl"] == inetnumurl:
            exists = True
            if verbose:
                screenlock.acquire()
                print("\t[!] %s already exists in the data dictionary. Skipping lookup" % inetnumurl)
                screenlock.release()
    return exists

def whoistrycatch(query, whoisurl):
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

def urlopentrycatch(link):
    try:
        response = urllib.urlopen(link)
        responsedecode = response.read().decode('utf-8')
        try:
            response.close()
        except NameError or AttributeError:
            pass
        return responsedecode
    except HTTPError.HTTPError:
        if verbose:
            screenlock.acquire()
            print("\t[-] 404 error for: %s" % link)
            screenlock.release()
        return None
    except HTTPError.URLError:
        time.sleep(5)
        try:
            response = urllib.urlopen(link)
            responsedecode = response.read().decode('utf-8')
            try:
                response.close()
            except NameError or AttributeError:
                pass
            return responsedecode
        except HTTPError.HTTPError:
            if verbose:
                screenlock.acquire()
                print("\t[-] 404 error for: %s" % link)
                screenlock.release()
            return None
        except HTTPError.URLError:
            time.sleep(5)
            try:
                response = urllib.urlopen(link)
                responsedecode = response.read().decode('utf-8')
                try:
                    response.close()
                except NameError or AttributeError:
                    pass
                return responsedecode
            except HTTPError.HTTPError:
                if verbose:
                    screenlock.acquire()
                    print("\t[-] 404 error for: %s" % link)
                    screenlock.release()
                return None
            except HTTPError.URLError:
                print("\t[!] Tried to reconnect 3 times and failed, sorry")

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
        for iprange in list(combined_whoisresults):
            if IPNetwork(self.cidr) in IPNetwork(iprange):
                exists = True

        if self.email:
            if self.cidr in list(combined_whoisresults):
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


class WhoISparser:
    def __init__(self, verbose, pool, name, whoisurl, rir, inetnumurl, emaildomain):
        self.verbose = verbose
        self.name = name
        self.whoisurl = whoisurl
        self.inetnumurl = inetnumurl
        self.rir = rir
        self.emaildomain = emaildomain
        self.fullwhoisdata = []
        self.netnamelist = []
        self.pool = pool
        self.emaillist = []
        self.sanilist = []

    def initializewhoisdata(self):
        if self.verbose:
            print("[*] Enumerating CIDRs for %s Org Names via %s" % (self.name, self.rir))

        whoisdata = whoistrycatch(self.name, self.whoisurl)
        for line in whoisdata:
            if line and not re.match('^%', line):
                self.fullwhoisdata.append(line)

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
            singlewhoisdata = []
            whoisdata = whoistrycatch(inet, self.whoisurl)

            for line in whoisdata:
                if line and not re.match('^%', line):
                    singlewhoisdata.append(line)
            inetnumhtml = inet.replace(' ', '%20').replace('-', '%2D').replace(',', '%2C').replace('.', '%2E').replace(
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
        self.fullwhoisdata = []
        whoisdata = whoistrycatch(email, self.whoisurl)
        for line in whoisdata:
            if line and not re.match('^%', line):
                self.fullwhoisdata.append(line)
        self.pool.map(self.inetexec, self.fullwhoisdata)

    def emaillookup(self):
        self.pool.map(self.emailsearch, self.fullwhoisdata)

        for email in self.sanilist:
            if email not in self.emaillist:
                self.emaillist.append(email)

        self.pool.map(self.emailexec, self.emaillist)


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
                    email = None
                    singlewhoisdata.append(whoisdata[index])
                    for x in range(1, 40):
                        if '######################' in whoisdata[index - x]:
                            break
                        singlewhoisdata.append(whoisdata[index - x])
                    for x in range(1, 40):
                        if '######################' in whoisdata[index + x]:
                            break
                        singlewhoisdata.append(whoisdata[index + x])

                    for sline in singlewhoisdata:
                        if 'owner:' in sline:
                            org = ' '.join(sline.split()[1:])
                            break

                    for sline in singlewhoisdata:
                        if 'ownerid:' in sline:
                            netname = ' '.join(sline.split()[1:])
                        if 'e-mail' in sline:
                            email = re.findall(r'[A-Za-z0-9\-\.]{1,100}@[A-Za-z0-9\-\.]{1,30}\.[A-Za-z\.]{1,5}', sline)[
                                0]

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
                            tn.write(b"show ip bgp regexp %s\n" % lookupitem[2:].encode('ascii'))
                            tn.write(b"\n")
                            tn.write(b"\n")
                            tn.write(b"exit\n")
                            telnetdata = tn.read_all().split()
                            tn.close()
                            time.sleep(2)
                            ranges = []
                            for ipadd in telnetdata:
                                if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$",
                                            ipadd.decode('utf-8')) or re.match(
                                    r"^i([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$",
                                    ipadd.decode('utf-8')):
                                    if 'i' in ipadd.decode('utf-8'):
                                        ranges.append(ipadd.decode('utf-8')[1:])
                                    else:
                                        ranges.append(ipadd.decode('utf-8'))

                            if ranges:
                                # get cidrs for each network
                                for cidradd in ranges:
                                    cidr = cidradd
                                    inetnum = str(IPNetwork(cidr).network) + " - " + str(IPNetwork(cidr).broadcast)
                                    asnhtml = lookupitem.replace(' ', '%20').replace('-', '%2D').replace(',',
                                                                                                         '%2C').replace(
                                        '.', '%2E').replace('&', '%26')
                                    asnurl = url.replace("${asn}", asnhtml)

                                    dictentry = BuildResultDict(cidr, inetnum, org, netname, asnurl, country,
                                                                self.rir,
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
            with open(self.datafile, encoding='ISO-8859-1') as f:
                whoisdata = list(filter(None, f.read().split('\n')))

            owners = []
            inet = []
            asn = []
            emails = []

            for line in whoisdata:
                if 'owner:' in line:
                    if name.lower() in line.lower():
                        owners.append(line)
                if ('@' + self.cemail).lower() in line.lower():
                    emails.append(re.findall(r'[A-Za-z0-9\-\.]{1,100}@[A-Za-z0-9\-\.]{1,30}\.[A-Za-z\.]{1,5}', line)[0])

            if owners or emails:
                if self.verbose:
                    print("[+] Found LACNIC Records for %s" % name)
                if owners:
                    for index, line in enumerate(whoisdata):
                        for owner in owners:
                            if owner.lower() in line.lower():
                                for x in range(1, 5):
                                    if 'inetnum' in whoisdata[index - x]:
                                        inet.append(" ".join(whoisdata[index - x].split()[1:]))
                                    if 'aut-num' in whoisdata[index - x] and 'N/A' not in whoisdata[index - x]:
                                        asn.append(" ".join(whoisdata[index - x].split()[1:]))

                    if inet:
                        inet = sorted(set(inet))
                        self.lutype = 'inetnum'
                        # query by inetnum
                        self.singlelookup(whoisdata, inet)

                    if asn:
                        asn = sorted(set(asn))
                        self.lutype = 'asn'
                        self.singlelookup(whoisdata, asn)

                if emails:
                    emails = sorted(set(emails))
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
        self.whoisname = "whois.lacnic.net"

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

        response = urlopentrycatch("http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest")
        fulldata = response.split('\n')
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
                if self.verbose:
                    print("[*] Pulling base whois data for %s via LACNIC" % irange)
                lacnicwhoisdata = whoistrycatch(irange, self.whoisname)

                for line in lacnicwhoisdata:
                    if line and not re.match('^\%', line):
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
        self.emails = []

    def orgsearch(self, orgid):
        # get list of org networks
        orglinks = []
        try:
            response = urlopentrycatch("http://whois.arin.net/rest/org/%s/nets" % orgid)
            if response is None:
                return

            for orglink in re.findall(r'https://whois\.arin\.net/rest/net/[A-Z0-9a-z\-]{0,30}', response):
                insecurelink = re.sub(r'https://', "http://", orglink)
                orglinks.append(insecurelink + ".txt")
        except HTTPError.HTTPError as e:
            if self.verbose:
                screenlock.acquire()
                print("\t[-] 404 error retrieving network range for OrgID %s" % orgid)
                screenlock.release()

        # pull ASNs for later
        try:
            response = urlopentrycatch("http://whois.arin.net/rest/org/%s/asns" % orgid)
            if response is None:
                return

            for asnlink in re.findall(r'https://whois\.arin\.net/rest/asn/AS[0-9]{0,8}', response):
                insecurelink = re.sub(r'https://', "http://", asnlink)
                self.asns.append(insecurelink)
        except HTTPError.HTTPError as e:
            if self.verbose:
                screenlock.acquire()
                print("\t[-] 404 error retrieving ASN for OrgID %s" % orgid)
                screenlock.release()

        for orglink in orglinks:
            # get cidrs for each network
            self.restnetlookup(orglink, None, "OrgID", orgid)

    def custsearch(self, customer):
        rgx = re.compile('[()]')
        netname = rgx.sub('', re.findall(r'\([A-Z0-9-]{1,30}\)', customer)[1])
        inetnum = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*', customer)[0]
        cidr = str(IPRange(inetnum.split()[0], inetnum.split()[2]).cidrs()[0])
        cust = re.findall(r'^.*\(C[0-9]{1,15}\)', customer)[0]
        custlink = ("https://whois.arin.net/rest/net/%s.txt" % netname)
        dictentry = BuildResultDict(cidr, inetnum, cust, netname, custlink, self.country,
                                    self.rir, None, self.verbose)
        dictentry.build()

    def restnetlookup(self, link, email, origin, originid):
        try:
            if existcheck(link, self.verbose):
                return
            # Keep getting TLS connection errors on Windows
            insecurelink = re.sub(r'https://', "http://", link)
            response = urlopentrycatch(insecurelink)
            if response is None:
                return

            netname = re.findall(r'NetName:.*', response)[0].split()[1]
            org = " ".join(re.findall(r'Organization:.*', response)[0].split()[1:])
            cidrs = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}', response)
            for cidr in cidrs:
                if '/32' in cidr:
                    inetnum = str(IPNetwork(cidr).network)
                else:
                    inetnum = str(IPNetwork(cidr).network) + " - " + str(IPNetwork(cidr).broadcast)
                dictentry = BuildResultDict(cidr, inetnum, org, netname, link, self.country,
                                            self.rir, email, self.verbose)
                dictentry.build()

        except HTTPError.HTTPError as e:
            if self.verbose:
                screenlock.acquire()
                print("\t[-] 404 error retrieving CIDRs for %s %s" % origin, originid)
                screenlock.release()

    def emailsearch(self, poclink):
        pochandle = re.findall(r'[A-Za-z0-9\-\ ]{0,30}$', poclink)[0]

        try:
            response = urlopentrycatch(poclink)
            if response is None:
                return

            email = re.findall(r'[A-Za-z0-9\-\.]{0,30}@[A-Za-z0-9\-\.]{0,30}', response)[0]

            try:
                response = urlopentrycatch("http://whois.arin.net/rest/poc/%s/nets" % pochandle)
                if response is None:
                    return

                if response:
                    if self.verbose:
                        screenlock.acquire()
                        print("\t[+] Found network ranges related to the email: %s." % email)
                        screenlock.release()
                    for netlink in re.findall(r'https://whois\.arin\.net/rest/net/[A-Z0-9a-z\-]{0,30}', response):
                        insecurelink = re.sub(r'https://', "http://", netlink)
                        self.restnetlookup(insecurelink + '.txt', email, "net lookup POC email", email)

                else:
                    if self.verbose:
                        screenlock.acquire()
                        print("\t[-] No network ranges related to the email %s." % email)
                        screenlock.release()
            except HTTPError.HTTPError as e:
                if self.verbose:
                    print("\t[-] 404 error retrieving CIDRs for POC %s" % pochandle)

            try:
                response = urlopentrycatch("http://whois.arin.net/rest/poc/%s/orgs" % pochandle)
                if response is None:
                    return

                if self.verbose:
                    screenlock.acquire()
                    print("\t[+] Found Orgs related to the email %s." % email)
                    screenlock.release()
                orglinks = re.findall(r'https://whois\.arin\.net/rest/org/[A-Z0-9a-z\-]{0,30}', response)
                orglinks = sorted(set(orglinks))

                for orglink in orglinks:
                    try:
                        orglink = re.sub(r'https://', "http://", orglink)
                        response = urlopentrycatch(orglink + "/nets")
                        if response is None:
                            return

                        for netlink in re.findall(r'https://whois\.arin\.net/rest/net/[A-Z0-9a-z\-]{0,30}',
                                                  response):
                            insecurelink = re.sub(r'https://', "http://", netlink)
                            self.restnetlookup(insecurelink + '.txt', email, "org lookup POC email", email)
                    except HTTPError.HTTPError as e:
                        if self.verbose:
                            screenlock.acquire()
                            print("\t[-] 404 error retrieving network range for orgs related to POC %s" % email)
                            screenlock.release()

                    # pull ASNs for later
                    try:
                        response = urlopentrycatch(orglink + "/asns")
                        if response is None:
                            return

                        for asnlink in re.findall(r'https://whois\.arin\.net/rest/asn/AS[0-9]{0,8}', response):
                            insecurelink = re.sub(r'https://', "http://", asnlink)
                            self.asns.append(insecurelink)
                    except HTTPError.HTTPError as e:
                        if self.verbose:
                            screenlock.acquire()
                            print("\t[-] 404 error retrieving ASN for orgs related to POC %s" % email)
                            screenlock.release()

                else:
                    if self.verbose:
                        screenlock.acquire()
                        print("\t[-] No Orgs related to the email %s." % email)
                        screenlock.release()
            except HTTPError.HTTPError as e:
                if self.verbose:
                    print("\t[-] 404 error retrieving Orgs for POC %s" % pochandle)

        except HTTPError.HTTPError as e:
            if self.verbose:
                screenlock.acquire()
                print("\t[-] 404 error retrieving CIDRs for POC %s" % pochandle)
                screenlock.release()

    def threadedemails(self, emaildomain):
        try:
            response = urlopentrycatch("http://whois.arin.net/rest/pocs;domain=@%s*" % emaildomain)
            if response is None:
                return

            poclinks = []
            for poclink in re.findall(r'https://whois\.arin\.net/rest/poc/[A-Za-z0-9\-]{0,30}', response):
                insecurelink = re.sub(r'https://', "http://", poclink)
                poclinks.append(insecurelink)

            # validate email domains
            if poclinks:
                if self.verbose:
                    print("\t[+] Found ARIN email Records for @%s." % emaildomain)
                self.pool.map(self.emailsearch, poclinks)
            else:
                if self.verbose:
                    print("[-] No ARIN Records found for %s." % emaildomain)
        except HTTPError.HTTPError as e:
            if self.verbose:
                screenlock.acquire()
                print("\t[-] 404 error retrieving POCs for email domain %s" % emaildomain)
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

        self.pool.map(self.threadedemails, emails)

    def asnlinklookup(self, asnlink):
        netname = None
        email = None
        url = "http://bgp.he.net/${asn}#_asinfo"

        try:
            response = urlopentrycatch(asnlink)
            if response is None:
                return

            asn = re.findall(r'AS[0-9]{1,10}', response)[0]
            asnnum = asn[2:]
            org = re.findall(r'name\=\"[A-Za-z0-9\ \,\-\.]{1,100}\"', response)[0].split('"')[1]
            try:
                tn = telnetlib.Telnet(random.choice(self.routesrvs), '23', timeout=10)
                tn.write(b"show ip bgp regexp %s\n" % asnnum.encode('ascii'))
                tn.write(b"\n")
                tn.write(b"\n")
                tn.write(b"exit\n")
                telnetdata = tn.read_all().split()
                tn.close()
                time.sleep(2)
                ranges = []
                for ipadd in telnetdata:
                    if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$",
                                ipadd.decode('utf-8')) or re.match(
                        r"^i([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])?$", ipadd.decode('utf-8')):
                        if 'i' in ipadd.decode('utf-8'):
                            ranges.append(ipadd.decode('utf-8')[1:])
                        else:
                            ranges.append(ipadd.decode('utf-8'))

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
        except HTTPError.HTTPError as e:
            if self.verbose:
                screenlock.acquire()
                print("\t[-] 404 error retrieving ASN information for %s" % asn)
                screenlock.release()

    def run(self):
        for name in self.cname:
            orgitems = []
            customeritems = []
            if self.verbose:
                print("[*] Pulling base whois data for %s via ARIN" % name)
            querystring = name + "*"
            arinwhoisdata = whoistrycatch(querystring, self.whoisname)

            for line in arinwhoisdata:
                if '(' in line:
                    if '(C' in line:
                        customeritems.append(line)
                    else:
                        orgitems.append(line)

            rgx = re.compile('[()]')
            orgids = []
            for orgitem in orgitems:
                orgids.append(rgx.sub('', re.findall(r'\(.*\)', orgitem)[0]))

            if self.verbose:
                print("[*] Enumerating CIDRs for %s Org Handles via ARIN" % name)

            if orgids:
                if self.verbose:
                    print("\t[+] Found Org Handles for %s" % name)
                self.pool.map(self.orgsearch, orgids)
            else:
                if self.verbose:
                    print("\t[-] No Org Handles found for %s." % name)

            if self.verbose:
                print("[*] Enumerating CIDRs for %s Customer Handles via ARIN." % name)

            if customeritems:
                if self.verbose:
                    print("\t[+] Found Customer Handles for %s." % name)
                for customeritem in customeritems:
                    self.custsearch(customeritem)
            else:
                if self.verbose:
                    print("\t[-] No Customer Handles found for %s." % name)

            # ARIN - query BGP route server
            if self.verbose:
                print("[*] Enumerating CIDRs for %s ASNs via ARIN." % name)
            if self.asns:
                self.asns = sorted(set(self.asns))
                if self.verbose:
                    print("\t[+] Found ASN Records for %s." % name)
                self.pool.map(self.asnlinklookup, self.asns)
            else:
                if self.verbose:
                    print("[-] No ASN Records found for %s." % name)


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
        if not isinstance(value, str):
            value = str(value)
        return self.QUOTE + value + self.QUOTE

    def joinline(self, row):
        return self.sep.join([self.quote(value) for value in row])

    def write(self):
        self.csvlinewrite(
            ['IP Range', 'CIDR', 'Organization|Customer', 'Network Name', 'Country', 'RIR Database', 'URL',
             "Associated Email"])
        for cidr in combined_whoisresults:
            row = [combined_whoisresults[cidr]["range"], cidr, combined_whoisresults[cidr]["org"],
                   combined_whoisresults[cidr]["netname"], combined_whoisresults[cidr]["country"],
                   combined_whoisresults[cidr]["rir"], combined_whoisresults[cidr]["inetnumurl"],
                   combined_whoisresults[cidr]["email"]]
            self.csvlinewrite(row)
        self.closecsv()
        if self.verbose:
            print('[%s] Created %s' % ('*', self.filename))


class Main:
    def __init__(self, verbosity, output, threads, updatelacnicdb, ripe, lacnic, afrinic, apnic, arin):
        self.verbose = verbosity
        self.clientname = []
        self.cemaildomain = ""
        self.countrycodeopts = []
        self.cfolder = ""
        self.datafile = "lacnicdb.txt"
        self.datafilebu = "lacnicdb.txt.bu"

        self.output = output
        self.updatelacnicdb = updatelacnicdb
        self.ripe = ripe
        self.lacnic = lacnic
        self.afrinic = afrinic
        self.apnic = apnic
        self.arin = arin
        self.threadpool = threads

        routeserverhostnames = ["route-server.he.net",  # Hurricane Electric
                                "route-views.nwax.routeviews.org",  # Route-Views NWAX
                                "route-views.chicago.routeviews.org",  # Route-Views Chicago
                                "route-views.sfmix.routeviews.org",  # Route-Views SanFrancisco
                                "route-server.eastlink.ca"]  # Eastlink
        self.routeservers = []
        for routeserverhostname in routeserverhostnames:
            try:
                rs = socket.gethostbyname(routeserverhostname)
                self.routeservers.append(rs)
            except:
                if self.verbose:
                    print("[-] An IP address for route server %s could not be resolved" % routeserverhostname)

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
            choice = input("Enter Client Name: ")
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
            choice = input(
                "Does %s use any other alternative names? (i.e. Microsoft, MS) Y or N: " % self.clientname[0])
            if choice.lower() != 'y' and choice.lower() != 'n' and choice.lower() != 'yes' and choice.lower() != 'no':
                print("[!] Please choose Y or N.")
            else:
                if choice.lower() == 'y':
                    choice = ''
                    while True:
                        choice = input(
                            "Please enter alternative client name for %s: " % self.clientname[0])
                        if choice.lower() == '':
                            print("Client name is empty, please try again.")
                        else:
                            # Check for names containing '&' or 'and' or space to search for both instances
                            if '&' in choice:
                                print(
                                    "[*] Client name contains an '&'. We will search for name with 'and' also.")
                                self.clientname.append(choice)
                                self.clientname.append(choice.replace("&", "and"))
                            elif 'and' in choice:
                                print(
                                    "[*] Client name contains an 'and'. We will search for name with '&' also.")
                                self.clientname.append(choice)
                                self.clientname.append(choice.replace("and", "&"))
                            else:
                                self.clientname.append(choice)
                            if ' ' in choice:
                                print(
                                    "[*] Client name contains a space. We will search for name without spaces also.")
                                self.clientname.append(choice)
                                self.clientname.append(''.join(choice.split()))
                        break
                else:
                    break

        # Get client email domain
        while True:
            choice = input("Enter Client Email Domain: ")
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
            choice = input("Does %s use country codes in email addresses? Y or N: " % self.cemaildomain)
            if choice.lower() != 'y' and choice.lower() != 'n' and choice.lower() != 'yes' and choice.lower() != 'no':
                print("[!] Please choose Y or N.")
            else:
                self.countrycodeopts.append(choice)
                if choice.lower() == 'y':
                    choice = ''
                    # Check country code position in email address
                    while True:
                        choice = input(
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

            arin = ARIN(self.verbose, self.threadpool, self.clientname, self.cemaildomain, self.countrycodeopts,
                        self.routeservers)
            arin.runemails()
            arin.run()
            # Wait for threads to finish up
            time.sleep(4)

        if self.ripe:
            if self.verbose:
                print("[*] Running RIPE queries.")
            ripe = RIPE(self.verbose, self.threadpool, self.clientname)
            ripe.run()
            # Wait for threads to finish up
            time.sleep(4)

        if self.apnic:
            if self.verbose:
                print("[*] Running APNIC queries.")
            apnic = APNIC(self.verbose, self.threadpool, self.clientname, self.cemaildomain)
            apnic.run()
            # Wait for threads to finish up
            time.sleep(4)

        if self.lacnic:
            if self.verbose:
                print("[*] Running LACNIC queries.")
            lacnic = LACNIC(self.verbose, self.threadpool, self.clientname, self.cemaildomain, self.routeservers,
                            self.datafile)
            lacnic.run()

        if self.afrinic:
            if self.verbose:
                print("[*] Running AfriNIC queries.")
            afrinic = AfriNIC(self.verbose, self.threadpool, self.clientname, self.cemaildomain)
            afrinic.run()

        if self.verbose:
            print("[+] Lookup complete!")

        if self.output:
            output = CSVout(self.cfolder, self.verbose)
            output.write()
            print("[+] Output written to: %s" % self.cfolder)
        return combined_whoisresults, self.cemaildomain

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
   *c    ..    $$     " d  @ jL # jL #    d  pwhois.py
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
    parser.add_argument('-T', '--threads', default=1, help='Specify how many threads to use. [Default = 1]')
    # parser.add_argument('-q', '--query', default=False, help='whois query')
    # parser.add_argument('-d', '--emaildomain', default=False, help='email domain')

    args = parser.parse_args()
    if not (args.ripe or args.lacnic or args.afrinic or args.apnic or args.arin or args.all):
        parser.error('[!] Please select a RIR database with -r (RIPE), -l (LACNIC), -f (AfriNIC), -p (APNIC), '
                     '-a (ARIN), or all with -A.')
        sys.exit()

    if args.verbose:
        verbose = True

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
        go.banner()
        go.run()

    except KeyboardInterrupt:
        print("[!] Caught ctrl+c, aborting . . . ")
        sys.exit()
