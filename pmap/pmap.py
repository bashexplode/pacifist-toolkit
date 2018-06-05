#!/usr/bin/env python
# pmap.py version 2.0
#        .ed"""" "^^^^**mu__
#      -"                  ""*m__
#    ."             mwu___      "Ns
#   /               ug___"9*u_     "q_
#  d  3             ,___"9*u_"9w_    "u_
#  $  *             ,__"^m,_"*s_"q_    9_
# .$  ^c            __"9*,_"N_ 9u "s    "M
# d$L  4.           ""^m__"q_"*_ 4_ b    `L
# $$$$b ^ceeeee.    "*u_ 9u "s ?p 0_ b    9p
# $$$$P d$$$$F $ $  *u_"*_ 0_`k 9p # `L    #
# 3$$$F "$$$$b   $  s 5p 0  # 7p # ]r #    0
#  $$P"  "$$b   .$  `  B jF 0 jF 0 jF 0    t
#   *c    ..    $$     " d  @ jL # jL #    d
#     %ce""    $$$  m    " d _@ jF 0 jF    0
#      *$e.    ***  jm*      # jF g" 0    jF
#       $$$      4  __a*" _    " J" 0     @
#      $"'$=e....$  "__a*^"_s   " jP    _0
#      $  *=%4.$ L  ""__a*@"_w-        j@
#      $   "%*ebJL  """__a*^"_a*     _p"
#       %..      4  ^^""___m*"     _y"
#        $$$e   z$  e*^F""      __*"
#         "*$c  "$          __a*"
#           """*$$______aw*^""
# Pacifist Toolkit by Jesse Nebling (@bashexplode)
# Censys, sanitization, output, and execution functions created by Jesse Nebling (@bashexplode)
# Original Shodan function created by Max Arthur
# -----------------------------------------------

from __future__ import print_function
from colorama import init, Fore

from netaddr import *
import argparse
import requests
import os
import sys
import socket
import random
from multiprocessing.dummy import Pool as ThreadPool
import threading

init(autoreset=True)
screenlock = threading.Semaphore(value=1)

class Shodan:
    def __init__(self, ip, svclookup, proxyset):
        # Set Shodan API Key here
        self.shodan_key = ""

        if self.shodan_key:
            self.API_URL = "https://api.shodan.io/shodan/host/%s?key=%s" % (ip, self.shodan_key)
        else:
            print(
                "[%s] No Shodan API key set in the script, please either add your own API key into the Shodan class or "
                "use the -c flag to specify only using Censys.io." % (Fore.LIGHTRED_EX + '!' + Fore.RESET))
            sys.exit(0)

        # Set IP for functions to use
        self.ip = ip.rstrip()

        # Set whether or not to lookup services
        self.servicelookup = svclookup

        # Set the proxy if it was specified by the user
        self.proxy = proxyset

    def search(self):
        if self.proxy:
            socks = {
                'http': 'socks5://%s' % self.proxy,
                'https': 'socks5://%s' % self.proxy
            }
            res = requests.get(self.API_URL, proxies=socks)
        else:
            res = requests.get(self.API_URL)

        # print(self.API_URL)

        payload = res.json()
        if 'error' in payload.keys():
            return

        ports = []
        proto = []
        for service in payload['data']:
            current_proto = service['_shodan']['module']
            proto.append(current_proto)
            ports.append(service['port'])

        ports = [str(x) for x in ports]

        ip = payload['ip_str']

        dictinput = combineresults(ip, ports, proto)
        dictinput.check()

        if self.servicelookup:
            for service in payload['data']:
                proto = service['_shodan']['module']
                port = str(service['port'])
                service_data = service['data']

                combined_results[ip]['ports'][port]["service_lookup"].append("[%s] %s Banner: \n%s" % (
                    Fore.LIGHTGREEN_EX + '+' + Fore.RESET, proto.upper(), service_data))

                if 'vulns' in service['opts'].keys():
                    for s in range(len(service['opts']['vulns'])):
                        if service['opts']['vulns'][s] != "!CVE-2014-0160":
                            combined_results[ip]['ports'][port]["service_lookup"].append(
                                "[%s] Vulnerability %s of %s: %s" % (
                                    Fore.LIGHTRED_EX + '!' + Fore.RESET, s, len(service['opts']['vulns']),
                                    service['opts']['vulns'][s]))


class Censys:
    def __init__(self, ip, svclookup, iteration, proxyset):

        # Set API URL and UID and SECRET API keys for PwC Security Research accounts (to deal with API limiting)
        # This is a temporary workaround. Censys.io limits to 120 API calls every 5 minutes. Need to either create more
        # accounts for larger ranges or reach out to the Censys team and ask for a limit upgrade. The latter might be
        # difficult to make a case.
        # Creation of 3 or more keys is suggested.
        # Make sure the key pairs are in the same location in each list. e.g. UID[0] and SECRET[0] are a pair.
        self.API_URL = "https://www.censys.io/api/v1"
        self.UID = [""]
        self.SECRET = [""]

        # Set IP/CIDR/hostname/domain name
        self.ip = ip.rstrip()

        # Sets whether or not service lookup will be performed
        self.servicelookup = svclookup

        # Set a counter to know which key to use to get around API limit
        self.iteration = iteration

        # Set count for amount of tokens
        self.tokencount = len(self.UID) - 1

        # Set counter for better token rotation if service lookup is selected
        if svclookup:
            self.iterationv = 8 + self.iteration
            if self.iterationv >= self.tokencount:
                self.iterationv -= self.tokencount

        # Set proxy if user chose to
        self.proxy = proxyset

    def tokencounter(self):
        return len(self.UID) - 1

    def tokenselector(self, iteration):
        # Define a list rotation function
        def rotate(l, n):
            return l[n:] + l[:n]

        # If there is only one token, return it
        if len(self.UID) <= 0:
            print("[%s] Please add your own API tokens to the script." % (Fore.LIGHTRED_EX + '!' + Fore.RESET))
            sys.exit(0)

        # If there is only one token, return it
        elif len(self.UID) == 1:
            return [self.UID[0], self.SECRET[0]]

        # If there are two or more tokens, rotate tokens per iteration
        else:
            uid = rotate(self.UID, iteration)
            secret = rotate(self.SECRET, iteration)
            string = [uid[0], secret[0]]
            #   print (string)
            return string

    def search(self):

        # Select a token depending on how many ranges/hosts are sent through the host file option
        authtoken = self.tokenselector(self.iteration)

        # Set page variables
        pages = float('inf')
        page = 1

        # Loop while page is less than the pages variable set at the end of the function from json metadata
        while page <= pages:

            # After two pages rotate the token to bypass API limiting.
            if page > 2:
                p = self.iteration + page + 3
                # In case the number of pages is extremely large, subtract token count until it's under the max
                while True:
                    if p > self.tokencount:
                        p -= self.tokencount
                    else:
                        break
                authtoken = self.tokenselector(p)

            # Set json request parameters for get request
            params = {'query': self.ip, 'page': page}

            # Check if a proxy was specified and run API request with parameters
            if self.proxy:
                socks = {
                    'http': 'socks5://%s' % self.proxy,
                    'https': 'socks5://%s' % self.proxy
                }
                res = requests.post(self.API_URL + "/search/ipv4", json=params, auth=(authtoken[0], authtoken[1]),
                                    proxies=socks)
            else:
                res = requests.post(self.API_URL + "/search/ipv4", json=params, auth=(authtoken[0], authtoken[1]))
            # Set json data to the list payload
            payload = res.json()

            for r in payload['results']:
                ip = r['ip']
                proto = r['protocols']
                ports = [p.split("/")[0] for p in proto]
                proto = [p.split("/")[1] for p in proto]
                dictinput = combineresults(ip, ports, proto)
                dictinput.check()

                # If we are running both censys and shodan.
                if self.servicelookup:
                    Censys.view(self, ip)

            pages = payload['metadata']['pages']
            page += 1

    def view(self, server):

        # Select a token depending on how many ranges/hosts are sent through the host file option
        # Add iteration token to select different token than what's used in the search function for better token
        # rotation
        authtoken = self.tokenselector(self.iterationv)

        # Add 1 to token counter
        self.iterationv += 1
        if self.iterationv >= 15:
            self.iterationv -= 15

        res = requests.get(self.API_URL + ("/view/ipv4/%s" % server), auth=(authtoken[0], authtoken[1]))
        payload = res.json()

        try:
            if '21' in payload.keys():
                port = '21'
                if 'banner' in payload[port]['ftp'].keys():
                    if 'banner' in payload[port]['ftp']['banner'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] FTP Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['ftp']['banner']['banner']))
                    if 'metadata' in payload[port]['ftp']['banner']['metadata'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] FTP Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['ftp']['banner']['metadata']))
            if '22' in payload.keys():
                port = '22'
                if 'banner' in payload[port]['ssh'].keys():
                    if 'raw_banner' in payload[port]['ssh']['banner'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] SSH Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['ssh']['banner']['raw_banner']))
                    if 'metadata' in payload[port]['ssh']['banner']['metadata'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] SSH Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['ssh']['banner']['metadata']))
            if '23' in payload.keys():
                port = '23'
                if 'banner' in payload[port]['telnet'].keys():
                    if 'banner' in payload[port]['telnet']['banner'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] Telnet Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['telnet']['banner']['banner']))
                    if 'metadata' in payload[port]['telnet']['banner']['metadata'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] Telnet Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['telnet']['banner']['metadata']))
            if '25' in payload.keys():
                port = '25'
                if 'starttls' in payload[port]['smtp'].keys():
                    if 'banner' in payload[port]['smtp']['starttls'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] SMTP Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['smtp']['starttls']['banner']))
                    if 'metadata' in payload[port]['smtp']['starttls']['metadata'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] SMTP Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['smtp']['starttls']['metadata']))
            if '80' in payload.keys():
                port = '80'
                if 'title' in payload[port]['http']['get'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] Title: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['http']['get']['title']))
                if 'headers' in payload[port]['http']['get'].keys():
                    if 'server' in payload[port]['http']['get']['headers'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] Server: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['http']['get']['headers']['server']))
            if '102' in payload.keys():
                port = '102'
                if 'support' in payload[port]['s7']['szl'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] S7 Supported: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['s7']['szl']['support']))
                if 'metadata' in payload[port]['s7']['szl'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] S7 Metadata: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['s7']['szl']['metadata']))
            if '110' in payload.keys():
                port = '110'
                if 'ssl_2' in payload[port]['pop3'].keys():
                    if 'banner' in payload[port]['pop3']['ssl_2'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] POP3 Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['pop3']['ssl_2']['banner']))
                    if 'metadata' in payload[port]['pop3']['ssl_2']['metadata'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] POP3 Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['pop3']['ssl_2']['metadata']))
                if 'starttls' in payload[port]['pop3'].keys():
                    if 'banner' in payload[port]['pop3']['starttls'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] POP3 Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['pop3']['starttls']['banner']))
                    if 'metadata' in payload[port]['pop3']['starttls'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] POP3 Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['pop3']['starttls']['metadata']))
            if '143' in payload.keys():
                port = '143'
                if 'ssl_2' in payload[port]['imap'].keys():
                    if 'banner' in payload[port]['imap']['ssl_2'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] IMAP Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['imap']['ssl_2']['banner']))
                    if 'metadata' in payload[port]['imap']['ssl_2']['metadata'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] IMAP Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['imap']['ssl_2']['metadata']))
                if 'starttls' in payload[port]['imap'].keys():
                    if 'banner' in payload[port]['imap']['starttls'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] IMAP Banner: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['imap']['starttls']['banner']))
                    if 'ssl_2' in payload[port]['imap'].keys():
                        if 'metadata' in payload[port]['imap']['ssl_2']['metadata'].keys():
                            combined_results[server]['ports'][port]["service_lookup"].append("[%s] IMAP Metadata: %s" % (
                                Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['imap']['starttls']['metadata']))
            if '443' in payload.keys():
                port = '443'
                if 'tls' in payload[port]['https'].keys():
                    if 'names' in payload[port]['https']['tls']['certificate']['parsed'].keys():
                        cdnames = payload[port]['https']['tls']['certificate']['parsed']['names']
                        cdnames = ','.join(map(str, cdnames))
                        combined_results[server]['ports'][port]["service_lookup"].append(
                            "[%s] TLS Registered Domains: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET, cdnames))
                    if 'version' in payload[port]['https']['tls'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append(
                            "[%s] Most Recent SSL Version Supported: %s" % (
                                Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['https']['tls']['version']))
                if 'ssl_2' in payload[port]['https'].keys():
                    if 'support' in payload[port]['https']['ssl_2'].keys():
                        if payload[port]['https']['ssl_2']['support'] == "True":
                            combined_results[server]['ports'][port]["service_lookup"].append("[%s] SSL2 Support: %s" % (
                                Fore.LIGHTRED_EX + '!' + Fore.RESET, payload[port]['https']['ssl_2']['support']))
                if 'ssl_3' in payload[port]['https'].keys():
                    if 'support' in payload[port]['https']['ssl_3'].keys():
                        if payload[port]['https']['ssl_3']['support'] == "True":
                            combined_results[server]['ports'][port]["service_lookup"].append("[%s] SSL3 Support: %s" % (
                                Fore.LIGHTRED_EX + '!' + Fore.RESET, payload[port]['https']['ssl_3']['support']))
                if 'heartbleed' in payload[port]['https'].keys():
                    if 'heartbleed_vulnerable' in payload[port]['https']['heartbleed'].keys():
                        if payload[port]['https']['heartbleed']['heartbleed_vulnerable'] == "True":
                            combined_results[server]['ports'][port]["service_lookup"].append(
                                "[%s] Vulnerable to Heartbleed: %s" % (Fore.LIGHTRED_EX + '!' + Fore.RESET,
                                                                       payload[port]['https']['heartbleed'][
                                                                           'heartbleed_vulnerable']))
            if '465' in payload.keys():
                port = '465'
                if 'ssl_2' in payload[port]['smtps'].keys():
                    if 'extra_clear' in payload[port]['smtps']['ssl_2'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] SMTPS Extra Clear: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['smtps']['ssl_2']['extra_clear']))
                    if 'metadata' in payload[port]['smtps']['ssl_2'].keys():
                        combined_results[server]['ports'][port]["service_lookup"].append("[%s] SMTPS Metadata: %s" % (
                            Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['smtps']['ssl_2']['metadata']))
            if '502' in payload.keys():
                port = '502'
                if 'function_code' in payload[port]['modbus']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append(
                        "[%s] modbus Function Code: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET,
                                                           payload[port]['modbus']['device_id'][
                                                               'function_code']))
                if 'metadata' in payload[port]['modbus']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] modbus Metadata: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['modbus']['device_id']['metadata']))
            if '993' in payload.keys():
                port = '993'
                if 'banner' in payload[port]['imaps']['tls'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] IMAPS Banner: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['imaps']['tls']['banner']))
                if 'metadata' in payload[port]['imaps']['tls']['metadata'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] IMAPS Metadata: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['imaps']['tls']['metadata']))
            if '995' in payload.keys():
                port = '995'
                if 'banner' in payload[port]['pop3s']['tls'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] POP3S Banner: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['pop3s']['tls']['banner']))
                if 'metadata' in payload[port]['pop3s']['tls']['metadata'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] POP3S Metadata: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['pop3s']['tls']['metadata']))
            if '1900' in payload.keys():
                port = '1900'
                if 'server' in payload[port]['upnp']['discovery'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] UPNP Banner: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['upnp']['discovery']['server']))
                if 'location' in payload[port]['upnp']['discovery'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] UPNP Location File: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['upnp']['discovery']['location']))
                if 'agent' in payload[port]['upnp']['discovery'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] UPNP Agent: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['upnp']['discovery']['agent']))
                if 'x-user-agent' in payload[port]['upnp']['discovery'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append(
                        "[%s] UPNP User Agent: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET,
                                                      payload[port]['upnp']['discovery']['x-user-agent']))
            if '1911' in payload.keys():
                port = '1911'
                if 'vm_name' in payload[port]['fox']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] Fox VM: %s %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['fox']['device_id']['vm_name'],
                        payload[port]['fox']['device_id']['vm_version']))
                if 'vm_uuid' in payload[port]['fox']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] Fox VM UUID: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['fox']['device_id']['vm_uuid']))
                if 'os_name' in payload[port]['fox']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] Fox OS: %s %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['fox']['device_id']['os_name'],
                        payload[port]['fox']['device_id']['os_version']))
                if 'app_name' in payload[port]['fox']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] Fox App Name: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['fox']['device_id']['app_name']))
                if 'hostname' in payload[port]['fox']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] Internal IP Address: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['fox']['device_id']['hostname']))
                if 'brand_id' in payload[port]['fox']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] Fox Brand: %s %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['fox']['device_id']['brand_id'],
                        payload[port]['fox']['device_id']['version']))
            if '7547' in payload.keys():
                port = '7547'
                if 'status_line' in payload[port]['cwmp']['get'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] CWMP Response: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['cwmp']['get']['status_line']))
                if 'www_authenticate' in payload[port]['cwmp']['get']['headers'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append(
                        "[%s] CWMP Authentication Line: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET,
                                                               payload[port]['cwmp']['get']['headers'][
                                                                   'www_authenticate']))
            if '20000' in payload.keys():
                port = '20000'
                if 'support' in payload[port]['dnp3']['status'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] DNP3 Support: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['dnp3']['status']['support']))
                if 'raw_response' in payload[port]['dnp3']['status'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] DNP3 Raw Response: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['dnp3']['status']['raw_response']))
                if 'metadata' in payload[port]['dnp3']['status'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append("[%s] DNP3 Metadata: %s" % (
                        Fore.LIGHTGREEN_EX + '+' + Fore.RESET, payload[port]['dnp3']['status']['metadata']))
            if '47808' in payload.keys():
                port = '47808'
                if 'official_name' in payload[port]['bacnet']['device_id']['vendor'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append(
                        "[%s] Bacnet Device Vendor: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET,
                                                           payload[port]['bacnet']['device_id']['vendor'][
                                                               'official_name']))
                if 'firmware_revision' in payload[port]['bacnet']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append(
                        "[%s] Bacnet Firmware Version: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET,
                                                              payload[port]['bacnet']['device_id'][
                                                                  'firmware_revision']))
                if 'description' in payload[port]['bacnet']['device_id'].keys():
                    combined_results[server]['ports'][port]["service_lookup"].append(
                        "[%s] Bacnet Banner: %s, %s, %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET,
                                                            payload[port]['bacnet']['device_id'][
                                                                'description'],
                                                            payload[port]['bacnet']['device_id'][
                                                                'object_name'],
                                                            payload[port]['bacnet']['device_id'][
                                                                'model_name']))
        except Exception as error:
            print(error)


class Test:
    def __init__(self, ip, svclookup):
        self.ip = ip
        self.svclookup = svclookup

    def add(self):
        combined_results[self.ip] = {}
        combined_results[self.ip]["hostname"] = "example.test.com"
        combined_results[self.ip]["ports"] = {}
        combined_results[self.ip]['ports']['80'] = {}
        combined_results[self.ip]['ports']['80']["protocol"] = 'http'
        combined_results[self.ip]['ports']['80']["service_lookup"] = []
        combined_results[self.ip]['ports']['443'] = {}
        combined_results[self.ip]['ports']['443']["protocol"] = 'https'
        combined_results[self.ip]['ports']['443']["service_lookup"] = []
        if self.svclookup:
            port = '80'
            combined_results[self.ip]['ports'][port]["service_lookup"].append("[%s] Title: %s" % (
                Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "404 File Not Found"))
            combined_results[self.ip]['ports'][port]["service_lookup"].append("[%s] Server: %s" % (
                Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "Apache Server"))
            port = '443'
            combined_results[self.ip]['ports'][port]["service_lookup"].append(
                "[%s] TLS Registered Domains: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "example.test.com,"
                                                                                            "dev.test.com"))
            combined_results[self.ip]['ports'][port]["service_lookup"].append(
                "[%s] Most Recent SSL Version Supported: %s" % (
                    Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "TLSv1.2"))
            combined_results[self.ip]['ports'][port]["service_lookup"].append("[%s] SSL2 Support: %s" % (
                Fore.LIGHTRED_EX + '!' + Fore.RESET, "True"))
            combined_results[self.ip]['ports'][port]["service_lookup"].append("[%s] SSL3 Support: %s" % (
                Fore.LIGHTRED_EX + '!' + Fore.RESET, "True"))
            combined_results[self.ip]['ports'][port]["service_lookup"].append(
                "[%s] Vulnerable to Heartbleed: %s" % (Fore.LIGHTRED_EX + '!' + Fore.RESET, "True"))

        combined_results["192.168.0.2"] = {}
        combined_results["192.168.0.2"]["hostname"] = "example.test.com"
        combined_results["192.168.0.2"]["ports"] = {}
        combined_results["192.168.0.2"]['ports']['80'] = {}
        combined_results["192.168.0.2"]['ports']['80']["protocol"] = 'http'
        combined_results["192.168.0.2"]['ports']['80']["service_lookup"] = []
        combined_results["192.168.0.2"]['ports']['443'] = {}
        combined_results["192.168.0.2"]['ports']['443']["protocol"] = 'https'
        combined_results["192.168.0.2"]['ports']['443']["service_lookup"] = []
        if self.svclookup:
            port = '80'
            combined_results["192.168.0.2"]['ports'][port]["service_lookup"].append("[%s] Title: %s" % (
                Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "404 File Not Found"))
            combined_results["192.168.0.2"]['ports'][port]["service_lookup"].append("[%s] Server: %s" % (
                Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "Apache Server"))
            port = '443'
            combined_results["192.168.0.2"]['ports'][port]["service_lookup"].append(
                "[%s] TLS Registered Domains: %s" % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "example.test.com,"
                                                                                            "dev.test.com"))
            combined_results["192.168.0.2"]['ports'][port]["service_lookup"].append(
                "[%s] Most Recent SSL Version Supported: %s" % (
                    Fore.LIGHTGREEN_EX + '+' + Fore.RESET, "TLSv1.2"))
            combined_results["192.168.0.2"]['ports'][port]["service_lookup"].append("[%s] SSL2 Support: %s" % (
                Fore.LIGHTRED_EX + '!' + Fore.RESET, "True"))
            combined_results["192.168.0.2"]['ports'][port]["service_lookup"].append("[%s] SSL3 Support: %s" % (
                Fore.LIGHTRED_EX + '!' + Fore.RESET, "True"))
            combined_results["192.168.0.2"]['ports'][port]["service_lookup"].append(
                "[%s] Vulnerable to Heartbleed: %s" % (Fore.LIGHTRED_EX + '!' + Fore.RESET, "True"))


# Class that creates dictionary and combines results from all repos
class combineresults:
    def __init__(self, ip, ports, protocols):
        self.ip = ip
        self.ports = ports
        self.port = None
        self.protos = protocols
        self.proto = None

    def build(self):
        combined_results[self.ip] = {}
        hostnamelookup = pdnslookup(self.ip)
        combined_results[self.ip]["hostname"] = hostnamelookup.rdnslookup()
        combined_results[self.ip]["ports"] = {}

    def addports(self):
        combined_results[self.ip]["ports"][self.port] = {}
        combined_results[self.ip]["ports"][self.port]["protocol"] = self.proto
        combined_results[self.ip]["ports"][self.port]["service_lookup"] = []

    def check(self):
        if self.ip not in combined_results.keys():
            self.build()
            for p in range(len(self.ports)):
                self.proto = self.protos[p]
                self.port = self.ports[p]
                self.addports()

        else:
            for p in range(len(self.ports)):
                if self.ports[p] not in combined_results[self.ip]["ports"].keys():
                    self.proto = self.protos[p]
                    self.port = self.ports[p]
                    self.addports()


# Cut from pdnslookup.py by Jesse Nebling
# Script that accepts a host as input and prints the DNS or rDNS lookup name
# -----------------------------------------------
class pdnslookup:
    def __init__(self, ip):
        self.ip = ip

    def rdnslookup(self):
        if self.ip:
            try:
                hostname = socket.gethostbyaddr(self.ip)
                hostname = hostname[0]
            except socket.herror:
                hostname = False
            return hostname
        else:
            print("Host not provided!")


# Cut from standardwriter.py by Jesse Nebling
# Script that utilizes system standard output and writes to a file.
# -----------------------------------------------

class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)


class StandardOut:
    def __init__(self, ip):
        self.ip = ip
        self.ports = None

    def check(self):
        if self.ip:
            self.ports = [int(x) for x in combined_results[self.ip]["ports"]]
            self.output()
        else:
            for hosts in combined_results.keys():
                self.ip = hosts
                self.ports = [int(x) for x in combined_results[self.ip]["ports"]]
                self.output()

    def output(self):
        print('[%s] IP: %s - Protocols: %s' % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET, self.ip, self.ports))
        if combined_results[self.ip]["hostname"]:
            print('%s Hostname: %s' % (Fore.LIGHTGREEN_EX + '-->' + Fore.RESET, combined_results[self.ip]["hostname"]))

        for port in combined_results[self.ip]['ports']:
            for banner in combined_results[self.ip]['ports'][port]['service_lookup']:
                if banner:
                    print(banner)
        print('==============================================\n')


# Cut from xmlwriter.py by Jesse Nebling
# Script that accepts an IP address, hostname, and open ports and writes it to a xml file compatible
# with Metasploits db_import functionality.
# -----------------------------------------------

class XMLout:
    def __init__(self, filename):
        if filename.lower().endswith('.xml'):
            self.filename = filename
        else:
            self.filename = filename + '.xml'

        self.ip = None
        self.hostname = None
        self.ports = None
        self.proto = None

    def write(self):
        if self.exists():
            outf = open(self.filename, 'a')
            print("<host><status state=\"up\"/>", file=outf)
            print("<address addr=\"" + self.ip + "\" addrtype=\"ipv4\"/>", file=outf)
            print("<hostnames>", file=outf)
            if self.hostname:
                print("<hostname name=\"" + self.hostname + "\" type=\"PTR\"/>", file=outf)
            print("</hostnames>", file=outf)
            print("<ports>", file=outf)
            for m in range(len(self.ports)):
                # Putting this here for now for eventual UDP integration
                protocol = "tcp"
                print(
                    "<port protocol=\"" + protocol + "\" portid=\"" + str(self.ports[m]) +
                    "\"><state state=\"open\"/><service name=\"" + str(self.proto[m]) + "\"/></port>", file=outf)
            print("</ports>", file=outf)
            print("</host>", file=outf)
            outf.close()
        else:
            self.create()

    def exists(self):
        return os.path.isfile(self.filename)

    def create(self):
        outf = open(self.filename, 'w')
        print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", file=outf)
        print("<!DOCTYPE nmaprun>", file=outf)
        print("<nmaprun>", file=outf)
        outf.close()
        self.write()

    def compile(self):
        for ip in combined_results.keys():
            self.ip = ip
            self.ports = list(combined_results[self.ip]["ports"].keys())
            self.proto = []
            self.hostname = combined_results[self.ip]["hostname"]
            for port in self.ports:
                self.proto.append(combined_results[self.ip]["ports"][port]["protocol"])
            self.write()

    def close(self):
        outf = open(self.filename, 'a')
        print("</nmaprun>", file=outf)
        outf.close()
        print('[%s] Created %s' % (Fore.LIGHTGREEN_EX + '*' + Fore.RESET, self.filename))


class CSVout:
    def __init__(self, filename):
        if filename.lower().endswith('.csv'):
            self.filename = filename
        else:
            self.filename = filename + '.csv'

        self.ip = None
        self.hostname = None
        self.ports = None
        self.proto = None
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
        self.csvlinewrite(['address', 'hostname', 'port', 'protocol', 'service info'])
        for ip in combined_results:
            if combined_results[ip]["hostname"]:
                hostname = combined_results[ip]["hostname"]
            else:
                hostname = None
            for port in combined_results[ip]["ports"]:
                row = [ip, hostname, port, combined_results[ip]["ports"][port]["protocol"]]
                srvinfo = []
                for banner in combined_results[ip]["ports"][port]["service_lookup"]:
                    bannerlen = len(banner) + 1
                    croppedban = banner[14:bannerlen]
                    croppedban = croppedban.replace('\"', '\'')
                    srvinfo.append(croppedban)
                row.append(';\r\n'.join(map(str, srvinfo)))
                self.csvlinewrite(row)
        self.closecsv()
        print('[%s] Created %s' % (Fore.LIGHTGREEN_EX + '*' + Fore.RESET, self.filename))


# InputSanitizer class by Jesse Nebling
# Sanitizes list of IPs to follow a certain schema, outputs list
# -----------------------------------------------
class InputSanitizer:
    def __init__(self, inputlist):
        self.input = inputlist
        self.saniout = []
        self.sanitizelist = []
        self.strip()

    def clean(self):
        self.input = self.saniout
        self.saniout = []
        self.sanitizelist = []

    def strip(self):
        for linestrip in self.input:
            self.saniout.append(linestrip.rstrip())
        self.clean()

    def rangetocidr(self):
        for index, linerc in enumerate(self.input):
            if '-' in linerc:
                try:
                    for iprange in iprange_to_cidrs(linerc.split('-')[0], linerc.split('-')[1]):
                        if '/32' in str(iprange):
                            self.saniout.append(str(iprange).split('/')[0])
                        else:
                            self.saniout.append(str(iprange))
                    self.sanitizelist.append(linerc)
                except core.AddrFormatError:
                    print("[%s] Line %s of the input file has an error in it:" % (Fore.LIGHTRED_EX + '!' + Fore.RESET, index))
                    print("[%s] %s" % (Fore.LIGHTRED_EX + '-' + Fore.RESET, linerc))
        if self.sanitizelist:
            for iprange in self.sanitizelist:
                self.input.remove(iprange)
        for ips in self.input:
            self.saniout.append(ips)
        self.clean()

    def cidrtoips(self):
        for index, lineci in enumerate(self.input):
            if '/' in lineci:
                try:
                    for host in IPNetwork(lineci):
                        host = str(host)
                        self.saniout.append(host)
                    self.sanitizelist.append(lineci)
                except core.AddrFormatError:
                    print("[%s] Line %s of the input file has an error in it:" % (Fore.LIGHTRED_EX + '!' + Fore.RESET, index))
                    print("[%s] %s" % (Fore.LIGHTRED_EX + '-' + Fore.RESET, lineci))
        if self.sanitizelist:
            for iprange in self.sanitizelist:
                self.input.remove(iprange)
        for ips in self.input:
            self.saniout.append(ips)
        self.clean()

    def iplisttocidrs(self):
        netmanipulation = []
        for index, lineic in enumerate(self.input):
            try:
                if (not '/' in lineic) and (not '-' in lineic):
                    netmanipulation.append(IPAddress(lineic))
            except core.AddrFormatError:
                print("[%s] Line %s of the input file has an error in it:" % (Fore.LIGHTRED_EX + '!' + Fore.RESET,
                      index))
                print("[%s] %s" % (Fore.LIGHTRED_EX + '-' + Fore.RESET, lineic))
        netmanipulation = cidr_merge(netmanipulation)
        for iprange in netmanipulation:
            if '/32' in str(iprange):
                self.saniout.append(str(iprange).split('/')[0])
            else:
                self.saniout.append(str(iprange))
        for ranges in self.input:
            if ('/' in ranges) or ('-' in ranges):
                self.saniout.append(ranges)
        self.clean()

    def cidrtoranges(self):
        for index, linecr in enumerate(self.input):
            if '/' in linecr:
                try:
                    hostrange = str(IPNetwork(linecr).network) + " - " + str(IPNetwork(linecr).broadcast)
                    self.saniout.append(hostrange)
                    self.sanitizelist.append(linecr)
                except core.AddrFormatError:
                    print("[%s] Line %s of the input file has an error in it:" % (Fore.LIGHTRED_EX + '!' + Fore.RESET,
                          index))
                    print("[%s] %s" % (Fore.LIGHTRED_EX + '-' + Fore.RESET, linecr))
        if self.sanitizelist:
            for iprange in self.sanitizelist:
                self.input.remove(iprange)
        for ips in self.input:
            self.saniout.append(ips)
        self.clean()

    def output(self):
        return self.input

    # create sanitzation functions for shodan and censys
    def censys(self):
        self.iplisttocidrs()
        self.rangetocidr()
        return self.input

    def shodan(self):
        self.rangetocidr()
        self.cidrtoips()
        return self.input

# For standalone use of pmap.py
class Main():
    def __init__(self):


        parser = argparse.ArgumentParser(description='Passive Service Discovery Search')
        maininput = parser.add_mutually_exclusive_group(required=True)
        maininput.add_argument('-q', '--query', help='Censys Search Term (i.e. pwc.com, 192.168.1.1, 10.0.0.0/16)')
        maininput.add_argument('-iL', '--filename', default=False, help='Passive Search with file (i.e. scope.txt)')
        output = parser.add_mutually_exclusive_group(required=False)
        output.add_argument('-oA', '--outputall', default=False, help='Outputs in all available formats')
        output.add_argument('-oS', '--outputstandard', default=False, help='Outputs standard output to a .log file')
        output.add_argument('-oC', '--outputcsv', default=False, help='Outputs into a .csv file')
        output.add_argument('-oX', '--outputnmapxml', default=False,
                            help='Outputs into a nmap style .xml file (for simplified msf db_import)')
        parser.add_argument('-sV', '--servicelookup', default=False, action='store_true',
                            help='Checks for additional details about open ports')
        # adding proxy option to test within PwC offices (Shodan cert not trusted by PwC)
        parser.add_argument('-p', '--proxy', default=False, help='Specify SOCKS5 proxy (i.e. 127.0.0.1:8123)')
        # adding proxy option to test within PwC offices (Shodan cert not trusted by PwC)
        parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Output in verbose mode while script runs')
        # threads plz
        parser.add_argument('-T', '--threads', default=1, help='Specify how many threads to use. [Default = 1]')
        # are we using Censys or Shodan
        method = parser.add_mutually_exclusive_group(required=False)
        method.add_argument('-c', '--censys', default=False, action='store_true', help='Perform lookup with Censys.io')
        method.add_argument('-s', '--shodan', default=False, action='store_true', help='Perform lookup with Shodan.io')
        method.add_argument('-t', '--test', default=False, action='store_true', help='Fake test data')

        # parser.add_argument('-db', '--updatedb',
        # help='Checks for active mysql database instance and inserts results [Work in progress...]')
        # parser.add_argument('--create-db', action='store_true',
        # help='Start the mysql service and creates a database [Work in progress...]')
        # parser.add_argument('-n', '--client-name', default='PacifistDB',
        # help='Client name for database purposes [Work in progress...]')

        args = parser.parse_args()
        self.pool = ThreadPool(int(args.threads))
        self.servicelookup = args.servicelookup
        self.proxy = args.proxy
        self.verbosity = args.verbose
        self.carg = args.censys
        self.sarg = args.shodan
        self.targ = args.test
        self.filename = args.filename
        self.query = args.query
        self.iterat = 0

        self.outputfile = False
        if args.outputall:
            self.outputfile = ['all', args.outputall]
            sys.stdout = Logger(self.outputfile[1] + '.log')
        if args.outputcsv:
            self.outputfile = ['csv', args.outputcsv]
        if args.outputnmapxml:
            self.outputfile = ['xml', args.outputnmapxml]
        if args.outputstandard:
            self.outputfile = ['log', args.outputstandard]
            sys.stdout = Logger(self.outputfile[1] + '.log')

        self.go()

    def verbose(self, ip):
        def shout(ipin):
            voutput = StandardOut(ipin)
            voutput.check()

        if '/' in ip:
            isani = InputSanitizer([ip])
            isani.cidrtoips()
            ips = isani.output()
            for sanihost in ips:
                if sanihost in combined_results:
                    shout(sanihost)
        else:
            if ip in combined_results:
                shout(ip)

    # Define output for standalone use
    def output(self, outlist):

        # Define output functions
        def xmlf(outlisti):
            xmlo = XMLout(outlisti[1])
            xmlo.compile()
            xmlo.close()

        def csv(outlisti):
            csvfilename = outlisti[1] + '.csv'
            csvo = CSVout(csvfilename)
            csvo.write()

        def log(outlisti):
            logfilename = outlisti[1] + '.log'
            print('[%s] Created %s' % (Fore.LIGHTGREEN_EX + '*' + Fore.RESET, logfilename))

        # Perform output actions depending on chosen file type
        if outlist[0] == 'xml':
            xmlf(outlist)
        elif outlist[0] == 'csv':
            csv(outlist)
        elif outlist[0] == 'log':
            log(outlist)
        elif outlist[0] == 'all':
            xmlf(outlist)
            csv(outlist)
            log(outlist)
        else:
            print("[%s] This should never happen, if it does please report." % (Fore.LIGHTRED_EX + '!' + Fore.RESET))
            sys.exit(0)

    def execute(self, einput):
        def inputset(inhosts):
            if type(inhosts) is str:
                sanitinput = InputSanitizer([inhosts])
            else:
                sanitinput = InputSanitizer(inhosts)
            return sanitinput

        def censys(cinput):
            saninput = inputset(cinput)
            inputfile = saninput.censys()
            self.pool.map(cenexec, inputfile)

        def cenexec(line):
            if self.verbosity:
                screenlock.acquire()
                print("[*] Pulling Censys.io info for: %s" % line)
                screenlock.release()
            censysgo = Censys(line, self.servicelookup, self.iterat, self.proxy)
            censysgo.search()
            self.iterat += 1
            # If the iteration number goes over the total number of Censys tokens
            # subtract by token count + 1, so we can still use the final token
            if self.iterat > ctokencount:
                self.iterat -= (ctokencount + 1)
            if self.verbosity:
                screenlock.acquire()
                self.verbose(line)
                screenlock.release()

        def shodan(sinput):
            saninput = inputset(sinput)
            inputfile = saninput.shodan()
            self.pool.map(shoexec, inputfile)

        def shoexec(line):
            if self.verbosity:
                screenlock.acquire()
                print("[*] Pulling Shodan.io info for: %s" % line)
                screenlock.release()
            shodango = Shodan(line, self.servicelookup, self.proxy)
            shodango.search()
            if self.verbosity:
                screenlock.acquire()
                self.verbose(line)
                screenlock.release()

        def allexec(ainput):
            censys(ainput)
            shodan(ainput)

        # Creating ghetto token count for censys because bad planning
        cen = Censys("127.0.0.1", None, None, None)
        ctokencount = cen.tokencount

        # Set random iteration number for censys token rotation
        self.iterat = random.randint(0, ctokencount)

        if self.carg:
            censys(einput)
        elif self.sarg:
            shodan(einput)
        elif self.targ:
            query = einput
            testdata = Test(query, self.servicelookup)
            testdata.add()
            print(combined_results)
        else:
            allexec(einput)

        self.pool.close()
        self.pool.join()
        print('+++++++++++++++++++++++++++++++++++++++++++++++')
        print('[%s] Printing all results' % (Fore.LIGHTGREEN_EX + '+' + Fore.RESET))
        print('+++++++++++++++++++++++++++++++++++++++++++++++\n')
        console = StandardOut(None)
        console.check()
        if self.outputfile:
            self.output(self.outputfile)

    def go(self):
        if self.filename:
            if os.path.isfile(self.filename):
                if os.stat(self.filename).st_size != 0:
                    inputfile = []
                    with open(self.filename) as ifile:
                        for line in ifile:
                            inputfile.append(line)
                    self.execute(inputfile)
                else:
                    print("[%s] %s is empty!" % (Fore.LIGHTRED_EX + '!' + Fore.RESET, self.filename))
            else:
                print("[%s] %s does not exist!" % (Fore.LIGHTRED_EX + '!' + Fore.RESET, self.filename))
        if self.query:
            self.execute(self.query)


if __name__ == "__main__":
    try:
        combined_results = {}  # Dict to consolidate host and port results from all modules
        Main()
    except KeyboardInterrupt:
        print("You killed it.")
        sys.exit()
