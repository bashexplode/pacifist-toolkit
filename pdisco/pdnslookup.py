#!/usr/bin/python
# Pacifist Toolkit by Jesse Nebling (@bashexplode)
# pdnslookup.py by Jesse Nebling (@bashexplode)
# Script that accepts a host as input and prints the DNS lookup
# -----------------------------------------------

import socket
import argparse
from multiprocessing.dummy import Pool as ThreadPool
import threading

screenlock = threading.Semaphore(value=1)
dnslookups_results = {}


class DNSLookup:
    def __init__(self, hosts, verbose, threadpool):
        self.hosts = hosts
        self.verbose = verbose
        self.threadpool = threadpool
        self.hostlist = []

    def lookup(self, host):

            # Splitting out for sublist3r output
            if '<BR>' in host:
                for hostitem in host.split('<BR>'):
                    if hostitem.lower() not in self.hostlist:
                        self.hostlist.append(hostitem.lower())
                        try:
                            ipaddr = socket.gethostbyname(hostitem)
                            if __name__ == "__main__":
                                print(hostitem + " : " + ipaddr)
                            dictionarybuilder = BuildResultDict(hostitem, ipaddr, self.verbose)
                            dictionarybuilder.build()
                        except UnicodeError:
                            print("[!] Unicode error for %s" % hostitem)
                        except socket.gaierror:
                            if self.verbose:
                                screenlock.acquire()
                                print("[!] No IP Address associated with %s" % hostitem)
                                screenlock.release()
            else:
                try:
                    if host.lower() not in self.hostlist:
                        ipaddr = socket.gethostbyname(host)
                        if __name__ == "__main__":
                            print(host + " : " + ipaddr)
                        dictionarybuilder = BuildResultDict(host, ipaddr, self.verbose)
                        dictionarybuilder.build()
                except UnicodeError:
                    print("[!] Unicode error for %s" % host)
                except socket.gaierror:
                    if self.verbose:
                        screenlock.acquire()
                        print("[!] No IP Address associated with %s" % host)
                        screenlock.release()

    def execute(self):
        if self.hosts:
            self.threadpool.map(self.lookup, self.hosts)
            return dnslookups_results
        else:
            if self.verbose:
                screenlock.acquire()
                print ("[!] Host(s) not provided!")
                screenlock.release()

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
      *c    ..    $$     " d  @ jL # jL #    d  pdnslookup.py
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

class BuildResultDict:
    def __init__(self, subdomain, ip, verbose):
        self.subdomain = subdomain
        self.ip = ip
        self.verbose = verbose

    def build(self):
        if self.subdomain != '':
            if self.subdomain not in dnslookups_results.keys():
                dnslookups_results[self.subdomain] = {}
                dnslookups_results[self.subdomain]["ip"] = self.ip
            else:
                if self.verbose:
                    screenlock.acquire()
                    print("[!] %s already exists in the data dictionary." % self.subdomain)
                    screenlock.release()


# For testing or standalone use
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS Lookup')
    reqopts = parser.add_mutually_exclusive_group(required=True)
    reqopts.add_argument('-q', '--query', help='Query (i.e. pwc.com)')
    reqopts.add_argument('-iL', '--inputlist', default=False, help='File that contains hosts separated by new lines (i.e. 192.168.1.1, 10.0.0.0/16)')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose mode')
    parser.add_argument('-T', '--threads', default=30, help='Specify how many threads to use. Makes standard '
                                                           'logging with verbose mode unstable. [Default = 1]')

    args = parser.parse_args()
    pool = ThreadPool(int(args.threads))
    host = []

    if args.query:
        host.append(args.query)
    else:
        with open(args.inputlist) as f:
            hosts = f.read().split('\n')
        for line in hosts:
            host.append(line.rstrip())
        # print(host)
    action = DNSLookup(host, args.verbose, pool)
    action.banner()
    action.execute()

    print(dnslookups_results)

    # IPpattern = re.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
