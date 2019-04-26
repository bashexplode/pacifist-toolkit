# Coded by Jesse Nebling (@bashexplode)

#### Summary

pmap.py utilizes the API from censys.io to pull open services from a repository of scans that are performed on a regular basis by the University of Michigan, and shodan.io. This allows us to pull information on client resources without actively scanning them for the first few days of an external pentest, allowing for much greater stealth and a lesser likelihood of being caught by an IDS. Because the scans only cover the ports below, pmap.py is great for the start of external pentests, but if the results do not give a foothold it would be smart to still perform an nmap scan on ports outside of the censys.io scope.



Censys.io ports: 21, 22, 23, 25, 53, 80, 102, 110, 143, 443, 465, 502, 993, 995, 1911, 7547, 20000, 47808

Shodan.io ports: 21, 22, 23, 80, UDP:161, 443, 554, 5060, 8080, 8443

#### Usage:

python pmap.py [-h] (-q QUERY | -iL FILENAME) [-oA OUTPUTALL | -oS OUTPUTSTANDARD | -oC OUTPUTCSV | -oX OUTPUTNMAPXML] [-sV]

Parameters/Flags:

-q <query> : A single query that can be an IP address, a hostname, or an IP range [e.g. 192..0.0.1, www.microsoft.com, 192.0.0.0/24, 192.0.0.1 - 192.0.0.255]

-iL <filename> : A list of queries from a file with above queries separated by new lines. [works best with CIDR ranges because of API rate limits]

-oS <filename> : Designates an output file for the standard output of the script.

-oX <filename> : Designates an output file in an xml format based on the nmap xml format that can be easily imported to a metasploit workspace.

-oC <filename> : Designates an output file in a csv format for easy readability.

-oA <filename> : Creates all available output file types.

-sV : Pulls additional services information that censys.io collects [not recommended for use with very large host files because of API rate limit]

-c : Only pull results from Censys.io

-s : Only pull results from Shodan.io

-p <proxy> : Specify SOCKS5 proxy (i.e. 127.0.0.1:8123)

-T <threads> : Specify the number of threads to use. Unstable with verbose standard logging. [Default = 1]

-v : Verbose mode


#### Requirements:

Your API keys for Shodan and Censys.io

Python 3

##### if you are using a new version of openSSL you may need to downgrade. here's an easy script to do so: https://gist.github.com/bmaupin/8caca3a1e8c3c5686141


#### License:
This script is under the [BSD 3-Clause license](https://raw.githubusercontent.com/bashexplode/Invoke-LateralMovement/master/LICENSE).

