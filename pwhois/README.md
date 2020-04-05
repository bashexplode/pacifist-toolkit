# Coded by Jesse Nebling (@bashexplode)

#### Summary

pwhois.py utilizes the whois databases through the python-whois library, as well as web API calls and BGP router lookups. Inspired by hardCIDR.sh by @ninewires from TrustedSec. Additional functionality such as threading was added to this python version.


#### Usage:

python pwhois.py [-h] [-v] [-r] [-l] [-f] [-p] [-a] [-A] [-u] [-T THREADS]

Parameters/Flags:

  -h, --help            			Help message
  
  -v, --verbose         			Output in verbose mode while script runs

  -r, --ripe            			Query RIPE NCC (Europe / Middle East / Central Asia)
  
  -l, --lacnic          			Query LACNIC (Latin America & Caribbean)
  
  -f, --afrinic         			Query AfriNIC (Africa)
  
  -p, --apnic           			Query APNIC (Asia / Pacific)
  
  -a, --arin            			Query ARIN (North America)
  
  -A, --all             			Query All RIR databases
  
  -u, --updatelacnicdb  			Update LACNIC database
  
  -T THREADS, --threads THREADS		Specify how many threads to use. [Default = 1]


#### Requirements:

Python 3

Everything in the requirements.txt file

##### if you are using a new version of openSSL you may need to downgrade. here's an easy script to do so: https://gist.github.com/bmaupin/8caca3a1e8c3c5686141


#### Suggested Improvements:

ASN BGP lookups don't give the network name. Not high priority, but the ASN-related functions needs to be reworked

RIPE whois lookups are rate limited, so it may come back with blank organization and network names. There is a link provided in the second to last column, click it and enter the info manually. 

#### License:
This script is under the [BSD 3-Clause license](https://raw.githubusercontent.com/bashexplode/Invoke-LateralMovement/master/LICENSE).
