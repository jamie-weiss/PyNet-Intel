import pandas as pd
import nmap
import numpy as np
import pydnsbl
from ipwhois import IPWhois
import ipwhois
from pprint import pprint
import shodan

SHODAN_API_KEY = 'wGwBOQ9JUCVUbrkkvPiB37Ry6qOOE11Y'


# MAKE CLASS FOR THIS WITH THE RESULTS OF THESE FUNCTIONS AS ATTRIBUTES
# HAVE AN ATTRIBUTE WITH SPECIFIC DATASETS WE NEED FOR VIS ETC...

def nmap_scan(ip):
	try:
		scanner = nmap.PortScanner()
		scanner.scan(hosts=ip, arguments='-F -sV', sudo=False)
		return scanner[ip]
	except:
		print("NMAP Exception")
		pass
		return None


def check_blacklist(ip):
	try:
		ip_checker = pydnsbl.DNSBLIpChecker()
		result = ip_checker.check(ip)
		return result.blacklisted
	except:
		print("Blacklist Exception")
		pass
		return None


def ipwhois(ip):
	try:
		obj = IPWhois(ip)
		results = obj.lookup_rdap(depth=1)
		return results
	except:
		print("IPWhois Exception")
		pass
		return None


def shodan_search(ip):
	try:
		api = shodan.Shodan(SHODAN_API_KEY)
		host = api.host(ip)
		return host
	except:
		print("Shodan Exception")
		pass
		return None


def main():
	#IP = '172.16.88.177' # Metasploitable
	#IP = '64.233.160.0' # Google Owned
	#IP = '136.143.153.86' # Webcam
	

	


if __name__ == '__main__':
	main()