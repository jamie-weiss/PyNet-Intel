import pandas as pd
import nmap as nm
import numpy as np
import pydnsbl
from ip2geotools.databases.noncommercial import DbIpCity
import ipwhois
from pprint import pprint
import shodan as sd

SHODAN_API_KEY = 'L1Z4GyP8JuAjxQQsw6HjoPJvXaHn18TC'


def nmap(ip):
	try:
		scanner = nm.PortScanner()
		scanner.scan(hosts=ip, arguments='-F -sV', sudo=False)
		return scanner[ip]
	except:
		pass
		return None


def blacklist(ip):
	try:
		ip_checker = pydnsbl.DNSBLIpChecker()
		result = ip_checker.check(ip)
		return result.blacklisted
	except:
		pass
		return None


def geoIP(ip):
	try:
		response = DbIpCity.get(ip, api_key='free')
		return response.latitude, response.longitude
	except:
		try:
			response = HostIP.get(ip)
			return response.latitude, response.longitude
		except:
			try:
				response = Ipstack.get(ip)
				return response.latitude, response.longitude
			except:
				try:
					response = MaxMindGeoLite2City.get(ip)
					return response.latitude, response.longitude
				except:
					try:
						response = Ip2Location.get(ip)
						return response.latitude, response.longitude
					except:
						return None, None

	


def shodan(ip):
	try:
		api = sd.Shodan(SHODAN_API_KEY)
		host = api.host(ip)
		return host
	except:
		pass
		return None



class PyNet:

	def __init__(self, target):
		self.target = target
		self.recon = {}


	'''
		Call helper functions, scrape outputs for important data
		return scraped output dicts or whatever. These member functions 
		will be called by a wrapper titled: reconnaissance that will 
		run all the scans in order and return a payload of information 
		that will be added to the object as attributes

	'''
	#####################################

	def run_nmap(self):
		results = nmap(self.target)
		if (results['status']['state'] == 'up'):
			self.recon['running'] = True
		else:
			self.recon['running'] = False
		self.recon['open_ports'] = results['tcp']
		return self
		

	def run_blacklist(self):
		results = blacklist(self.target)
		self.recon['blacklisted'] = results
		return self


	def run_geoIP(self):
		latitude, longitude = geoIP(self.target)
		self.recon['location'] = {}
		self.recon['location']['latitude'] = latitude
		self.recon['location']['longitude'] = longitude
		return self


	def run_shodan(self):
		response = shodan(self.target)
		try:
			self.recon['isp'] = response['data'][0]['isp']
		except:
			self.recon['isp'] = None
			pass
		try:
			http_dict = response['data'][1]['http']
			self.recon['http_components'] = http_dict['components'].keys()
		except:
			self.recon['http_components'] = None
			pass
		return self

	
	#####################################

	'''
		Call member functions and add outputted data as member variables.
		Function will be void.
		Function must be called before ThreatAnalysis is run because that
		function is dependent on the member variables we add in here.

	'''
	def reconnaissance(self):
		print("Running Reconnaissance......")
		print("Running NMAP Scan\t\t[1/4]")
		self.run_nmap()
		print("Running Blacklist Scan\t\t[2/4]")
		self.run_blacklist()
		print("Running GeoLocation Scan\t[3/4]")
		self.run_geoIP()
		print("Running Shodan Scan\t\t[4/4]")
		self.run_shodan()
		return self


	def display_recon_results(self):
		print("------------ Reconnaissance Network Scan Results ------------")
		print("Target: ", self.target)
		print("Running: ", self.recon['running'])
		print("Blacklisted: ", self.recon['blacklisted'])
		print("Location: [" + str(self.recon['location']['latitude']) + ", " + str(self.recon['location']['longitude']) + "]")
		print("ISP: ", self.recon['isp'])
		print("HTTP Components: ", self.recon['http_components'])
		print("--------------- OPEN PORT INFO ---------------")
		pprint(self.recon['open_ports'])



def main():
	#IP = '172.16.88.177' # Metasploitable
	#IP = '64.233.160.0' # Google Owned
	#IP = '136.143.153.86' # Webcam
	#IP = '192.168.2.223' # Me
	IP = '85.14.229.112' # CSGO Server
	pynet = PyNet(target=IP)
	pynet.reconnaissance()
	print()
	pynet.display_recon_results()
	

	

	


if __name__ == '__main__':
	main()