import pandas as pd
import nmap as nm
import numpy as np
import pydnsbl
from ip2geotools.databases.noncommercial import DbIpCity
import ipwhois
from pprint import pprint
import shodan as sd
import requests
import vulners
import time
import json
import sys

import scans.xss_detector as xss
import scans.ssh_penetrator as ssh
import scans.ftp_penetrator as ftp
import scans.http_vulnerability_detector as hvd
import scans.vulners_search as V


SHODAN_API_KEY = 'L1Z4GyP8JuAjxQQsw6HjoPJvXaHn18TC'
VULNERS_API_KEY = 'X5FSV2X2I4W9R2XK5SBO1FH0U6Z5KB45D92W62S9GNXJJSLB6654NDMN7JIOV5FW'
XSS_PAYLOAD_PATH = 'data/payloads_small.txt'
CREDENTIALS_PATH = 'data/credentials_small.txt'



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
		self.analysis = {}


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
		return self


	def reconnaissance(self):
		print("Running Reconnaissance......")
		self.run_nmap()
		print("NMAP Scan\t\t\t[1/4]")
		self.run_blacklist()
		print("Blacklist Scan\t\t\t[2/4]")
		self.run_geoIP()
		print("GeoLocation Scan\t\t[3/4]")
		self.run_shodan()
		print("Shodan Scan\t\t\t[4/4]")
		return self


	def display_recon_results(self):
		print()
		print("------------ Reconnaissance Network Scan Results ------------")
		print("Target: ", self.target)
		print("Running: ", self.recon['running'])
		print("Blacklisted: ", self.recon['blacklisted'])
		print("Location: [" + str(self.recon['location']['latitude']) + ", " + str(self.recon['location']['longitude']) + "]")
		print("ISP: ", self.recon['isp'])
		print("--------------- OPEN PORT INFO ---------------")
		for port in self.recon['open_ports'].keys():
			print("Port Number: ", port)
			if self.recon['open_ports'][port]['state'] != '':
				print("--> State: ", self.recon['open_ports'][port]['state'])
			if self.recon['open_ports'][port]['name'] != '':
				print("--> Name: ", self.recon['open_ports'][port]['name'])
			if self.recon['open_ports'][port]['version'] != '':
				print("--> Version: ", self.recon['open_ports'][port]['version'])
			if self.recon['open_ports'][port]['product'] != '':
				print("--> Product: ", self.recon['open_ports'][port]['product'])
			if self.recon['open_ports'][port]['reason'] != '':
				print("--> Reason: ", self.recon['open_ports'][port]['reason'])
			print()
		print()


	def display_analysis_results(self):
		print()
		print("------------ Analysis Results ------------")

		print("Has Web Server: ", self.analysis['xss']['web_server'])

		if self.analysis['xss']['web_server'] or self.analysis['xst']['web_server']:
			print("--> XSS Vulnerable: ", self.analysis['xss']['vulnerable'])
			if self.analysis['xss']['vulnerable']:
				print("----> XSS Exploit: ", self.analysis['xss']['exploit'])
				print("----> XSS Payload: ", self.analysis['xss']['payload'])

			print("--> XST Vulnerable: ", self.analysis['xst']['vulnerable'])
			print("--> MIME Sniffing Vulnerable: ", self.analysis['mime_sniffing']['vulnerable'])
			print("----> Content Type Options: ", self.analysis['mime_sniffing']['options'])
			print("--> Man in the Middle Vulnerable: ", self.analysis['man_in_the_middle']['vulnerable'])

			print("HTTP Methods Responses:")
			for method in self.analysis['http_methods'].keys():
				print("--> " + method + ": " + str(self.analysis['http_methods'][method]['status_code']) + ", " + self.analysis['http_methods'][method]['reason'])
		
		print("Has SSH Server: ", self.analysis['ssh']['ssh_server'])
		if self.analysis['ssh']['ssh_server']:
			print("--> Cracked: ", self.analysis['ssh']['cracked'])
			print("--> Sec Level: ", self.analysis['ssh']['sec_level'])
			if self.analysis['ssh']['cracked']:
				print("----> Username: ", self.analysis['ssh']['username'])
				print("----> Password: ", self.analysis['ssh']['password'])
		
		print("Has FTP Server: ", self.analysis['ftp']['ftp_server'])
		if self.analysis['ftp']['ftp_server']:
			print("--> Cracked: ", self.analysis['ftp']['cracked'])
			if self.analysis['ftp']['cracked']:
				print("----> Username: ", self.analysis['ftp']['username'])
				print("----> Password: ", self.analysis['ftp']['password'])

		print("------------ RELATED CVE INFORMATION ------------")
		for key in self.analysis['CVE_vulnerabilities']:
			print("Port Number: ", key)
			if self.analysis['CVE_vulnerabilities'][key] == []:
				print("None")
			else:
				for vuln in self.analysis['CVE_vulnerabilities'][key]:
					print("CVE ID: ", vuln['id'])
					print("Date Created: ", vuln['created'])
					print("Last Modified: ", vuln['modified'])
					print("CVSS Threat Score: ", vuln['score'])
					print("Link: ", vuln['link'])
					print()
				print()


	def has_web_server(self):
		if 80 or 443 in self.recon['open_ports'].keys():
			return True
		else:
			return False


	def detect_xss(self, port=80):
		self.analysis['xss'] = {}

		if not self.has_web_server():
			self.analysis['xss']['web_server'] = False
			self.analysis['xss']['vulnerable'] = None
			self.analysis['xss']['exploit'] = None
			self.analysis['xss']['payload'] = None
			return self
		if port == 443:
			url = 'https://' + self.target + ':' + str(port)
		else:
			url = 'http://' + self.target + ':' + str(port)

		try:
			resp = requests.get(url)

			if resp.status_code == 200: 
				found, form_details, payload = xss.scan_xss(url, XSS_PAYLOAD_PATH)
				self.analysis['xss']['web_server'] = True
				self.analysis['xss']['vulnerable'] = found
				self.analysis['xss']['exploit'] = form_details
				self.analysis['xss']['payload'] = payload
				return self
			else:
				self.analysis['xss']['web_server'] = False
				self.analysis['xss']['vulnerable'] = None
				self.analysis['xss']['exploit'] = None
				self.analysis['xss']['payload'] = None
				return self
			
			return self
		except:
			pass
			self.analysis['xss']['web_server'] = False
			self.analysis['xss']['vulnerable'] = None
			self.analysis['xss']['exploit'] = None
			self.analysis['xss']['payload'] = None
			return self


	def has_ssh_server(self):
		if 22 in self.recon['open_ports'].keys():
			if self.recon['open_ports'][22]['name'] == 'ssh':
				return True
			else:
				return False
		else:
			return False


	def detect_ssh(self):
		self.analysis['ssh'] = {}
		try:
			if self.has_ssh_server():
				cracked, sec_level, username, password = ssh.scan_ssh(self.target, CREDENTIALS_PATH)
				self.analysis['ssh']['ssh_server'] = True
				self.analysis['ssh']['cracked'] = cracked
				self.analysis['ssh']['sec_level'] = sec_level
				self.analysis['ssh']['username'] = username
				self.analysis['ssh']['password'] = password
			else:
				self.analysis['ssh']['ssh_server'] = False
				self.analysis['ssh']['cracked'] = None
				self.analysis['ssh']['sec_level'] = None
				self.analysis['ssh']['username'] = None
				self.analysis['ssh']['password'] = None
			return self
		except:
			pass
			self.analysis['ssh']['ssh_server'] = False
			self.analysis['ssh']['cracked'] = None
			self.analysis['ssh']['sec_level'] = None
			self.analysis['ssh']['username'] = None
			self.analysis['ssh']['password'] = None
			return self


	def has_ftp_server(self):
		if 21 in self.recon['open_ports'].keys():
			if self.recon['open_ports'][21]['name'] == 'ftp':
				return True
			else:
				return False
		else:
			return False


	def detect_ftp(self):
		self.analysis['ftp'] = {}
		try:
			if self.has_ftp_server():
				cracked, username, password = ftp.scan_ftp(self.target, CREDENTIALS_PATH)
				self.analysis['ftp']['ftp_server'] = True
				self.analysis['ftp']['cracked'] = cracked
				self.analysis['ftp']['username'] = username
				self.analysis['ftp']['password'] = password
			else:
				self.analysis['ftp']['ftp_server'] = False
				self.analysis['ftp']['cracked'] = None
				self.analysis['ftp']['username'] = None
				self.analysis['ftp']['password'] = None
			return self
		except:
			pass
			self.analysis['ftp']['ftp_server'] = False
			self.analysis['ftp']['cracked'] = None
			self.analysis['ftp']['username'] = None
			self.analysis['ftp']['password'] = None
			return self


	def detect_xst(self):
		self.analysis['xst'] = {}
		if not self.has_web_server():
			self.analysis['xst']['web_server'] = False
			self.analysis['xst']['vulnerable'] = None
			return self
		else:
			url = 'http://' + self.target + ':80'
			try:
				vuln = hvd.scan_xst(url)
				self.analysis['xst']['vulnerable'] = vuln
				self.analysis['xst']['web_server'] = True
				return self
			except:
				pass
				self.analysis['xst']['vulnerable'] = None
				self.analysis['xst']['web_server'] = False
				return self


	def scan_http_responses(self):
		if not self.has_web_server():
			self.analysis['http_methods'] = {
					  'GET': {'status_code': None, 'reason': None},
					  'POST': {'status_code': None, 'reason': None},
					  'PUT': {'status_code': None, 'reason': None},
					  'DELETE': {'status_code': None, 'reason': None},
					  'OPTIONS': {'status_code': None, 'reason': None},
					  'TRACE': {'status_code': None, 'reason': None},
					  'TEST': {'status_code': None, 'reason': None}
				   }
			return self
		else:
			url = 'http://' + self.target + ':80'
			try:
				results_dict = hvd.test_method_responses(url)
				self.analysis['http_methods'] = results_dict
				return self
			except:
				pass
				self.analysis['http_methods'] = {
					  'GET': {'status_code': None, 'reason': None},
					  'POST': {'status_code': None, 'reason': None},
					  'PUT': {'status_code': None, 'reason': None},
					  'DELETE': {'status_code': None, 'reason': None},
					  'OPTIONS': {'status_code': None, 'reason': None},
					  'TRACE': {'status_code': None, 'reason': None},
					  'TEST': {'status_code': None, 'reason': None}
				   }
				return self


	def detect_MIME_sniffing(self):
		self.analysis['mime_sniffing'] = {}
		if not self.has_web_server():
			self.analysis['mime_sniffing']['vulnerable'] = None
			return self
		else:
			url = 'http://' + self.target + ':80'
			result, content_type_options = hvd.scan_content_type_options(url)
			self.analysis['mime_sniffing']['vulnerable'] = result
			self.analysis['mime_sniffing']['options'] = content_type_options
			return self


	def detect_man_in_the_middle(self):
		self.analysis['man_in_the_middle'] = {}
		if not self.has_web_server():
			self.analysis['man_in_the_middle']['vulnerable'] = None
			return self
		else:
			url = 'http://' + self.target + ':80'
			result = hvd.scan_MITM(url)
			self.analysis['man_in_the_middle']['vulnerable'] = result
			return self


	def vulners_scan(self):
		results = V.scan_vulners_api(self.recon['open_ports'], VULNERS_API_KEY)
		self.analysis['CVE_vulnerabilities'] = {}
		for key in results.keys():
			if results[key] == []:
				self.analysis['CVE_vulnerabilities'][key] = []
			else:
				modified_list = []
				for vuln in results[key]:
					modified_vuln = {
						'id': vuln['id'],
						'score': vuln['cvss']['score'],
						'link': vuln['href'],
						'created': vuln['published'],
						'modified': vuln['modified'],
						'description': vuln['description']
					}
					modified_list.append(modified_vuln)
				self.analysis['CVE_vulnerabilities'][key] = modified_list

		return self


	def vulnerability_analysis(self):
		print()
		print("Running Vulnerability Analysis......")
		self.detect_xss()
		print("XSS Analysis\t\t\t[1/9]")
		self.detect_xst()
		print("XST Analysis\t\t\t[2/9]")
		self.detect_MIME_sniffing()
		print("MIME Sniffing Analysis\t\t[3/9]")
		self.detect_man_in_the_middle()
		print("Man in the Middle Analysis\t[4/9]")
		self.scan_http_responses()
		print("HTTP Methods Analysis\t\t[5/9]")
		self.detect_ssh()
		print("SSH Penetration Analysis\t[6/9]")
		self.detect_ftp()
		print("FTP Penetration Analysis\t[7/9]")
		self.vulners_scan()
		print("Related CVE Analysis\t\t[8/9]")
		self.calc_threat_scores()
		print("Calculating Threat Scores\t[9/9]")
		return self


	def calc_threat_scores(self):
		total_threat_score = 0
		total_open_ports_with_threat = 0
		for key in self.analysis['CVE_vulnerabilities'].keys():
			total_open_ports_with_threat += 1
			if self.analysis['CVE_vulnerabilities'][key] == []:
				continue
			else:
				for threat in self.analysis['CVE_vulnerabilities'][key]:
					total_threat_score += threat['score']
		scaled_threat_score = float(total_threat_score) / float(total_open_ports_with_threat)
		self.threat_scores = {"total": total_threat_score, "scaled": scaled_threat_score}
		return self



	def build_dict(self):
		dictionary = {'target': self.target, 'threat_scores': self.threat_scores, 'recon': self.recon, 'analysis': self.analysis}
		return dictionary


	def save_json(self, outfile_path):
		dictionary = {'target': self.target, 'threat_scores': self.threat_scores, 'recon': self.recon, 'analysis': self.analysis}
		with open(outfile_path, 'w') as outfile:
			json.dump(dictionary, outfile)


def run(ip):
	pynet = PyNet(target=ip)
	pynet.reconnaissance()
	pynet.vulnerability_analysis()
	payload = pynet.build_dict()
	return payload


# def main():
# 	# start = time.time()
# 	# ip_addr = sys.argv[1]
# 	# outfile_name = sys.argv[2]
# 	# outfile_location = 'json/'+outfile_name
# 	# #IP = '172.16.88.177' # Metasploitable (SSH Vulnerable)
# 	# #IP = '136.143.153.86' # Webcam (Shodan Info, Lots of Ports)
# 	# pynet = PyNet(target=ip_addr)
# 	# pynet.reconnaissance()
# 	# pynet.vulnerability_analysis()
# 	# pynet.save_json(outfile_path=outfile_location)
# 	# end = time.time()
# 	# print()
# 	# elapsed = end - start
# 	# print("Elapsed Time: ", elapsed)



	

# if __name__ == '__main__':
# 	main()