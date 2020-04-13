import vulners
import warnings
from pprint import pprint

def scan_vulners_api(nmap_results_dict, API_KEY):
	vulners_api = vulners.Vulners(api_key=API_KEY)

	payload = {}

	for port_number in nmap_results_dict.keys():
		with warnings.catch_warnings():
			warnings.simplefilter("ignore")
			cpe = nmap_results_dict[port_number]['cpe']
			try:
				results = vulners_api.cpeVulnerabilities(cpe)
				vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
				assert vulnerabilities_list != []
			except:
				pass
				software_name = nmap_results_dict[port_number]['name']
				software_version = nmap_results_dict[port_number]['version']

				
				if ' - ' in software_version:
					split_arr = software_version.split()
					software_version = split_arr[-1]
				elif '-' in software_version:
					split_arr = software_version.split('-')
					software_version = split_arr[-1]

				try:
					results = vulners_api.softwareVulnerabilities(software_name, software_version)
					vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
					assert vulnerabilities_list != []
				except:
					pass
					vulnerabilities_list = [[]]
		try:			
			payload[port_number] = vulnerabilities_list[0]
		except:
			payload[port_number] = []


	return payload


