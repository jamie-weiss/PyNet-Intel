import requests

def scan_content_type_options(url):
	req = requests.get(url)
	try:
		options_content_type = req.headers['X-Content-Type-Options']
		if options_content_type != 'nosniff':
			return True
		else:
			return False
	except:
		pass
		return None


def scan_MITM(url):
	req = requests.get(url)
	try:
		transport_security = req.headers['Strict-Transport-Security']
		return False
	except:
		pass
		return True
