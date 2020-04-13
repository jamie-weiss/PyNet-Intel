#software_version = '8.3.0 - 8.3.7'
#software_version = '3.X - 4.X'
#software_version = '2-4'
#software_version = '3.2'
software_version = '3X'


if 'X' in software_version:
	print("no search")
elif ' - ' in software_version:
	split_arr = software_version.split()
	v = split_arr[-1]
	print(v)
elif '-' in software_version:
	split_arr = software_version.split('-')
	v = split_arr[-1]
	print(v)