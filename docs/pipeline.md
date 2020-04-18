# PyNet Intelligence - Pipeline
*This page discusses the control flow of the backend code.  It is a description of the scans run and the code behind them.  The next page will discuss a user's guide to using PyNet and how to interpret the results on a higher level than this.*

This application was built as an API first, and then developed into a full stack app. As a result, the back-end control flow is quite trivial and runs through a PyNet object and its functions. The general pipeline of functions is chronologically as follows:

### User Input

First, user input is read in directly from the web interface.  The input asks for an IP address and will of course check for valid formatting first.  This input is received and stored as the target system to run reconnaissance and analysis on.  The next 4 scans make up the reconnaissance schema.  These scans will be run, then the results stored in a database.

### NMAP Scan

The first scan that will occur is an NMAP scan.  [NMAP](https://nmap.org/) is one of the most popular tools in the cybersecurity field.  It is used to gather information about an IP and accomplishes this by pinging specific ports of a system and analyzing the responses.  Some of the information we can recieve from nmap is:

* Is the server running.
* Which ports are open and closed.
* What services are running on the open ports.
* What products and what versions are being used.
* What operating system is being used.
* And more...

Clearly NMAP is quite a powerful tool for information gathering.  The NMAP scan is the most time consuming out of all the other scans and analyses that are performed in this stack, however the tradeoff of gathering the most important information is absolutley worth it. An [NMAP library for python](https://pypi.org/project/python-nmap/) is used to run scans from a python script. 

### Blacklist IP Check

The next scan that is conducted is a blacklisted IP check.  This scan is trivial.  The IP address that the user inputted is run against a list of blacklisted IPs.  The IP addresses included in this database are IPs that have been reported having malicious or spam-like behaviors.  The response from this scan is a simple True or False boolean value if the IP was blacklisted or not. [The library](https://pypi.org/project/pydnsbl/) used scans more than 50 blacklists for the address in under 1 second.

### Geolocation Scan

The next scan searches for any location data for a given IP address. The goal is to be able to pinpoint the exact latitude and longitude coordinates of a system.  There are many databases containing IP location data available.  PyNet scans 5 different database for location data using an API found [here](https://github.com/tomas-net/ip2geotools).

### Shodan Scan

[Shodan](https://www.shodan.io/) is a tool that is *very* similar to this one.  Perhaps this tool was modeled after shodan in the first place.  The biggest difference is that PyNet is more robust than Shodan and as a result, takes longer to run, and is *way* more intrusive. The shodan API is used by PyNet to pull one important piece of information: the internet service provider of the target. Shodan is a search engine for internet connected devices or IoT devices. If the system, that PyNet is scanning, is connected to the internet, then Shodan can discover the internet service provider it is using and report it to us. 

### Database Storage

Now that we have quality information regarding the target IP address, all the important data we extracted gets stored in a database. The structure of the database is dictionary which allows us to search elements quickly. Pythonic dictionaries are also useful in converting to [Pandas DataFrames](https://www.geeksforgeeks.org/python-pandas-dataframe/) which are the desired data structure for many plotting libraries.

The next set of functions make up the analysis or intelligence schema.  These functions will require information gathered during the reconnaissance schema as input to run analysis on.  The results from these functions will be *appended* to the same database use to store the recon information. This whole payload will, in turn, be delivered to the visualization functions that will present the data to the user.

### Web Vulnerability Detection

After information was gathered about the target IP address, PyNet will then check if a web server is running on one of the open ports. If there is a web server, a set of vulnerability scans are run on this port.  The scans are as follows:

**Cross-Site Scripting:** An [XSS vulnerability](https://www.acunetix.com/websitesecurity/cross-site-scripting/) detector is run internally by first searching for form inputs on the web page.  Once form inputs are detected, a dictionary of JavaScript code is injected into the forms and submitted.  If the JavaScript is read as input, the web page is vulnerable. Otherwise, the result is not vulnerable.

At this moment, the search will not [crawl](https://www.sovrn.com/blog/website-crawling-information/) as a result of performance issues. Future releases will have this option. Additionally, the scipt-list used to test injected scripts is not large for the same reason. In future releases, the user will have the option to input their own word list, or run on a default one.

**Cross-Stie Tracing:** An [XST vulnerability](https://owasp.org/www-community/attacks/Cross_Site_Tracing) detector is run on the webpage discovered as well.  XST involves using XSS injected scripts, as well as the TRACE HTTP method.  A TRACE request is sent to the web server using the `requests` python library as `requests.request('TRACE', ip)`. Since our previous XSS check only runs a finite number of scripts, it is *not* safe to assume the site is safe from XST if the XSS check comes back secure.  As a result, a 200 OK response from the TRACE method will result in the XST test to show up as vulnerable.

**MIME Sniffing:** A [MIME Sniffing vulnerability](https://www.keycdn.com/support/what-is-mime-sniffing) detector is then run on the web page. MIME sniffing is a specific attack that involves leveraging HTML `X-Content-Type-Options:` to inject malicious code disguised as the desired file input.  Our detector checks this parameter using the `requests` library for python. The line `req.headers['X-Content-Type-Options']` will reveal the options set. If this is set to `nosniff`, the website is *not* vulnerable, otherwise, it is.

**Man in the Middle Attacks:** The last web-based vulnerability that PyNet will check for is the possibility of a [Man in the Middle attack](https://www.imperva.com/learn/application-security/man-in-the-middle-attack-mitm/). Man in the Middle Attakcs (MitM) occur when an actor is able to eavesdrop user's input over a server by listening to the packets being sent over the server.  While this type of attack is quite dense to disect, a quick way to check for a vulnerability is to check the transport security policy set by the web page. The policy can be found using the `requests` python library.  The line `req.headers['Strict-Transport-Security']` will throw an exception if it is not found, thus rendering the server vulnerable.

### SSH and FTP Security

The next vulnerability that is analyzed is the FTP and SSH server vulnerabilities. First, it needs to be confirmed that these services are indeed running on our target IP address.  If this check returns true, PyNet will proceed to run a dictionary attack in an attempt to crack the username and password for the system.  Much like the Cross-Site Scripting vulnerability check found in the [Web Vulnerability section](#web-vulnerability-detection), the default wordlist is not large.  The wordlist *is* however, stored with commonly used default credenttials which are run against the SSH and FTP ports. This attack uses the `paramiko` library, `socket` library, and `ftplib` library to run. It runs the block for SSH:
```
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(hostname=hostname, username=username, password=password, timeout=3)
```

It runs the block for FTP:
```
server = ftplib.FTP()
server.connect(hostname, 21, timeout=5)
server.login(username, password)
```

These code blocks will throw an exception if the username and password are incorrect so it should be wrapped in a try-except block.

### Related CVE Mappings

The last function of the analysis will map the vulnerabilities detected to related CVEs from [MITRE's Database](https://cve.mitre.org/).  This function relies heavily on the [Vulners API](https://github.com/vulnersCom/api). Vulners also has a product that is very simillary to PyNet Intel.  The main difference is that Vulners will scan your personal Linux based system only. In comparison, Vulners provides great visualization in a similar dashboard type interface. The Vulners API will look up vulnerabilities based on Common Platform Enumeration (CPE) key.  This means the vulnerabilities reported are unique to the specific software and version that is running on an open port.


### Database Appendage

The dictionary database that was created earlier contains just the scan results at this moment.  After the vulnerability analysis is run, this data gets appended to the existing database to save storage. This whole payload will get delivered to a suite of visualization functions.

### Visualization

Once the data is passed to the visualization functions, a number of temporary data structures are created to store data in the specific format that is required by our graphing libraries.  The main library used is [plotly](https://plotly.com/).  Plotly is a powerful graphing library for Python that can create beautiful, interactive charts.  Passing in Pandas DataFrames to Plotly makes the graphing process seamless (creating DataFrames with python dictionaries is also seamless).










