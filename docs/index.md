# PyNet Intelligence - Overview
*This is Pynet's Application documentation, for API information click here*

## Contents

* [User Guide](user_guide.md) - How to use PyNet Intelligence and interpret output.
* [Pipeline](pipeline.md) - Behind the scences of PyNet Intelligence on a more technical level.
* [Policy and Disclaimer](policy.md) - An important description of the policy surrounding PyNet Intelligence and a disclaimer for its use.


## Introduction

PyNet Intelligence is a network reconnaissance and intelligence application. The control flow of the application can be described in 3 steps:

1. The program takes in an IP address as user input.
2. The IP address is run through many different scans including some  that are built internally, and others that leverage popular APIs.
3. The results from the scans are delivered back to the user in the form of repors, charts, maps, and tables. 

PyNet is a unique tool in the way that it provides an abstraction for a suite of multi-level tools in cybersecurity. 

You also may want to check out [this](https://www.youtube.com/watch?v=OAEm-enU_jY) video demonstration.  I made it as a demonstration and covers much of the information in the documentation but at a less-technical level.

For a more in-depth description of the back-end please visit the [GitHub Repository](https://github.com/jamie-weiss/PyNet-Intel) and the [Pipeline section](pipeline.md) of the documentation.

## Purpose

There are 4 main reasons why PyNet Intelligence was built:

1. **Centralization** - In network scanning and penetration testing, there are a plethora of tools available for the cybersecurity engineer to use.  Often these tools live in many different locations (i.e Sodan on the web vs. NMAP as a command-line program). PyNet takes the industry standard tools and techniques, and centralizes them under one roof.  This is accomplished by building the tools internally, calling upon python pip packages, and the use of APIs. 
2. **Ease-of-Use** - Many of the tools in cybersecurity are built on command line and often require some level of prior Linux knowledge to use.  PyNet removes this requirement with a simple front end interface for user interaction.  As mentioned in the [introduction](#introduction), the only items that are user-facing in the system are a user input of an IP address, and the scan results report.
3. **Visualization** - The style and visualization of outputs from many network scanning tools is bounded by the interface that the program is built on.  Since many tools are built on command line interfaces, their visualization of output sufferes because of it.  PyNet intelligence scrapes the output of these tools, extracts important information, stores that information in a database, and runs analysis on that information to create more interesting insights to display.
4. **Vulnerability Reporting** - When detecting vulnerabilities in a system, it is often a requirement that the report contain a section for related [CVEs](https://cve.mitre.org/) (Common Vulnerability and Exposures). Unlike any other tool, PyNet will parse the CVE database for entries related to the vulnerabilities that were discovered in the user-inputted system.

## Technologies

The main technologies used in the stack are [python](https://www.python.org/) and a web developing library for python called [streamlit](https://www.streamlit.io/).

**Python:** Python 3 was used to build this tool.  Python 3 is the latest version of the python programming language.  Python has been an extremely popular choice for programming cybersecurity related tasks.  Python also is the most popular language for runnning data analysis.  PyNet application is a combination of both cybersecurity and data analysis.  Python remains popular because of its ability to work on a wide range of levels as well as its robust open sourced libraries and extensions to work with.  If you still need more convincing about python, feel free to read [this](https://startacybercareer.com/python-useful-for-cyber-security/) article.

**Streamlit:** Streamlit is a python library that was developed for data scientists to quickly deploy front end applications with ease.  Streamlit completely eliminates the need for HTML and JavaScript knowledge to build seamless dashboards on the web using markdown.  The product is free to use and part of python's pip package managing library.


















