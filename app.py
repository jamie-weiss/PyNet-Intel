import streamlit as st
import numpy as np
import pandas as pd
import pydeck as pdk
import json
import altair as alt
import plotly.graph_objects as go
from pprint import pprint



INFILE = 'json/x.json'


def load_data(infile_path):
	with open(infile_path) as json_file:
		data = json.load(json_file)
		return data

def number_of_open_ports(data):
	open_ports = data['recon']['open_ports'].keys()
	return len(open_ports)

def get_threat_scores(data):
	score_dict = data['threat_scores']
	return round(score_dict['total']), round(score_dict['scaled'])

def get_blacklisted(data):
	return data['recon']['blacklisted']


def get_isp(data):
	return data['recon']['isp']

def create_location_df(data):
	latitude = data['recon']['location']['latitude']
	longitude = data['recon']['location']['longitude']
	loc_df = pd.DataFrame([[latitude, longitude]], columns=['lat', 'lon'])
	return loc_df

def create_port_threat_df(data):
	p_list = []
	t_list = []
	s_list = []
	for port_number in data['analysis']['CVE_vulnerabilities'].keys():
		p_list.append(port_number)
		s_list.append(len(data['analysis']['CVE_vulnerabilities'][port_number]))
		port_score = 0
		for cve in data['analysis']['CVE_vulnerabilities'][port_number]:
			port_score += cve['score']
		t_list.append(port_score)
	
	df_dict = {'port_number': p_list,
			   'threat_score': t_list,
			   'num_threats': s_list
			   }

	pt_df = pd.DataFrame(df_dict)
	return pt_df


def get_open_ports_list(data):
	return data['recon']['open_ports'].keys()


@st.cache
def run_port_analysis(data, port_number):
	payload = {}
	payload['state'] = data['recon']['open_ports'][port_number]['state']
	payload['name'] = data['recon']['open_ports'][port_number]['name']
	payload['version'] = data['recon']['open_ports'][port_number]['version']
	payload['product'] = data['recon']['open_ports'][port_number]['product']
	payload['num_vulnerabilities'] = len(data['analysis']['CVE_vulnerabilities'][port_number])
	payload['CVEs'] = data['analysis']['CVE_vulnerabilities'][port_number]
	return payload




data = load_data(INFILE)

st.title('PyNet Intel')
st.markdown("---")
st.markdown("## Scan Results")

st.markdown("**Web Server Running: **" + str(data['analysis']['xss']['web_server']))
if data['analysis']['xss']['web_server']:
	st.markdown("**Cross-Site Scripting Vulnerable: **" + str(data['analysis']['xss']['vulnerable']))
	if data['analysis']['xss']['vulnerable']:
		st.markdown("**XSS Exploit: **`" + data['analysis']['xss']['exploit'] + "`")
		st.markdown("**XSS Payload: **`" + data['analysis']['xss']['payload'] + "`")
	st.markdown("**Cross-Site Tracing Vulnerable: **" + str(data['analysis']['xst']['vulnerable']))
	st.markdown("**MIME Sniffing Vulnerable: **" + str(data['analysis']['mime_sniffing']['vulnerable']))
	st.markdown("**Content Type Options: **`" + str(data['analysis']['mime_sniffing']['options']) + "`")
	st.markdown("**Man in the Middle Vulnerable: **" + str(data['analysis']['man_in_the_middle']['vulnerable']))
	

	st.markdown("**HTTP Methods Responses:**")
	methods_dict = {}
	for method in data['analysis']['http_methods'].keys():
		methods_dict[method] = [data['analysis']['http_methods'][method]['status_code'], data['analysis']['http_methods'][method]['reason']]
	methods_df = pd.DataFrame(methods_dict, index=['Code', 'Reason'])
	st.table(methods_df)

st.markdown("**SSH Server Running: **" + str(data['analysis']['ssh']['ssh_server']))
if data['analysis']['ssh']['ssh_server']:
	st.markdown("**SSH Credentials Cracked: **" + str(data['analysis']['ssh']['cracked']))
	st.markdown("**SSH Security Level: **" + str(data['analysis']['ssh']['sec_level']))
	if data['analysis']['ssh']['cracked']:
		st.markdown("**Username: **`" + str(data['analysis']['ssh']['username'])+"`")
		st.markdown("**Password: **`" + str(data['analysis']['ssh']['password'])+"`")

st.markdown("**FTP Server Running: **" + str(data['analysis']['ftp']['ftp_server']))
if data['analysis']['ftp']['ftp_server']:
	st.markdown("**FTP Credentials Cracked: **" + str(data['analysis']['ftp']['cracked']))
	if data['analysis']['ftp']['cracked']:
		st.markdown("**Username: **`" + str(data['analysis']['ftp']['username'])+"`")
		st.markdown("**Password: **`" + str(data['analysis']['ftp']['password'])+"`")

location = [data['recon']['location']['longitude'], data['recon']['location']['latitude']]
df = create_location_df(data)

fig = go.Figure(data=go.Scattergeo(
        locationmode = 'USA-states',
        lon = df['lon'],
        lat = df['lat'],
        mode = 'markers',
        marker = dict(
            size = 8,
            opacity = 0.8,
            colorscale = 'Blues',
        )))

fig.update_layout(
		height=200,
		width=1400,
		margin=dict(
			l=0,r=0,b=0,t=0
		),
		paper_bgcolor='rgba(0,0,0,0)',
    	plot_bgcolor='rgba(0,0,0,0)',
        geo = dict(
        	bgcolor="rgba(0,0,0,0)",
            scope='world',
            showframe=False,
            showland = True,
	        landcolor = "rgb(212, 212, 212)",
	        subunitcolor = "rgba(0,0,0,0)",
	        countrycolor = "rgba(0,0,0,0)",
	        showlakes = True,
	        lakecolor = "rgba(0,0,0,0)",
	        showsubunits = True,
	        showcountries = True,
	        showcoastlines = False,
	        resolution = 50,
	        projection = dict(
	            type = 'mercator',
	            rotation_lon = -100
	        ),
	        lonaxis = dict(
	            showgrid = False,
	            range= [ -140.0, -55.0 ],
	            dtick = 5
	        ),
	        lataxis = dict (
	            showgrid = False,
	            gridwidth = 0.5,
	            range= [ 20.0, 60.0 ],
	            dtick = 5
	        )
    	),

)

st.sidebar.plotly_chart(fig, use_container_width=True)
ip = data['target']
st.sidebar.markdown('# ' + ip)
open_ports = number_of_open_ports(data)
if open_ports is not None:
	st.sidebar.markdown('**Number of Open Ports: **' + str(open_ports))

threat_total, threat_scaled = get_threat_scores(data)
if threat_total or threat_scaled is not None:
	st.sidebar.markdown('**Total Threat Score: **' + str(threat_total))
	st.sidebar.markdown('**Scaled Threat Score: **' + str(threat_scaled))

blacklisted = get_blacklisted(data)
if blacklisted is not None:
	st.sidebar.markdown('**Blacklisted IP: **' + str(blacklisted))

isp = get_isp(data)
if isp is not None:
	st.sidebar.markdown('**ISP: **' + str(isp))

st.markdown("---")
st.markdown("### Vulnerability by Port")
threat_df = create_port_threat_df(data)

chart_data=go.Scatter(
	x=threat_df['port_number'],
    y=threat_df['threat_score'],
    mode='markers',
    marker=dict(
    	size=16,
        color=threat_df['num_threats'],
        colorscale='Inferno',
        showscale=True,
        ),
)

layout = go.Layout(plot_bgcolor='rgb(238,238,238)',
		margin=dict(
			l=0,r=0,b=0,t=0
		),
		height=250,
		width=100,
)

fig = go.Figure(data=[chart_data], layout=layout)

fig.update_layout(
    xaxis={
        'title':'Port Number',
        'type':'log'},
    yaxis={'title':'Threat Score'})


st.plotly_chart(fig, use_container_width=True)
st.sidebar.markdown("---")
st.sidebar.markdown("**Port Vulnerability Analysis**")
port_analyze = st.sidebar.number_input(
					label="Port",
					min_value=1,
				)

valid_ports = get_open_ports_list(data)
temp_string = str(port_analyze)
if st.sidebar.button('Run Analysis'):
	if temp_string in valid_ports:
		payload = run_port_analysis(data, temp_string)
		st.markdown("## Port Vulnerability Report")
		st.markdown("---")

		if payload['state'] is not None:
			st.markdown("**Port State: **" + payload['state'])
		if payload['name'] is not None:
			st.markdown("**Service Name: **" + payload['name'])
		if payload['version'] is not None:
			st.markdown("**Service Version: **" + payload['version'])
		if payload['product'] is not None:
			st.markdown("**Product Name: **" + payload['product'])
		if payload['num_vulnerabilities'] is not 0:
			st.markdown("**Number of Vulnerabilities: **" + str(payload['num_vulnerabilities']))
			st.markdown("---")
			for v in payload['CVEs']:
				st.markdown("**CVE ID: **[" + v['id'] + "](" +v['link'] + ")")
				st.markdown("**Date Created: **" + v['created'] + "(Last Modified: " + v['modified'] + ')')
				st.markdown("**CVSS Threat Score: **" + str(v['score']))
				st.markdown("**Description: **" + v['description'])
				st.markdown("---")

	else:
		st.error("Port is not open")





# REMEMBER TO PUT XSS FTP SSH XST etc... Data in this shit












