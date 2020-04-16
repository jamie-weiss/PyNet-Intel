import streamlit as st
import numpy as np
import pandas as pd
import pydeck as pdk
import json
import altair as alt
import plotly.graph_objects as go
from pprint import pprint



INFILE = 'json/results.json'


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

st.title('PyNet Intel: Scan Results')
st.markdown("---")

if data['analysis']['xss']['web_server']:
 	if data['analysis']['xss']['vulnerable']:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Cross-Site Scripting: <text class="text-danger">Vulnerable</text></h4>
				<h5 class="card-text">Exploit: <pre>{data['analysis']['xss']['exploit']}</pre></h5>
				<h5 class="card-text">Payload: <pre>{data['analysis']['xss']['payload']}</pre></h5>
			</div>
		</div>

			''', unsafe_allow_html=True)
 	else:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Cross-Site Scripting: <text class="text-success">No Vulnerability Detected</text></h5>
			</div>
		</div>

			''', unsafe_allow_html=True)

 	if data['analysis']['xst']['vulnerable']:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Cross-Site Tracing: <text class="text-danger">Vulnerable</text></h4>
				<h5 class="card-test">Responses - GET: {data['analysis']['http_methods']['GET']['status_code']} | POST: {data['analysis']['http_methods']['POST']['status_code']} | PUT: {data['analysis']['http_methods']['PUT']['status_code']} | DELETE: {data['analysis']['http_methods']['DELETE']['status_code']} | OPTIONS: {data['analysis']['http_methods']['OPTIONS']['status_code']} | TRACE: {data['analysis']['http_methods']['TRACE']['status_code']} | TEST: {data['analysis']['http_methods']['TEST']['status_code']}</h5>
			</div>
		</div>

			''', unsafe_allow_html=True)
 	else:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Cross-Site Tracing: <text class="text-success">No Vulnerability Detected</text></h5>
			</div>
		</div>

			''', unsafe_allow_html=True)

 	if data['analysis']['mime_sniffing']['vulnerable']:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Mime Sniffing: <text class="text-danger">Vulnerable</text></h4>
				<h5 class="card-test">Content Type Options: {str(data['analysis']['mime_sniffing']['options'])}</h5>
			</div>
		</div>

			''', unsafe_allow_html=True)
 	else:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Mime Sniffing: <text class="text-success">No Vulnerability Detected</text></h4>
			</div>
		</div>

			''', unsafe_allow_html=True)

 	if data['analysis']['man_in_the_middle']['vulnerable']:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Man-in-the-Middle Attack: <text class="text-danger">Vulnerable</text></h4>
			</div>
		</div>

			''', unsafe_allow_html=True)
 	else:
 		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">Man-in-the-Middle Attack: <text class="text-success">No Vulnerability Detected</text></h4>
			</div>
		</div>

			''', unsafe_allow_html=True)
else:
	st.markdown(f'''

	<div class="card bg-light mb-3">
		<div class="card-body">
			<h4 class="card-title">Web Server Not Running: <text class="text-success">No Web Vulnerabilities Detected</text></h4>
		</div>
	</div>

		''', unsafe_allow_html=True)



if data['analysis']['ssh']['ssh_server']:
	if data['analysis']['ssh']['cracked']:
		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">SSH Credentials: <text class="text-danger">Cracked</text></h4>
				<h5 class="card-test">Username: {str(data['analysis']['ssh']['username'])}</h5>
				<h5 class="card-test">Password: {str(data['analysis']['ssh']['password'])}</h5>
			</div>
		</div>

			''', unsafe_allow_html=True)
	elif data['analysis']['ssh']['sec_level'] == 1:
		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">SSH Credentials: <text class="text-warning">Possible to Crack</text></h4>
				<h5 class="card-test">Credentials not found in small default wordlist. No server timeout or bot detection.</h5>
			</div>
		</div>

			''', unsafe_allow_html=True)
	else:
		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">SSH Credentials: <text class="text-success">Unable to Crack</text></h4>
				<h5 class="card-test">Secure credentials with retry limit and/or bot detection.</h5>
			</div>
		</div>

			''', unsafe_allow_html=True)

else:
	st.markdown(f'''

	<div class="card bg-light mb-3">
		<div class="card-body">
			<h4 class="card-title">SSH Not Running: <text class="text-success">No SSH Vulnerabilities Detected</text></h5>
		</div>
	</div>

		''', unsafe_allow_html=True)


if data['analysis']['ftp']['ftp_server']:
	if data['analysis']['ftp']['cracked']:
		st.markdown(f'''

		<div class="card bg-light mb-3">
			<div class="card-body">
				<h4 class="card-title">FTP Credentials: <text class="text-danger">Cracked</text></h4>
				<h5 class="card-test">Username: {str(data['analysis']['ftp']['username'])}</h5>
				<h5 class="card-test">Password: {str(data['analysis']['ftp']['password'])}</h5>
			</div>
		</div>

			''', unsafe_allow_html=True)

else:
	st.markdown(f'''

	<div class="card bg-light mb-3">
		<div class="card-body">
			<h4 class="card-title">FTP Not Running: <text class="text-success">No FTP Vulnerabilities Detected</text></h5>
		</div>
	</div>

		''', unsafe_allow_html=True)


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
	        subunitcolor = "rgb(243,244,247)",
	        countrycolor = "rgb(243,244,247)",
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
open_ports = str(number_of_open_ports(data))
if open_ports is not None:
	st.sidebar.markdown(f'''

	<div class="card text-white bg-secondary mb-3" style="width:18rem">
		<div class="card-body">
			<h5 class="card-title">Number of Open Ports</h5>
			<p class="card-text">{open_ports}</p>
		</div>
	</div>


		''', unsafe_allow_html=True)

threat_total, threat_scaled = get_threat_scores(data)
if threat_total or threat_scaled is not None:
	st.sidebar.markdown(f'''

	<div class="card text-white bg-secondary mb-3" style="width:18rem">
		<div class="card-body">
			<h5 class="card-title">Vulnerability Scores</h5>
			<p class="card-text">Total: {str(threat_total)} | Scaled: {str(threat_scaled)}</p>
		</div>
	</div>


		''', unsafe_allow_html=True)

blacklisted = get_blacklisted(data)
if blacklisted is not None:
	st.sidebar.markdown(f'''

	<div class="card text-white bg-secondary mb-3" style="width:18rem">
		<div class="card-body">
			<h5 class="card-title">Blacklisted IP</h5>
			<p class="card-text">{str(blacklisted)}</p>
		</div>
	</div>


		''', unsafe_allow_html=True)

isp = get_isp(data)
if isp is not None:
	st.sidebar.markdown(f'''

	<div class="card text-white bg-secondary mb-3" style="width:18rem">
		<div class="card-body">
			<h5 class="card-title">Internet Service Provider</h5>
			<p class="card-text">{str(isp)}</p>
		</div>
	</div>


		''', unsafe_allow_html=True)

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












