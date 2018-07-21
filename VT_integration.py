from appintegration import *
import requests
import time

class VirusTotal(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.api_key = self.secrets['virus_total']['api_key']

	def scan_and_report(self, d):
		"""Takes in a dict D with key RESOURCE, which is (a string) 
		the url of the file in question and tries to retrieve that 
		url's report. If the report does not exist, it will scan the 
		url and wait for a report to be generated before returning 
		the response dictionary.
		"""

		url = 'https://www.virustotal.com/vtapi/v2/url/report'
		params = {'apikey': self.api_key, 'resource': d['resource']}
		response = requests.get(url, params=params).json()
		
		if 'scans' not in response:
			
			url = 'https://www.virustotal.com/vtapi/v2/url/scan'
			params = {'apikey': self.api_key, 'url': d['resource']}
			response = requests.post(url, data=params).json()

			url = 'https://www.virustotal.com/vtapi/v2/url/report'
			params = {'apikey': self.api_key, 'resource': d['resource']}

			start = time.time()
			interval = 20
			while 'scans' not in response:
				wait = time.time() - start
				if wait > interval:
					response = requests.get(url, params=params).json()
					interval = 20 + wait
					print('iter')
			return response

		else:
			return response

	def get_domain_report(self, d):
		"""
		Takes in a dict D with key DOMAIN (as a string) and outputs 
		a dictionary RESPONSE containing a report.
		"""
		url = 'https://www.virustotal.com/vtapi/v2/domain/report'
		params = {'apikey': self.api_key, 'domain': d['domain']}
		response = requests.get(url, params=params)
		return response.json()

	def get_ip_report(self, d):
		"""
		Takes in a dict D with key IP (as a string) and outputs a 
		dictionary RESPONSE containing a report.
		"""
		url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
		params = {'apikey': self.api_key, 'ip': d['ip']}
		response = requests.get(url, params=params)
		return response.json()
