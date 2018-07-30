from appintegration import *
import requests

class Google_Safe_Browsing(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.api_key = self.secrets['google_safe_browsing']['api_key']

	def find_threat_matches(self, d):

		url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}'.format(key=self.api_key)
		params = {}
		params['client'] = {}
		client = params['client']
		client['clientId'] = 'orchestrator'
		client['clientVersion'] = '1.0.0'
		params['threatInfo'] = {}
		threat_info = params['threatInfo']

		threat_info['threatTypes'] = ['MALWARE', 'SOCIAL_ENGINEERING',
									 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION']

		if 'platform_types' in d:
			threat_info['platformTypes'] = list(map(str.upper, d['platform_types']))
		else:
			threat_info['platformTypes'] = ['WINDOWS', 'LINUX', 'OSX', 
											'ANDROID', 'IOS', 'CHROME']

		threat_info['threatEntryTypes'] = ['URL']

		threat_info['threatEntries'] = [{'url': d['url']}]

		return requests.post(url, json=params).json()
