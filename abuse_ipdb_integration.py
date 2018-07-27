from appintegration import *
import requests

class AbuseIPDB(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.api_key = self.secrets['abuse_ipdb']['api_key']

	def check_ip(self, d):
		"""
		Takes in a dictionary D with required key IP and optional
		key DAYS, both as strings. Returns response given by
		request.
		"""
		try:

			if 'days' in d:	
				url = 'https://www.abuseipdb.com/check/' +\
					d['ip'] + '/json?key=' + self.api_key +\
					'&days=' + d['days']

				params = {'IP' : d['ip'],
					  	  'DAYS' : d['days'],
					  	  'API_KEY' : self.api_key,
					  	 }
			else:
				url = 'https://www.abuseipdb.com/check/' +\
					d['ip'] + '/json?key=' + self.api_key +\
					'&days=30'

				params = {'IP' : d['ip'],
					  	  'DAYS' : '30',
					  	  'API_KEY' : self.api_key,
					  	 }

			return requests.get(url, params=params).json()

		except requests.exceptions.RequestException:
			return 'Request failed.'

	def check_cidr(self, d):
		"""
		Takes in a dictionary D with required key CIDR and
		optional key DAYS, both as strings. Returns response
		given by request.
		"""

		try:

			if 'days' in d:
				url = 'https://www.abuseipdb.com/check-block/json?network=' +\
					d['cidr'] + '&key=' + self.api_key +\
					'&days=' + d['days']

				params = {'CIDR' : d['cidr'],
					  	  'DAYS' : d['days'],
					  	  'API_KEY' : self.api_key,
					  	 }
			else:
				url = 'https://www.abuseipdb.com/check-block/json?network=' +\
					d['cidr'] + '&key=' + self.api_key +\
					'&days=30'

				params = {'CIDR' : d['cidr'],
					  	  'DAYS' : '30',
					  	  'API_KEY' : self.api_key,
					  	 }

			return requests.get(url, params=params).json()

		except requests.exceptions.RequestException:
			return 'Request failed.'

	def report_ip(self, d):
		"""
		Takes in a dictionary D with required keys CATEGORIES
		and IP and optional key COMMENT. CATEGORIES must be a
		list of numbers and IP must be a string.
		"""

		try:
			category_url = ''
			categories = d['categories']

			for cat in categories:
				category_url += str(cat) + ','

			category_url = category_url[:-1]

			if 'comment' in d:
				url = 'https://www.abuseipdb.com/report/json?key=' +\
					self.api_key + '&category=' + category_url +\
					'&comment=' + d['comment'] + '&ip=' + d['ip']

				params = {'IP' : d['ip'],
					  	  'COMMENT' : d['comment'],
					  	  'API_KEY' : self.api_key,
					  	  'CATEGORIES' : category_url
					  	 }
			else:

				url = 'https://www.abuseipdb.com/report/json?key=' +\
					self.api_key + '&category=' + category_url +\
					'&comment=&ip=' + d['ip']

				params = {'IP' : d['ip'],
					  	  'COMMENT' : '',
					  	  'API_KEY' : self.api_key,
					  	  'CATEGORIES' : category_url
					  	 }

			return requests.post(url, params=params).json()

		except requests.exceptions.RequestException:
			return 'Request failed.'
