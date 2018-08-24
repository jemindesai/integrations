from appintegration import *
import requests
import time

class HybridAnalysis(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.api_key = self.secrets['hybrid_analysis']['api_key']
		self.base_url = 'https://www.hybrid-analysis.com/api/v2'

	def search_hash(self, d):
		"""
		Takes in a dict D with key HASH, which is a string,
		and outputs a summary.
		"""
		url = self.base_url + '/search/hash'
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		return requests.post(url, data=d, headers=headers).json()

	def search_hashes(self, d):
		"""
		Takes in a dict D with key HASHES[], which is a list of strings,
		and outputs a summary.
		"""
		url = self.base_url + '/search/hashes'
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		return requests.post(url, data=d, headers=headers).json()

	def search_database(self, d):
		"""
		Takes in a dict D with keys FILENAME, FILETYPE, FILETYPE_DESC,
		ENV_ID, COUNTRY, VERDICT, AV_DETECT, VX_FAMILY, TAG, PORT,
		HOST, DOMAIN, URL, SIMILAR_TO, CONTEXT, IMP_HASH, SSDEEP,
		AUTHENTIHASH, all of which are optional strings, except 
		VERDICT and PORT, which are integers. Returns search results.
		"""
		url = self.base_url + '/search/terms'
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		if len(d) == 0:
			return {'message': 'Please fill in at least one search parameter.'}
		return requests.post(url, data=d, headers=headers).json()

	def quickscan_with_overview(self, d):
		"""
		Takes in a dict D with key URL, which is a file submission by
		url (string), and returns the analysis overview.
		"""
		url = self.base_url + '/quick-scan/url-to-file'

		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		d['scan_type'] = 'all'
		result = requests.post(url, data=d, headers=headers).json()

		start = time.time()
		interval = 20
		while not result['finished']:
			wait = time.time() - start
			if wait > interval:
				url = self.base_url + '/quick-scan/{id}'.format(id=result['id'])
				params = {'sha256': result['sha256'], 'id': result['id']}
				result = requests.get(url, params=params, headers=headers).json()

		url = self.base_url + '/overview/{sha256}'.format(sha256=result['sha256'])
		return requests.get(url, headers=headers).json()

	def overview(self, d):
		"""
		Takes in a dict D with key SHA256, which is a string, as well as,
		an optional key ID, which is a string associated with a quickscan 
		performed by the user, and either returns the overview for that hash
		or tells the user that the scan isn't finished.
		"""
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}

		if 'id' in d:
			url = self.base_url + '/quick-scan/{id}'.format(id=d['id'])
			params = {'sha256': d['sha256'], 'id': d['id']}
			result = requests.get(url, params=params, headers=headers).json()
			if not result['finished']:
				return result

		url = self.base_url + '/overview/{sha256}'.format(sha256=d['sha256'])
		return requests.get(url, headers=headers).json()

	def quickscan(self, d):
		"""
		Takes in a dict D with key URL, which is a file submission by
		url (string), and returns the result of the post request.
		"""
		url = self.base_url + '/quick-scan/url-to-file'

		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		d['scan_type'] = 'all'
		return requests.post(url, data=d, headers=headers).json()

