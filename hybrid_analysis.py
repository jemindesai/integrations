from appintegration import *
import requests
from array import array

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
