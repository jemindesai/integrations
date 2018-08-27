from appintegration import *
import requests
import time
import json

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

	def quickscan_file_with_overview(self, d):
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

	def quickscan_file(self, d):
		"""
		Takes in a dict D with key URL, which is a file submission by
		url (string), and returns the result of the post request.
		"""
		url = self.base_url + '/quick-scan/url-to-file'
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		d['scan_type'] = 'all'
		return requests.post(url, data=d, headers=headers).json()

	def convert_quickscan_to_sandbox(self, d):
		"""
		Takes in a dict D with keys ID and ENVIRONMENT_ID. ID is a
		string associated with a quickscan that has already been performed.
		ENVIRONMENT_ID is an integer associated with different operating
		platforms (e.g. Windows 7 64 bit). Other optional keys are the 
		following: NO_SHARE_THIRD_PARTY (boolean), ALLOW_COMMUNITY_ACCESS
		(boolean), NO_HASH_LOOKUP (boolean), ACTION_SCRIPT (string),
		HYBRID_ANALYSIS (boolean), EXPERIMENTAL_ANTI_EVASION (boolean),
		SCRIPT_LOGGING (boolean), INPUT_SAMPLE_TAMPERING (boolean),
		TOR_ENABLED_ANALYSIS (boolean), OFFLINE_ANALYSIS (boolean),
		EMAIL (string), PROPERTIES (string), COMMENT (string),
		CUSTOM_DATE_TIME (string), CUSTOM_CMD_LINE (string),
		CUSTOM_RUN_TIME (integer), CLIENT (string), SUBMIT_NAME
		(string), PRIORITY (integer), DOCUMENT_PASSWORD (string),
		ENVIRONMENT_VARIABLE (string). With these arguments, the
		quickscan associated with ID is converted to a sandbox
		submission.
		"""
		url = self.base_url + '/quick-scan/{id}/convert-to-full'.format(id=d['id'])
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		return requests.post(url, data=d, headers=headers).json()

	def quickscan_url(self, d):
		"""
		Takes in a dict D with key URL and scans the given URL. Returns
		the result of the post request.
		"""
		url = self.base_url + '/quick-scan/url-for-analysis'
		d['scan_type'] = 'all'
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		return requests.post(url, data=d, headers=headers).json()

	def quickscan_url_with_overview(self, d):
		"""
		Takes in a dict D with key URL, which is a string,
		and returns the analysis overview.
		"""
		url = self.base_url + '/quick-scan/url-for-analysis'

		d['scan_type'] = 'all'
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
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

	def submit_file(self, d):
		"""
		Takes in a dict D with keys URL and ENVIRONMENT_ID. URL is a string.
		ENVIRONMENT_ID is an integer associated with different operating
		platforms (e.g. Windows 7 64 bit). Other optional keys are the 
		following: NO_SHARE_THIRD_PARTY (boolean), ALLOW_COMMUNITY_ACCESS
		(boolean), NO_HASH_LOOKUP (boolean), ACTION_SCRIPT (string),
		HYBRID_ANALYSIS (boolean), EXPERIMENTAL_ANTI_EVASION (boolean),
		SCRIPT_LOGGING (boolean), INPUT_SAMPLE_TAMPERING (boolean),
		TOR_ENABLED_ANALYSIS (boolean), OFFLINE_ANALYSIS (boolean),
		EMAIL (string), PROPERTIES (string), COMMENT (string),
		CUSTOM_DATE_TIME (string), CUSTOM_CMD_LINE (string),
		CUSTOM_RUN_TIME (integer), CLIENT (string), SUBMIT_NAME
		(string), PRIORITY (integer), DOCUMENT_PASSWORD (string),
		ENVIRONMENT_VARIABLE (string). With these arguments, the
		quickscan associated with ID is converted to a sandbox
		submission.
		"""
		url = self.base_url + '/submit/url-to-file'
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		return requests.post(url, data=d, headers=headers).json()

	def sandbox_reports(self, d):
		"""
		Takes in a dict D with key IDS, which is a list of dicts
		containing the keys ID (string), JOB_ID (boolean), and
		ENVIRONMENT_ID (integer). If JOB_ID is true, the ID will
		be added to a new dictionary with the key HASHES[], which
		is the list of ids that the sandbox will retrieve reports
		for. If JOB_ID is false, then the ID string will be combined
		with the ENVIRONMENT_ID to form the valid id that can be
		added to HASHES[].
		"""
		headers = {'api-key': self.api_key, 'user-agent': 'Falcon Sandbox'}
		request_dict = {}
		request_dict['hashes[]'] = []
		try:
			for i in d['ids']:
				if i['job_id']:
					request_dict['hashes[]'].append(i['id'])
				else:
					request_dict['hashes[]'].append(
						i['id'] + ':' + str(i['environment_id']))

			if not request_dict:
				return {'message': 'Please input at least one ID.'}

			unfinished = []
			index = 0

			for i in request_dict['hashes[]']:
				url = self.base_url + '/report/{id}/state'.format(id = i)
				params = {'id': i}
				result = requests.get(url, params = params, headers = headers).json()
				success = 'state' in result
				if not success or result['state'] != 'SUCCESS':
					result['id'] = i
					unfinished.append(result)
					request_dict['hashes[]'][index] = None
				index += 1

			if unfinished:
				while None in request_dict['hashes[]']:
					request_dict['hashes[]'].remove(None)

			if not request_dict['hashes[]']:
				return unfinished

			url = self.base_url + '/report/summary'
			result = requests.post(url, data=request_dict, headers=headers).json()
			if type(result) == dict:
				return result
			result.extend(unfinished)
			return result
		except json.JSONDecodeError:
			return {'error': 'Something went wrong. Try again.'}
