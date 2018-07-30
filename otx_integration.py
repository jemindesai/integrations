from appintegration import *
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from OTXv2 import BadRequest
import hashlib

class OTX(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.api_key = self.secrets['otx']['api_key']
		self.otx = OTXv2(self.api_key)


	def get_pulse_details(self, d):
		"""
		Takes in a dict D with key PULSE_ID
		and returns its details.
		"""
		try:
			return self.otx.get_pulse_details(d['pulse_id'])
		except BadRequest:
			return 'Failed'


	def get_pulse_indicators(self, d):
		"""
		Takes in a dict D with key PULSE_ID
		and returns its associated indicators.
		"""
		try:
			indicators = self.otx.get_pulse_indicators(d['pulse_id'])
			return indicators
		except BadRequest:
			return 'Failed'

	def get_details(self, d):
		"""
		Takes in a dict D with keys TYPE and RESOURCE, both as strings.
		Assumes RESOURCE corresponds with TYPE and returns the indicator
		details.
		"""
		try:
			indicator_type = d['type']
			resource = d['resource']
			if indicator_type == 'IPv4':
				return self.otx.get_indicator_details_full(IndicatorTypes.IPv4,
																	 resource)
			elif indicator_type == 'IPv6':
				return self.otx.get_indicator_details_full(IndicatorTypes.IPv6,
																	 resource.lower())

			elif indicator_type == 'domain':
				return self.otx.get_indicator_details_full(IndicatorTypes.DOMAIN,
																	 resource)

			elif indicator_type == 'hostname':
				return self.otx.get_indicator_details_full(IndicatorTypes.HOSTNAME,
																	 resource)

			elif indicator_type == 'url':
				return self.otx.get_indicator_details_full(IndicatorTypes.URL,
																	 resource)

			elif indicator_type == 'hash':
				hash_type = IndicatorTypes.FILE_HASH_MD5

				if len(resource) == 64:
					hash_type = IndicatorTypes.FILE_HASH_SHA256
				if len(resource) == 40:
					hash_type = IndicatorTypes.FILE_HASH_SHA1

				return self.otx.get_indicator_details_full(hash_type, resource)

			elif indicator_type == 'md5':
				return self.otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5,
																	 resource)

			elif indicator_type == 'sha1':
				return self.otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA1,
																	 resource)

			elif indicator_type == 'sha256':
				return self.otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256,
																	 resource)

			elif indicator_type == 'cve':
				return self.otx.get_indicator_details_full(IndicatorTypes.CVE,
																	 resource)

			else:
				return 'Bad input'
		except BadRequest:
			return 'Failed'

	def create_pulse(self, d):
		"""
		Takes in a dict D with keys NAME and INDICATORS. NAME
		is a string and INDICATORS is a list of dictionaries with 
		keys INDICATOR and TYPE, both of which are strings. Creates
		a pulse with the given indicators and returns response.
		"""
		try:
			return self.otx.create_pulse(name = d['name'],
								public = True,
								indicators = d['indicators'],
								tags = [],
								references = [])
		except BadRequest:
			return 'Failed'

	def search_pulses(self, d):
		"""
		Takes in a dict D with key PULSE and searches
		the pulse and returns the result.
		"""
		try:
			return self.otx.search_pulses(d['pulse'])
		except BadRequest:
			return 'Failed'

	def scan_ip(self, d):
		"""
		Takes in a dict D with key IP. The key value must be a string.
		Scans the given resource and returns alerts.
		"""
		try:
			return self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4,
															d['ip'],
															'general')
		except BadRequest:
			return 'Failed'

	def scan_host(self, d):
		"""
		Takes in a dict D with key HOST. The key value must be a string.
		Scans the given resource and returns alerts.
		"""
		try:
			host_result = self.otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME,
																	d['host'],
																	'general')

			domain_result = self.otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN,
																		d['host'],
																		'general')

			host_result.update(domain_result)
			return host_result
		except BadRequest:
			return 'Failed'

	def scan_url(self, d):
		"""
		Takes in a dict D with key URL. The key value must be a string.
		Scans the given resource and returns alerts.
		"""
		try:
			return otx.get_indicator_details_full(IndicatorTypes.URL, d['url'])
		except BadRequest:
			return 'Failed'

	def scan_hash(self, d):
		"""
		Takes in a dict D with key HASH. The key value must be a string,
		but it can be any hash type. Scans the given resource and returns 
		alerts.
		"""
		try:
			hash_type = IndicatorTypes.FILE_HASH_MD5
			hash = d['hash']
			if len(hash) == 64:
				hash_type = IndicatorTypes.FILE_HASH_SHA256
			if len(hash) == 40:
				hash_type = IndicatorTypes.FILE_HASH_SHA1

			return self.otx.get_indicator_details_full(hash_type, hash)
		except BadRequest:
			return 'Failed'

	def scan_file(self, d):
		"""
		Takes in a dict D with key FILE. The key value must be a string.
		Scans the given resource and returns alerts.
		"""
		try:
			hash = hashlib.md5(open(d['file'], 'rb').read()).hexdigest()
			return self.scan_hash({'hash' : hash})
		except BadRequest:
			return 'Failed'
