from appintegration import *
import shodan

class Shodan(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.api_key = self.secrets['shodan']['api_key']
		self.api = shodan.Shodan(self.api_key)

	def lookup_host(self, d):
		"""
		Takes in a dictionary D with key IP and returns all
		information available for that IP.
		"""
		try:
			host = self.api.host(d['ip'])
			return host
		except shodan.APIError as e:
			return 'Error: {}'.format(e)