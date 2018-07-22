from appintegration import *

class MaxMind(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.license_key = self.secrets['max_mind']['license_key']
		self.account_id = self.secrets['max_mind']['account_id']
