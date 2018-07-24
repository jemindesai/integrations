from maxmind_integration import *
from minfraud import Client

class MinFraud(MaxMind):

	def __init__(self):
		MaxMind.__init__(self)
		self.client = minfraud.webservice.Client(self.account_id, self.license_key)