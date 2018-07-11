from appintegration import *
from twilio.rest import Client

class Twilio(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.phone_number = self.secrets['twilio']['phone_number']
		self.account_sid = self.secrets['twilio']['account_sid']
		self.auth_token = self.secrets['twilio']['auth_token']
		self.client = Client(self.account_sid, self.auth_token)

	def send_text(self, d):
		"""
		Takes in a dictionary D with keys 'phone_number' and
		'message' and sends a text.
		"""
		try:
			message = self.client.messages\
				.create(
					body = d['message'],
					from_ = self.phone_number,
					to = d['phone_number']
				)
		except twilio.base.exceptions.TwilioRestException:
			return {'status' : 'Error',
					'error_message' : 'Message failed to send'}

		output = {'status' : 'OK',
				  'error_message' : ''}

		return output

	def make_call(self, d):
		"""
		Takes in a dictionary D with key 'phone_number' and 
		calls the provided number.
		"""
		try:
			call = self.client.calls.create(
					to = d['phone_number'],
					from_ = self.phone_number,
					url = "http://demo.twilio.com/docs/voice.xml"
					)
		except twilio.base.exceptions.TwilioRestException:
			return {'status' : 'Error',
					'error_message' : 'Message failed to send'}

		output = {'status' : 'OK',
				  'error_message' : ''}

		return output