import sendgrid
from sendgrid.helpers.mail import *
from appintegration import *

class SendGrid(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.api_key = self.secrets['send_grid']['api_key']
		self.APIclient = sendgrid.SendGridAPIClient(apikey=self.api_key)

	def send_email(self, d):
		"""
		Takes in a dictionary D with keys 'from', 'to', 'subject',
		and 'content' and sends an email.
		"""
		from_email = Email(d['from'])
		to_email = Email(d['to'])
		subject = d['subject']
		content = Content("text/plain", d['content'])
		mail = Mail(from_email, subject, to_email, content)
		response = self.APIclient.client.mail.send.post(request_body=mail.get())
