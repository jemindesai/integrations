import requests
from appintegration import AppIntegration

class HaveIBeenPwned(AppIntegration):
    def get_breaches_for_email(self, d):
        """
        Lists the breaches `email` was involved in.
        https://haveibeenpwned.com/API/v2
        
        `email` (required) - email address to find breaches for
        `domain` (optional) - only search for email in breaches of this domain
        """
        try:
            email = d['email']
        except KeyError:
            return {
                'status': 'Error',
                'error_message': 'Key email is required'
            }

        domain = d.get('domain', None)
        if domain is None:
            return requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/%s" % email).json()
        else:
            return requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/%s?domain=%s" % (email, domain)).json()