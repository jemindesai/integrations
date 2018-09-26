import requests
from appintegration import AppIntegration

class UnshortenURL(AppIntegration):
    def unshorten_url(self, d):
        """
        Takes in a dictionary D with required key URL
        (eg, https://bit.ly/J7SNth). Follows 301 redirects to
        get the full link.

        Note: This is not an integration with a 3rd party.
        """
        try:
            short_url = d['url']
        except KeyError:
            return { 'status' : 'Error', 'error_message': 'Key url is required'}

        session = requests.Session()  # so connections are recycled
        response = session.head(short_url, allow_redirects=True)
        full_url = response.url

        return { 'full_url': full_url }