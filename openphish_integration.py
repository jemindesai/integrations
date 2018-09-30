from appintegration import AppIntegration
import requests

class OpenPhish(AppIntegration):
    def check_url(self, d):
        """
        Takes in a dictionary D with required key `url`. Downloads
        phishing URL feed from openphish.com and checks if the
        url is in the feed.
        """

        try:
            url = d['url']
        except KeyError:
            return { 'error': 'true', 'message': 'Key url is required' }

        # Downloading this 350KB file every time you run the task
        # may waste memory
        response = requests.get("https://openphish.com/feed.txt")

        # Looks like [{ 'match': 'http://site1.com' }, { 'match': 'http://site2.com' }]
        matches = []

        for bad_url in response.text.split("\n"):
            # Check if user's url is a substring of a known
            # phishing url
            if url in bad_url:
                matches.append({
                    'match': bad_url
                })

        if len(matches) == 0:
            return { 'result': 'No matches found' }
        else:
            return matches