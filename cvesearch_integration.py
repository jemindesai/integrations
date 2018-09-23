import requests
from appintegration import *

class CVESearch(AppIntegration):
    def look_up_cve(self, d):
        """
        Takes in a dictionary D with required key `cve` (eg, "CVE-2010-3333")
        and fetches its info from http://cve.circl.lu.
        """
        try:
            cve = d['cve']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key cve is required' }

        return requests.get("http://cve.circl.lu/api/cve/%s" % cve).json()