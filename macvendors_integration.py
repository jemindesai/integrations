import requests
from appintegration import *

class MacVendors(AppIntegration):
    def look_up_mac(self, d):
        """
        Takes in a dictionary D with required key MAC_ADDRESS,
        a string. Returns the vendor assigned to that MAC address.
        """
        try:
            mac_address = d['mac_address']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key mac_address is required'} 

        response = requests.get("https://api.macvendors.com/%s/" % mac_address)
        # response looks like 'Apple, Inc', so we must turn it into a dictionary
        return { 'vendor': response.text }
