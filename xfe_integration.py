from appintegration import AppIntegration
import requests
import base64

# Stands for IBM XForce Exchange
class XFE(AppIntegration):
    def __init__(self):
        AppIntegration.__init__(self)
        api_key = self.secrets['xfe']['api_key']
        api_password = self.secrets['xfe']['api_password']

        # we must pass base64(apikey:pass) in the Authorization header
        string_to_encode = '%s:%s' % (api_key, api_password)
        self.token = base64.b64encode(string_to_encode.encode())

    def lookup_ip(self, d):
        """Dictionary d has required key, `ip`."""
        try:
            ip = d['ip']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key ip is required'} 

        return requests.get("https://api.xforce.ibmcloud.com/ipr/%s" % ip, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token.decode()
        }).json()

    def lookup_hash(self, d):
        """Dictionary d has required key, `hash`. Can be any type of hash (I believe,
        documentation doesn't specify.)"""
        try:
            hash = d['hash']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key hash is required'} 
        
        return requests.get("https://api.xforce.ibmcloud.com/malware/%s" % hash, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token.decode()
        }).json()

    def lookup_url(self, d):
        """Dictionary d has required key, `url`."""
        try:
            url = d['url']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key url is required'} 
        
        return requests.get("https://api.xforce.ibmcloud.com/url/%s" % url, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token.decode()
        }).json()

    def get_malware_for_url(self, d):
        """Dictionary d has required key, `url`."""
        try:
            url = d['url']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key url is required'} 
        
        return requests.get("https://api.xforce.ibmcloud.com/url/malware/%s" % url, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token.decode()
        }).json()

    def get_whois(self, d):
        """Dictionary d has required key, `host`. This is either an IP or
        domain."""
        try:
            host = d['host']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key host is required'} 
        
        return requests.get("https://api.xforce.ibmcloud.com/whois/%s" % host, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token.decode()
        }).json()

    def get_networks_for_asns(self, d):
        """Dictionary d has required key, `asn`, an ASN code like `ASN5387`."""
        try:
            asn = d['asn']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key asn is required'} 
        
        return requests.get("https://api.xforce.ibmcloud.com/ipr/asn/%s" % asn, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token.decode()
        }).json()

    def get_dns_records(self, d):
        """Dictionary d has required key, `host`, a domain, url, or IP. Returns
        both passive and active DNS records."""
        try:
            host = d['host']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key host is required'} 
        
        return requests.get("https://api.xforce.ibmcloud.com/resolve/%s" % host, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Basic %s' % self.token.decode()
        }).json()