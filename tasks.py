from appintegration import *
from twilio_integration import *
from abuse_ipdb_integration import *
from geoIP_integration import *
from minfraud_integration import *
from sendgrid_integration import *
from shodan_integration import *
from VT_integration import *
from otx_integration import *
from google_safe_browsing import *
from hybrid_analysis import *

def abuse_ipdb_check_ip(d):

	ipdb = AbuseIPDB()
	return ipdb.check_ip(d)

def abuse_ipdb_check_cidr(d):

	ipdb = AbuseIPDB()
	return ipdb.check_cidr(d)

def abuse_ipdb_report_ip(d):

	ipdb = AbuseIPDB()
	return ipdb.report_ip(d)

def lookup_geoip(d):

	geoIP = GeoIP()
	return geoIP.lookup_geoip(d)

def google_safe_browsing_url_lookup(d):

	gsb = Google_Safe_Browsing()
	return gsb.find_threat_matches(d)

def get_otx_pulse_details(d):

	otx = OTX()
	return otx.get_pulse_details(d)

def get_otx_pulse_indicators(d):

	otx = OTX()
	return otx.get_otx_pulse_indicators(d)

def get_otx_indicator_details(d):

	otx = OTX()
	return otx.get_details(d)

def create_otx_pulse(d):

	otx = OTX()
	return otx.create_pulse(d)

def search_otx_pulses(d):

	otx = OTX()
	return otx.search_pulses(d)

def otx_scan_ip(d):

	otx = OTX()
	return otx.scan_ip(d)

def otx_scan_host(d):

	otx = OTX()
	return otx.scan_host(d)

def otx_scan_url(d):

	otx = OTX()
	return otx.scan_url(d)

def otx_scan_hash(d):

	otx = OTX()
	return otx_scan_hash(d)

def otx_scan_file(d):

	otx = OTX()
	return otx_scan_file(d)

def send_email(d):

	sg = SendGrid()
	return sg.send_email(d)

def shodan_lookup_host(d):

	s = Shodan()
	return s.lookup_host(d)

def send_text(d):

	t = Twilio()
	return t.send_text(d)

def make_call(d):

	t = Twilio()
	return t.make_call(d)

def vt_get_hash_report(d):

	vt = VirusTotal()
	return vt.get_hash_report(d)

def vt_scan_and_report(d):

	vt = VirusTotal()
	return vt.scan_and_report(d)

def vt_get_domain_report(d):

	vt = VirusTotal()
	return vt.get_domain_report(d)

def vt_get_ip_report(d):

	vt = VirusTotal()
	return vt.get_ip_report(d)