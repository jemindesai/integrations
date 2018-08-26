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

abuse_ipdb_check_ip.id = 'AbuseIPDB Check IP'

def abuse_ipdb_check_cidr(d):

	ipdb = AbuseIPDB()
	return ipdb.check_cidr(d)

abuse_ipdb_check_cidr.id = 'AbuseIPDB Check CIDR'

def abuse_ipdb_report_ip(d):

	ipdb = AbuseIPDB()
	return ipdb.report_ip(d)

abuse_ipdb_report_ip.id = 'AbuseIPDB Report IP'

def lookup_geoip(d):

	geoIP = GeoIP()
	return geoIP.lookup_geoip(d)

lookup_geoip.id = 'Lookup GeoIP'

def google_safe_browsing_url_lookup(d):

	gsb = Google_Safe_Browsing()
	return gsb.find_threat_matches(d)

google_safe_browsing_url_lookup.id = 'Google Safe Browsing URL Lookup'

def get_otx_pulse_details(d):

	otx = OTX()
	return otx.get_pulse_details(d)

get_otx_pulse_details.id = 'Get OTX Pulse Details'

def get_otx_pulse_indicators(d):

	otx = OTX()
	return otx.get_otx_pulse_indicators(d)

get_otx_pulse_indicators.id = 'Get OTX Pulse Indicators'

def get_otx_indicator_details(d):

	otx = OTX()
	return otx.get_details(d)

get_otx_indicator_details.id = 'Get OTX Indicator Details'

def create_otx_pulse(d):

	otx = OTX()
	return otx.create_pulse(d)

create_otx_pulse.id = 'Create OTX Pulse'

def search_otx_pulses(d):

	otx = OTX()
	return otx.search_pulses(d)

search_otx_pulses.id = 'Search OTX Pulses'

def otx_scan_ip(d):

	otx = OTX()
	return otx.scan_ip(d)

otx_scan_ip.id = 'OTX Scan IP'

def otx_scan_host(d):

	otx = OTX()
	return otx.scan_host(d)

otx_scan_host.id = 'OTX Scan Host'

def otx_scan_url(d):

	otx = OTX()
	return otx.scan_url(d)

otx_scan_url.id = 'OTX Scan URL'

def otx_scan_hash(d):

	otx = OTX()
	return otx_scan_hash(d)

otx_scan_hash.id = 'OTX Scan Hash'

def otx_scan_file(d):

	otx = OTX()
	return otx.scan_file(d)

otx_scan_file.id = 'OTX Scan File'

def send_email(d):

	sg = SendGrid()
	return sg.send_email(d)

send_email.id = 'Send Email'

def shodan_lookup_host(d):

	s = Shodan()
	return s.lookup_host(d)

shodan_lookup_host.id = 'Shodan Lookup Host'

def send_text(d):

	t = Twilio()
	return t.send_text(d)

send_text.id = 'Send Text'

def make_call(d):

	t = Twilio()
	return t.make_call(d)

make_call.id = 'Make Call'

def vt_get_hash_report(d):

	vt = VirusTotal()
	return vt.get_hash_report(d)

vt_get_hash_report.id = 'VT Get Hash Report'

def vt_scan_and_report(d):

	vt = VirusTotal()
	return vt.scan_and_report(d)

vt_scan_and_report.id = 'VT Scan and Report'

def vt_get_domain_report(d):

	vt = VirusTotal()
	return vt.get_domain_report(d)

vt_get_domain_report.id = 'VT Get Domain Report'

def vt_get_ip_report(d):

	vt = VirusTotal()
	return vt.get_ip_report(d)

vt_get_ip_report.id = 'VT Get IP Report'

def ha_search_hashes(d):

	ha = HybridAnalysis()
	return ha.search_hashes(d)

ha_search_hashes.id = 'HybridAnalysis Search Hashes'

def ha_search_database(d):

	ha = HybridAnalysis()
	return ha.search_database(d)

ha_search_database.id = 'HybridAnalysis Search Database'

def ha_overview(d):

	ha = HybridAnalysis()
	return ha.overview(d)

ha_overview.id = 'HybridAnalysis Overview'

def ha_quickscan_file_with_overview(d):

	ha = HybridAnalysis()
	return ha.quickscan_file_with_overview(d)

ha_quickscan_file_with_overview.id = 'HybridAnalysis QuickScan File with Overview'

def ha_quickscan_file(d):

	ha = HybridAnalysis()
	return ha.quickscan_file(d)

ha_quickscan_file.id = 'HybridAnalysis QuickScan File'

def ha_convert_quickscan_to_sandbox(d):

	ha = HybridAnalysis()
	return ha.convert_quickscan_to_sandbox(d)

ha_convert_quickscan_to_sandbox.id = 'HybridAnalysis Convert QuickScan to Sandbox'

def ha_quickscan_url(d):

	ha = HybridAnalysis()
	return ha.quickscan_url(d)

ha_quickscan_url.id = 'HybridAnalysis QuickScan URL'

def ha_quickscan_url_with_overview(d):

	ha = HybridAnalysis()
	return ha.quickscan_url_with_overview(d)

ha_quickscan_url_with_overview.id = 'HybridAnalysis QuickScan URL with Overview'

def ha_submit_file(d):

	ha = HybridAnalysis()
	return ha.submit_file(d)

ha_submit_file.id = 'HybridAnalysis Submit File'

def ha_sandbox_reports(d):

	ha = HybridAnalysis()
	return ha.sandbox_reports(d)

ha_sandbox_reports.id = 'HybridAnalysis Sandbox Reports'
