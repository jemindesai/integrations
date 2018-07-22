from appintegration import *
import geoip2.webservice

class MaxMind(AppIntegration):

	def __init__(self):
		AppIntegration.__init__(self)
		self.license_key = self.secrets['max_mind']['license_key']
		self.account_id = self.secrets['max_mind']['account_id']
		self.client = geoip2.webservice.Client(self.account_id, self.license_key)

	def lookup_geoip(self, d):
		"""
		Takes a dict D with key IP (as a string) and returns
		a response dictionary.
		"""
		insight = self.client.insights(d['ip'])
		response = {}

		#Create variables for each instance variable of INSIGHT
		city = insight.city
		continent = insight.continent
		country = insight.country
		location = insight.location
		registered_country = insight.registered_country
		represented_country = insight.represented_country
		subdivisions = insight.subdivisions
		traits = insight.traits

		#Create a dictionary with all CITY information
		response['City'] = {}
		city_d = response['City']

		city_d['Confidence'] = city.confidence
		city_d['Geoname ID'] = city.geoname_id
		city_d['Name'] = city.name

		#Create a dictionary with all CONTINENT information
		response['Continent'] = {}
		continent_d = response['Continent']

		continent_d['Code'] = continent.code
		continent_d['Geoname ID'] = continent.geoname_id
		continent_d['Name'] = continent.name

		#Create a dictionary with all COUNTRY information
		response['Country'] = {}
		country_d = response['Country']

		country_d['Confidence'] = country.confidence
		country_d['Geoname ID'] = country.geoname_id
		country_d['Is in EU?'] = country.is_in_european_union
		country_d['ISO Code'] = country.iso_code
		country_d['Name'] = country.name

		#Create a dictionary with all LOCATION information
		response['Location'] = {}
		location_d = response['Location']

		location_d['Average Income'] = location.average_income
		location_d['67% Confidence Location Radius (km)'] = location.accuracy_radius
		location_d['Latitude'] = location.latitude
		location_d['Longitude'] = location.longitude
		location_d['Metro Code'] = location.metro_code
		location_d['Population Density'] = location.population_density
		location_d['Time Zone'] = location.time_zone

		#Create a dictionary with all ISP REGISTERED COUNTRY information
		response['ISP Registered Country'] = {}
		reg_country_d = response['ISP Registered Country']

		reg_country_d['Confidence'] = registered_country.confidence
		reg_country_d['Geoname ID'] = registered_country.geoname_id
		reg_country_d['Is in EU?'] = registered_country.is_in_european_union
		reg_country_d['ISO Code'] = registered_country.iso_code
		reg_country_d['Name'] = registered_country.name

		#Create a dictionary with all REPRESENTED COUNTRY information
		response['Country Represented by Users of IP Address'] = {}
		rep_country_d = response['Country Represented by Users of IP Address']

		rep_country_d['Confidence'] = represented_country.confidence
		rep_country_d['Geoname ID'] = represented_country.geoname_id
		rep_country_d['Is in EU?'] = represented_country.is_in_european_union
		rep_country_d['ISO Code'] = represented_country.iso_code
		rep_country_d['Name'] = represented_country.name
		rep_country_d['Type'] = represented_country.type

		#Find most specific SUBDIVISION
		subdivision = subdivisions.most_specific

		#Create a dictionary with all MOST SPECIFIC SUBDIVISION information
		response['Most Specific Subdivision'] = {}
		subdivision_d = response['Most Specific Subdivision']

		subdivision_d['Confidence'] = subdivision.confidence
		subdivision_d['Geoname ID'] = subdivision.geoname_id
		subdivision_d['ISO Code'] = subdivision.iso_code
		subdivision_d['Name'] = subdivision.name

		#Create a dictionary with all TRAITS information
		response['Traits'] = {}
		traits_d = response['Traits']

		traits_d['Autonomous System Number'] = traits.autonomous_system_number
		traits_d['Autonomous System Organization'] = traits.autonomous_system_organization
		traits_d['Connection Type'] = traits.connection_type
		traits_d['Domain'] = traits.domain
		traits_d['IP Address'] = traits.ip_address
		traits_d['Is Anonymous?'] = traits.is_anonymous
		traits_d['Is Anonymous VPN?'] = traits.is_anonymous_vpn
		traits_d['Is Hosting Provider?'] = traits.is_hosting_provider
		traits_d['Is Legitimate Proxy?'] = traits.is_legitimate_proxy
		traits_d['Is Public Proxy?'] = traits.is_public_proxy
		traits_d['Is Satellite Provider?'] = traits.is_satellite_provider
		traits_d['Is Tor Exit Node?'] = traits.is_tor_exit_node
		traits_d['ISP'] = traits.isp
		traits_d['Organization'] = traits.organization
		traits_d['User Type'] = traits.user_type

		return response