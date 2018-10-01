from appintegration import AppIntegration
from piplapis.search import SearchAPIRequest, SearchAPIError

class PiplIntegration(AppIntegration):
    def look_up_person(self, d):
        """
        Takes in an non-empty dictionary D with optional keys:
        
        `phone` (string) - eg, 4087180840
        `first_name` (string)
        `middle_name` (string)
        `last_name` (string)
        `age` (number)
        `email` (string)
        `city` (string)
        `zipcode` (string)
        """

        # TODO: don't hard-code
        API_KEY = "shuii49shqc56hzfhj7lwu79"

        # error if D is empty
        if not d:
            return { 'error': 'true', 'error_message': 'Inputs cannot be empty'} 
        
        request = SearchAPIRequest(**d, api_key=API_KEY)
        try:
            response = request.send()
        except SearchAPIError as e:
            return { 'error': 'true', 'message': 'Call to Pipl Search API failed' }

        # PROBLEM: response is pre-parsed into objects, but we want
        # the raw JSON

        # PROBLEM: our api key will expire if our account isn't verified.
        # also if we don't add a billing account
        