from appintegration import AppIntegration
import requests

class Okta(AppIntegration):
    def __init__(self):
        AppIntegration.__init__(self)
        self.api_key = self.secrets['okta']['api_key']
        self.url = self.secrets['okta']['url']

    def list_users(self, d):
        """Lists all Okta users, regardless of status. Dictionary D
        can be empty."""

        # eg, https://dev-720070.oktapreview.com/api/v1/users/
        users_endpoint = "%s/api/v1/users/" % self.url

        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "SSWS %s" % self.api_key
        }

        return requests.get(users_endpoint, headers=headers).json()

    def suspend_user(self, d):
        """Dictionary D has a required key, `user_id`, the email address
        of user to suspend. User must be ACTIVE."""

        try:
            user_id = d['user_id']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key user_id is required'} 

        suspend_endpoint = "%s/api/v1/users/%s/lifecycle/suspend/" % (self.url, user_id)
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "SSWS %s" % self.api_key
        }
        
        # We don't check that user is ACTIVE. We delegate that to Okta's API
        return requests.post(suspend_endpoint, headers=headers).json()

    def unsuspend_user(self, d):
        """Dictionary D has a required key, `user_id`, the email address
        of user to unsuspend. User must be UNSUSPENDED."""
        try:
            user_id = d['user_id']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key user_id is required'} 

        unsuspend_endpoint = "%s/api/v1/users/%s/lifecycle/unsuspend/" % (self.url, user_id)
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "SSWS %s" % self.api_key
        }
        
        # We don't check that user is SUSPENDED. We delegate that to Okta's API
        return requests.post(unsuspend_endpoint, headers=headers).json()

    def expire_password(self, d):
        """Dictionary D has a required key, `user_id`, the email address
        of user to force to reset their password."""

        try:
            user_id = d['user_id']
        except KeyError:
            return { 'status': 'Error', 'error_message': 'Key user_id is required'} 

        expire_password_endpoint = "%s/api/v1/users/%s/lifecycle/expire_password/" % (self.url, user_id)
        headers = {
            'accept': "application/json",
            'content-type': "application/json",
            'authorization': "SSWS %s" % self.api_key
        }
        
        return requests.post(expire_password_endpoint, headers=headers).json()