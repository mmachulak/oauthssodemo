#!/usr/bin/env python

# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" OpenID Connect Client """

import logging
import urllib
from error import FlowUserInfoError
from error import FlowTokenInfoError
from tokeninfo import TokenInfo
from userinfo import UserInfo

from apiclient.anyjson import simplejson
import httplib2
from oauth2client.client import OAuth2WebServerFlow, OAuth2Credentials
from oauth2client.client import flow_from_clientsecrets

__author__ = "Maciej Machulak"
__maintainer__ = "Maciej Machulak"
__email__ = "mmachulak@google.com"

__copyright__ = "Copyright 2012 Google Inc. All Rights Reserved."
__license__ = "Apache License 2.0"
__version__ = "0.1"
__status__ = "Prototype"


GOOGLE_OPENIDCONNECT_SCOPE = "https://www.googleapis.com/auth/userinfo.profile"
GOOGLE_TOKENINFO_URI = "https://www.googleapis.com/oauth2/v1/tokeninfo"
GOOGLE_USERINFO_URI = "https://www.googleapis.com/oauth2/v1/userinfo"


def openidconnect_flow_from_clientsecrets(filename, scope = GOOGLE_OPENIDCONNECT_SCOPE, message=None):
  """Create OpenID Connect Flow from a clientsecrets file.

  Will create the right kind of Flow based on the contents of the clientsecrets
  file or will raise InvalidClientSecretsError for unknown types of Flows.

  Args:
    filename: string, File name of client secrets.
    scope: string or list of strings, scope(s) to request.
    message: string, A friendly string to display to the user if the
      clientsecrets file is missing or invalid. If message is provided then
      sys.exit will be called in the case of an error. If message in not
      provided then clientsecrets.InvalidClientSecretsError will be raised.

  Returns:
    A Flow object.

  Raises:
    UnknownClientSecretsFlowError if the file describes an unknown kind of Flow.
    clientsecrets.InvalidClientSecretsError if the clientsecrets file is
      invalid.
  """

  # Check if submitted scope contains the Ope
  oauth_flow = flow_from_clientsecrets(filename,scope,message)
  return OpenIDConnectFlow(client_id = oauth_flow.client_id,
      client_secret = oauth_flow.client_secret,
      scope = oauth_flow.scope,
      user_agent = oauth_flow.user_agent,
      auth_uri = oauth_flow.auth_uri,
      token_uri = oauth_flow.token_uri)


class VerifiedTokenCredentials(OAuth2Credentials):
    """Credentials verified with the TokenInfo endpoint."""

    def __init__(self, oauth_credentials, tokeninfo):
        OAuth2Credentials.__init__(self,
            oauth_credentials.access_token,
            oauth_credentials.client_id,
            oauth_credentials.client_secret,
            oauth_credentials.refresh_token,
            oauth_credentials.token_expiry,
            oauth_credentials.token_uri,
            oauth_credentials.user_agent,
            oauth_credentials.id_token)

        self.tokeninfo = tokeninfo

class OpenIDConnectCredentials(VerifiedTokenCredentials):
    """OpenID Connect Credentials received from the UserInfo endpoint."""

    def __init__(self, verified_token_credentials, userinfo):
        VerifiedTokenCredentials.__init__(self,
            verified_token_credentials,
            verified_token_credentials.tokeninfo)

        self.userinfo = userinfo


class OpenIDConnectFlow(OAuth2WebServerFlow):
    """Does the OpenID Connect flow."""

    def __init__(self,
                 scope=GOOGLE_OPENIDCONNECT_SCOPE,
                 tokeninfo_uri=GOOGLE_TOKENINFO_URI,
                 userinfo_uri=GOOGLE_USERINFO_URI,
                 **kwargs):
        """Constructor for OpenIDConnectFlow.

        Args:
          tokeninfo_uri: string, URI for TokenInfo endpoint. For convenience
            defaults to Google's endpoints but any OAuth 2.0 provider can be
            used.
          userinfo_uri: string, URI for UserInfo endpoint. For convenience
            defaults to Google's endpoints but any OAuth 2.0 provider can be
            used.
          **kwargs: dict, The keyword arguments require the following parameters
                          - client_id: string, client identifier.
                          - client_secret: string client secret.
                          - scope: string or list of strings, scope(s) of the
                          credentials being requested.
                          - user_agent: string, HTTP User-Agent to provide for
                          this application.
                          - auth_uri: string, URI for authorization endpoint.
                          For convenience defaults to Google's endpoints but
                          any OAuth 2.0 provider can be used.
                          - token_uri: string, URI for token endpoint. For
                          conveniencedefaults to Google's endpoints but
                          any OAuth 2.0 provider can be used
                          - any other optional parameters for OAuth 2.0
        """

        super(OpenIDConnectFlow, self).__init__(scope = scope, **kwargs)

        self.tokeninfo_uri = tokeninfo_uri
        self.userinfo_uri = userinfo_uri

    def step3_verify_access_token(self, credentials, http=None):
        """Verifies access token at the TokenInfo endpoint.

        Args:
            credentials

        Returns:
            VerifiedTokenCredentials

        Raises:
            FlowTokenInfoError
        """

        if http is None:
            http = httplib2.Http()

        resp, content = http.request(self.tokeninfo_uri,
            method="POST",
            body=urllib.urlencode({'access_token': credentials.access_token}),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if resp.status == 200:
            # Process the response
            d = simplejson.loads(content)
            tokeninfo = TokenInfo(d)
            logging.debug('Successfully retrieved token info: %s' % tokeninfo)
            verified_token_credentials = VerifiedTokenCredentials(credentials,
                tokeninfo)

            # Perform checks on the token info
            if verified_token_credentials.tokeninfo.audience \
            != credentials.client_id:
                logging.error('token issued for a different client ' \
                              '- issued to %s, '
                              'expected %s.' %
                    (verified_token_credentials.tokeninfo.audience,
                     credentials.client_id))
                raise FlowTokenInfoError('invalid token')

            if int(verified_token_credentials.tokeninfo.expires_in) < 1:
                logging.error('token expired')
                raise FlowTokenInfoError('token expired')

            return verified_token_credentials
        else:
            logging.error('Failed to retrieve token info: %s' % content)
            error_msg = 'Invalid token info response %s.' % resp['status']
            try:
                data = simplejson.loads(content)
                if 'error' in data:
                    error_msg = data['error']
            except Exception:
                pass

            raise FlowTokenInfoError(error_msg)

    def step4_userinfo(self, credentials, http=None):
        """Obtains UserInfo from the UserInfo endpoint.

        Args:
            credentials

        Returns:
            OpenIDConnectCredentials

        Raises:
            FlowUserInfoError
        """

        if http is None:
            http = httplib2.Http()

        http = credentials.authorize(http)
        resp, content = http.request(self.userinfo_uri)

        if resp.status == 200:
            d = simplejson.loads(content)
            userinfo = UserInfo(d)
            logging.debug('Successfully retrieved user info: %s' % userinfo)
            return OpenIDConnectCredentials(credentials, userinfo)
        else:
            logging.error('Failed to retrieve user info: %s' % content)
            error_msg = 'Invalid user info response %s.' % resp['status']
            try:
                data = simplejson.loads(content)
                if 'error' in data:
                    error_msg = data['error']
            except Exception:
                pass

            raise FlowUserInfoError(error_msg)

    def step234_exchange_and_tokeninfo_and_userinfo(self, code, http=None):
        """Exchanges authorization for token, then validates the token and
        obtains UserInfo.

        Args:
            code

        Returns:
            OpenIDConnectCredentials

        Raises:
            FlowUserInfoError
        """

        if http is None:
            http = httplib2.Http()

        logging.debug('exchanging code for access token')
        credentials = self.step2_exchange(code, http)
        logging.debug('verifing access token received from the IDP')
        credentials = self.step3_verify_access_token(credentials, http)
        logging.debug('using access token to access user info from the IDP')
        return self.step4_userinfo(credentials, http)
