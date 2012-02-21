""" Sample OpenID Connect Client """
import os

from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from oauth2client.client import flow_from_clientsecrets
from gaesessions import get_current_session

import logging
import endpoints
from account import Account
from openidconnect.client import OpenIDConnectFlow

CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secrets.json')


OAUTH_FLOW = flow_from_clientsecrets(CLIENT_SECRETS,
    scope='https://www.googleapis.com/auth/userinfo.profile '\
          'https://www.googleapis.com/auth/userinfo.email')


IDP_FLOW = OpenIDConnectFlow(client_id=OAUTH_FLOW.client_id,
    client_secret=OAUTH_FLOW.client_secret,
    user_agent=OAUTH_FLOW.user_agent,
    scope=OAUTH_FLOW.scope,
    auth_uri=OAUTH_FLOW.auth_uri,
    token_uri=OAUTH_FLOW.token_uri,
    access_type='offline')


def get_target_url(request):
    """Private method - returns the redirect URL for display on web page."""

    callback = request.host_url + endpoints.CALLBACK_URL
    return IDP_FLOW.step1_get_authorize_url(callback)


def get_current_account():
    """Private method - get account for currently logged in user."""

    session = get_current_session()
    if 'user_id' in session:
        return Account.get_by_key_name(session['user_id'])


def get_params(request):
    """Get params for display on the web page."""

    return {
        'targetUrl': get_target_url(request),
        'client_id': IDP_FLOW.client_id,
        'client_secret': '*********',
        'user_agent': IDP_FLOW.user_agent,
        'scope':endpoints.SCOPE,
        'auth_uri': endpoints.AUTH_ENDPOINT,
        'token_uri': endpoints.TOKEN_ENDPOINT,
        'tokeninfo_uri': endpoints.TOKENINFO_ENDPOINT,
        'userinfo_uri': endpoints.USERINFO_ENDPOINT,
        'params': endpoints.PARAMS
    }


class SignInHandler(webapp.RequestHandler):

    def get(self):
        """ Start the OpenID Connect flow."""

        callback = self.request.host_url + endpoints.CALLBACK_URL
        authorize_url = IDP_FLOW.step1_get_authorize_url(callback)
        self.redirect(authorize_url)


class MainHandler(webapp.RequestHandler):

    def get(self):
        """Start with STEP 0."""
        self.redirect('/step/0')


class CallbackHandler(webapp.RequestHandler):

    def get(self):
        """Handles OpenID Connect flow once user redirected back."""

        session = get_current_session()
        session.regenerate_id()
        session['response_with_code'] = self.request.path_url\
                                        + '?' + self.request.query_string

        # Perform steps 2, 3, and 4
        # 1) Exchange authorization code for access token
        # 2) Verify obtained access token
        # 3) Use access token to obtained user info
        openidconnect_credentials =\
        IDP_FLOW.step234_exchange_and_tokeninfo_and_userinfo(
            self.request.params)

        # Log in the user
        session['a_t'] = openidconnect_credentials.access_token
        session['user_id'] = openidconnect_credentials.userinfo.id
        session['token_info'] = openidconnect_credentials.tokeninfo
        session['user_info'] = openidconnect_credentials.userinfo

        userinfo = openidconnect_credentials.userinfo
        user_id =  openidconnect_credentials.userinfo.id

        # not happy with this, but not sure what else is available
        acct = Account(key_name=user_id,
            name=userinfo.name if 'name' in userinfo else None,
            user_info=userinfo.to_json(),
            family_name=userinfo.family_name if
            'family_name' in userinfo else None,
            locale=userinfo.locale if
            'locale' in userinfo else None,
            gender=userinfo.gender if
            'gender' in userinfo else None,
            email=userinfo.email if 'email' in userinfo else None,
            given_name=userinfo.given_name if
            'given_name' in userinfo else None,
            google_account_id=user_id if
            'id' in userinfo else None,
            verified_email=userinfo.verified_email if
            'verified_email' in userinfo else None,
            link=userinfo.link if
            'link' in userinfo else None,
            picture=userinfo.picture if
            'picture' in userinfo else None)

        # store the account within the DB
        acct.access_token = openidconnect_credentials.access_token
        acct.put()

        # redirect the user to the main page
        self.redirect('/')


class StepHandler(webapp.RequestHandler):
    def get(self, stepNum):
        if int(stepNum) > 4 or int(stepNum) < 0:
            self.error(400)
            return

        session = get_current_session()

        templateInfo = {
            'targetUrl': get_target_url(self.request),
            'session': session,
            'params': get_params(self.request),
            'stepNum': stepNum,
            'account':get_current_account(),
            'template_name':
                'step%s.html' % stepNum
        }

        self.response.out.write(
            template.render('templates/stepTemplate.html',
                templateInfo))


class LogoutHandler(webapp.RequestHandler):

    def get(self):
        """Logout the user from the application."""

        session = get_current_session()
        logging.info('Session: %s' % session)
        session.terminate()
        self.redirect('/')


class LogoutAndRemoveHandler(webapp.RequestHandler):

    def get(self):
        """Logout the user and remove their account."""

        session = get_current_session()
        logging.info('Session: %s' % session)
        user_id = session['user_id']
        account = Account.get_by_key_name(user_id)
        session.terminate()
        account.delete()
        self.redirect('/') 
