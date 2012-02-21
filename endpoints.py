# Google's OAuth 2.0 endpoints
AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/auth"
TOKEN_ENDPOINT = "https://accounts.google.com/o/oauth2/token"
TOKENINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v1/tokeninfo"
USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v1/userinfo'
SCOPE = "https://www.googleapis.com/auth/userinfo.email " \
        "https://www.googleapis.com/auth/userinfo.profile"

# client's callback
CALLBACK_URL = "/oauth2callback"

# params
PARAMS = "access_type=offline"