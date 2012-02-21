import os
from gaesessions import SessionMiddleware

# Make webapp.template use django 1.2
webapp_django_version = '1.2'

def webapp_add_wsgi_middleware(app):
    app = SessionMiddleware(app, cookie_key='\x9eN\x9e\\\x91\xa5\x06\x9c\x96m\xcdNXDf\xa1\x99\x8c\xe5\x80\xcc\xa7:B\x86\xbb\xa5;3\xb9\xc9F\xaf\xbb\xffK\xf7\xeb\xaf\xcd"\xf1X\x9e\xaf)\x92hbG\xc3\xea\xc7\xd3\xf6-%\r\x01\xe4\x054rv')
    return app