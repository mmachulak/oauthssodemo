from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
import endpoints

import index

def main():
    application = webapp.WSGIApplication([('/step/(?P<stepNum>\d{1})',
                                           index.StepHandler),
        (endpoints.CALLBACK_URL, index.CallbackHandler),
        ('/logout', index.LogoutHandler),
        ('/logoutandremove', index.LogoutAndRemoveHandler),
        ('/', index.MainHandler)],
        debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
