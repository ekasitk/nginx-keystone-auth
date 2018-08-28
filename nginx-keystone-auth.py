# Keystone authentication server working on port 9000
# 1) accepts GET /login and responds with a login form
#    curl -i -H "X-Target: /abc" http://localhost:9000/login
# 2) accepts POST /login, sets a cookie, and responds with redirect
#    curl -i  -X POST -d "username=test&password=1234&target=/abc" http://localhost:9000/login
# 3) accepts GET /auth to check if the cookie is valid
# 4) accepts GET /logout to delete and force cookie expired

import sys, os, signal, base64, Cookie, cgi, urlparse, requests, json

Listen = ('localhost', 9000)  # Use localhost to restrict only 127.0.0.1

auth_url = os.environ.get('OS_AUTH_URL') # e.g. "https://localhost:5000/v3"
project_name = os.environ.get('OS_PROJECT_NAME') 


session_timeout = 1800       # Live time of each cookie (seconds)
cookie_name = "nginxauth"

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
import dateutil.parser

import logging
logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
                    stream=sys.stderr)
logger = logging.getLogger(__name__)

# Disable insecure certificate verification warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import hashlib, random, string
key_length = 20 
random_key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(key_length))

import threading
from SocketServer import ThreadingMixIn
class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class AppHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        url = urlparse.urlparse(self.path)

        if url.path.startswith("/login"):
            return self.auth_form()
        elif url.path.startswith("/auth"):
            return self.auth_handler()
        elif url.path.startswith("/logout"):
            return self.auth_logout()

        self.send_response(200)
        self.end_headers()
        self.wfile.write('Hello, world! Requested URL: ' + self.path + '\n')


    # send login form html
    def auth_form(self, target = None, message = ''):

        # try to get target location from header
        if target == None:
            target = self.headers.get('X-Target')

        # form cannot be generated if target is unknown
        if target == None:
            self.log_message('target url is not passed')
            self.send_response(500)
            return

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
    <title>Simple Auth form</title>
  </head>
  <body>
    %s
    <br/>
    Please enter username/password  
    <form action="/login" method="post">
      <table>
        <tr>
          <td>Username: <input type="text" name="username"/></td>
        <tr>
          <td>Password: <input type="password" name="password"/></td>
        <tr>
          <td><input type="submit" value="Login"></td>
      </table>
        <input type="hidden" name="target" value="TARGET">
    </form>
  </body>
</html>""" % message

        self.send_response(200)
        self.end_headers()
        self.wfile.write(html.replace('TARGET', target))

    def auth_logout(self):
        self.send_response(200)

        cookies = Cookie.SimpleCookie()
        cookies[cookie_name] = "deleted"
        expires_at = datetime.fromtimestamp(0)   # Jan 1, 1970
        cookies[cookie_name]['expires'] = expires_at.strftime('%a, %d %b %Y %H:%M:%S') # No expires = cookie removed after browser has been closed
        logger.debug("Cookie %s " % cookies.output())
 
        for key, morsel in cookies.iteritems():
            self.send_header('Set-Cookie', morsel.OutputString())

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
  </head>
  <body>
You have been logout. 
New connections cannot be made but close the browser to destroy existing connections.
  </body>
</html>"""

        self.end_headers()
        self.wfile.write(html)

    # processes posted form and sets the cookie with login/password
    def do_POST(self):

        # prepare arguments for cgi module to read posted form
        env = {'REQUEST_METHOD':'POST',
               'CONTENT_TYPE': self.headers['Content-Type'],}

        # read the form contents
        form = cgi.FieldStorage(fp = self.rfile, headers = self.headers,
                                environ = env)

        # extract required fields
        username = form.getvalue('username')
        password = form.getvalue('password')
        target = form.getvalue('target')

        if username is None or password is None or target is None:
            message = 'some form fields are not provided'
            self.log_error(message)
            self.auth_form(target, message)
            return

        # form is filled, set the cookie and redirect to target
        # so that auth daemon will be able to use information from cookie

        val = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "domain": { "id": "default" },
                            "password": password
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": project_name,
                        "domain": { "id": "default" }
                    }
                }
            }
        }

        try:
            headers = {'Content-Type': 'application/json'}
            resp = requests.post(auth_url, data=json.dumps(val), headers=headers, verify=False) # Do not verify certificate

            if (resp.status_code != 201):
                logger.info("Keystone responses %d" % resp.status_code)
                if (resp.status_code == 401):
                   message = 'User %s not authorized' % username
                   logger.info(message)
                   self.auth_form(target, message)
                   return
                else:
                   self.send_response(500)
                   return

            #print resp.content
            #cred = resp.json()
            #expire_at = dateutil.parser.parse(cred['token']['expires_at'])

        except Exception as ex:
            self.log_error(str(ex))
            self.send_response(500)
            return

        logger.info("User %s is authenticated" % username)

        self.send_response(302)

        expires_at = (datetime.now() + timedelta(seconds=session_timeout)).replace(microsecond=0)
        expires = expires_at.isoformat()
        digest = hashlib.sha256(username + expires + random_key).hexdigest()

        enc = base64.b64encode(username + "|" + expires + "|" + digest)
        cookies = Cookie.SimpleCookie()
        cookies[cookie_name] = enc
        # Old browsers do not know max-age.
        #cookies[cookie_name]['max-age'] = 1800  # seconds
        #cookies[cookie_name]['expires'] = expires_at.strftime('%a, %d %b %Y %H:%M:%S') # No expires = cookie removed after browser has been closed
        cookies[cookie_name]['httponly'] = True
        logger.debug("Cookie %s " % cookies.output())
            
        for key, morsel in cookies.iteritems():
            self.send_header('Set-Cookie', morsel.OutputString())

        self.send_header('Location', target)
        self.end_headers()

        return


    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        sys.stdout.write("%s - - [%s] %s\n" % (addr,
                         self.log_date_time_string(), format % args))

    def auth_handler(self, target = None):
        # Check if cookie is still valid
        auth_cookie = self.get_cookie(cookie_name)
        if auth_cookie is None:
            self.log_message('No cookie found')
            self.send_response(401)
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()        
            return

        auth_decoded = base64.b64decode(auth_cookie)
        logger.debug("Cookie %s=%s", cookie_name, auth_cookie)
        username, expires, digest = auth_decoded.split('|')
        
        # Verify if cookie is valid
        if digest != hashlib.sha256(username + expires + random_key).hexdigest():
            self.log_message('Invalid cookie!!!')
            self.send_response(401)
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()        
            return

        logger.info('Check if cookie of user %s valid til %s' % (username, expires))
        expires_at = dateutil.parser.parse(expires) 
        if expires_at < datetime.now(): 
            self.log_message('Session of %s expired' % username)
            self.send_response(401)
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()        
            return

        self.send_response(200)
        self.end_headers()        

    def get_cookie(self, name):
        cookies = self.headers.get('Cookie')
        if cookies:
            cookie = Cookie.BaseCookie(cookies).get(name)
            if cookie:
                return cookie.value
            else:
                return None
        else:
            return None

    def get_keystone_auth_token(self, username, password):
        return None

def exit_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    if auth_url is None or project_name is None:
        logger.error('Cannot find OS_AUTH_URL or OS_PROJECT_NAME')
        exit(1)
    auth_url = auth_url + "/auth/tokens"
    server = AuthHTTPServer(Listen, AppHandler)
    signal.signal(signal.SIGINT, exit_handler)
    logger.info('Start listening on %s for %s and project %s' % (str(Listen), auth_url, project_name))
    server.serve_forever()

