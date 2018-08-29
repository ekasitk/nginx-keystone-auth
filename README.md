# nginx-keystone-auth

The nginx-keystone-auth allows other services to authenticate users with openstack keystone by nginx reverse proxy.

When a browser request a web page from backend service, nginx makes an internal HTTP subrequest to the nginx-keystone-auth daemon, which communicates with keystone to validate user credential.


![NGINX LDAP Architecture](https://cdn-1.wp.nginx.com/wp-content/uploads/2016/02/ldap-auth-components.jpg)


## Installation and Configuration

To install,

1. Install [nginx](https://www.nginx.com/), either community or commercial version. The nginx-keystone-auth requires **http_auth_request** module in nginx. The module is usually bundled in the pre-built package.

1. Check if keystone service is reachable from the proxy server. Replace _localhost_ with your host.
```shell
curl https://localhost:5000/v3
```

1. Clone the GitHub repository (**nginx-keystone-auth**) on the proxy server (can work on different server but it needs few configuration changes).
```shell
git clone https://github.com/ekasitk/nginx-keystone-auth.git
```

1. Change directory to nginx-keystone-auth home.
```shell
cd nginx-keystone-auth
```

1. Set environment variables. In this implementation, we restrict only users in a particular project to authenticate.
```shell
export OS_AUTH_URL=https://localhost:5000/v3
export OS_PROJECT_NAME=demo
```
1. Change nginx-keystone-auth.py for desired port and session timeout.
```python
Listen = ('localhost', 9000)  
session_timeout = 1800   
```

1. Run nginx-keystone-auth daemon.
```shell
nohup python nginx-keystone-auth.py 2>&1 &
```

1. Modify nginx configuration files. The following is a sample configuration. Modify it to suit your needs.
```java
server {
  listen 443 ssl;

  location / {

    auth_request /auth;
    error_page 401 =200 /login;

    proxy_pass http://backend:8080;

  }

  location /login {
    proxy_set_header X-Target $request_uri;
    proxy_pass http://localhost:9000;
  }

  location /logout {
    proxy_set_header X-Target $request_uri;
    proxy_pass http://localhost:9000;
  }

  location /auth {
    internal;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_pass http://localhost:9000;
  }
}
```
For any requests, the auth_request performs http subrequest authentication to /auth, which is proxied to the nginx-keystone-auth daemon. If the user is not authorized, browser is redirected to the login page. Once logged in, a authentication cookie is generated for the browser. Any subsequent requests will be authorized until the cookie expired.

1. Restart/reload nginx
```shell
sudo systemctl restart nginx
```

1. Test the installation. Use a web browser to access **https://proxy-server**. Verify that the browser presents a login form.

## Authentication Cookie Generation
An authenication cookie is named _nginxauth_ (configurable) and encoded in Base64.
```
nginxauth = username + '|' + expires_time + '|' + digest.
digest = sha256(username + expires_time + randomkey)
```
A session is timeout when the cookie expired or browser is closed. User can manually request **/logout** to force cookie deleted.
