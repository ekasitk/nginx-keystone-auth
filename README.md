
To run 
```shell
export OS_AUTH_URL=https://localhost:5000/v3
export OS_PROJECT_NAME=demo
./nginx-keystone-auth.py
```

It requires nginx auth_request module.

```
    location .... {

        auth_request /auth;
        error_page 401 =200 /login;

        ...

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
