# Falow the steps

send the request first as a `get` method and provide the usename and password

```
http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=oidc-client&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client&scope=openid profile
```
After getting the code send the `post` request with providing the addition information like 
```
http://127.0.0.1:9000/oauth2/token
```
> Use the postman for testing purpose 
> Select the basic auth and provide Username=oidc-client and password=secret (Here we are basically provides clientId and secrets)
> Then got to the body section and select `x-www-form-urlencoded` then provide bellow details as key and value
```
grant_type=authorization_code
code=INF83WnU3DNVf8QBrtmzh4p9n61YrpKnEDDbyy3JZZL9845T_KPn_YQ6A1-c7JNYSkoNpNlhRAnQ2-o6az9l5Q_UPcQ7_9HkT43WTICjjkkNX1lMEjBVhXjfpp6gCz1D (Here the generated code from the get request)
redirect_uri=http://127.0.0.1:8080/login/oauth2/code/oidc-client
```
then send the request then we will get (access_token, refresh_token, scope, id_token, token_type, expire_in)
