## An Oaut2 server should supports for
> Type Of
  - Authorization Code
  - Authorization Code w/ PKCE(Proof Key for Code Exchange) work with like single page apps & mobile apps
  - Resource Owner
  - Client Credentials

> [!Note]
> A Authorization Server/provide should suport for all, but some server supports few of them as well, Get the [OAuth2 Server Meta-data](https://datatracker.ietf.org/doc/html/rfc8414) ,
> 
RFC-8414 — OAuth 2.0 Authorization Server Metadata, send get request `curl -X GET http://localhost:9000/.well-known/oauth-authorization-server` 
Here we'll get the response as json about Authrization server supports, falow the below
```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/oauth2/authorize",
  "device_authorization_endpoint": "http://localhost:9000/oauth2/device_authorization",
  "token_endpoint": "http://localhost:9000/oauth2/token",
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth"
  ],
  "jwks_uri": "http://localhost:9000/oauth2/jwks",
  "response_types_supported": [
    "code"
  ],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "revocation_endpoint": "http://localhost:9000/oauth2/revoke",
  "revocation_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth"
  ],
  "introspection_endpoint": "http://localhost:9000/oauth2/introspect",
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ],
  "tls_client_certificate_bound_access_tokens": true
}
```
From this response, we can see that both authorization endpoint and token endpoint are readily available.

## What Spring-OAuth2 authorization server provide 

We have to figure out the core components or interfaces that need concrete implementations. Here’s the official getting started video guide: [OFFICIAL_VIDEO](https://youtu.be/ZIjqDIdFyBw) 

> Anyway, here are the main components:
  - OAuth2AuthorizationServerConfiguration
  - ProviderSettings
  - JWKSource
  - RegisteredClientRepository
  - OAuth2AuthorizationService
  - OAuth2AuthorizationConsentService

Combine whole thing implementation has done just run the source code and
## Falow the steps

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
