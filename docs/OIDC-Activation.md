# OpenID Connect (OIDC) Activation

PowerAuth protocol allows activation using OpenID Connect (OIDC) protocol.


## OIDC Activation Configuration

To enable OIDC activation, an entry with the key `oauth2_providers` must exist in the table `pa_application_config`.
Mind that this table supports encryption.


### Required Configuration

- `providerId` - Identification of the configuration record, used as a key for the configuration, known by the mobile application.
- `clientId` - The client identifier.
- `clientSecret` - The client secret.
- `issuerUri` - URI for the OpenID Connect 1.0 provider or the OAuth 2.0 Authorization Server; when `/.well-known/openid-configuration` endpoint exposed, other optional URI parameters are configured based on the response.
- `redirectUri` - URI for the redirection endpoint.


### Optional Configuration

- `clientAuthenticationMethod` - If empty, `client_secret_basic` is used.
- `authorizeUri` - URI for the authorization endpoint.
- `tokenUri` - URI for the token endpoint.
- `jwkSetUri` - URI for the JSON Web Key (JWK).
- `scopes` - Scope(s) used for the client.
- `pkceEnabled` - A hint for the mobile application whether to use Authorization Code Flow with Proof Key for Code Exchange (PKCE). If set to `true`, `codeVerifier` must be present in identity attributes during create activation step.
- `signatureAlgorithm` - If empty, `RS256` is used.


### Example

The value of `config_values` column may look like this:

```json
[
  {
    "providerId": "example",
    "scopes": "openid",
    "clientSecret": "top secret",
    "clientId": "client ID",
    "issuerUri": "https://issuer.example.com/",
    "redirectUri": "mtoken://oidc"
  }
]
```
