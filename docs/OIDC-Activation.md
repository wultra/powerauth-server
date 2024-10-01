# OpenID Connect (OIDC) Activation

PowerAuth protocol allows activation using OpenID Connect (OIDC) protocol.


## OIDC Activation Configuration

To enable OIDC activation, an entry with the key `oauth2_providers` must exist in the table `pa_application_config`.
Mind that this table supports encryption.

- `providerId` - (Required) Identification of the configuration record, used as a key for the configuration, known by the mobile application.
- `clientId` - (Required) The client identifier.
- `clientSecret` - (Required) The client secret.
- `issuerUri` - (Required) URI for the OpenID Connect 1.0 provider or the OAuth 2.0 Authorization Server; when `/.well-known/openid-configuration` endpoint exposed, other optional URI parameters are configured based on the response.
- `redirectUri` - (Required) URI for the redirection endpoint.
- `clientAuthenticationMethod` - (Optional) If empty, `client_secret_basic`.
- `authorizeUri` - (Optional) URI for the authorization endpoint.
- `tokenUri` - (Optional) URI for the token endpoint.
- `jwkSetUri` - (Optional) URI for the JSON Web Key (JWK).
- `scopes` - (Optional) Scope(s) used for the client-
- `pkceEnabled` - (Optional) A hint for the mobile application whether to use Authorization Code Flow with Proof Key for Code Exchange (PKCE). If set to `true`, `codeVerifier` must be present in identity attributes during create activation step.
- `signatureAlgorithm` - (Optional) If empty, `RS256` is used.


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
