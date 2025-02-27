# Migration from 1.10.x to 2.0.0

### Updated Package Names

Package names in Java code have been updated from historical `io.getlime` to `com.wultra`. Please update package imports in your source code which uses any `io.getlime` packages from PowerAuth server.

### Updated Validations in REST API

We have unified validations in PowerAuth server REST API. The error code returned for failed request validations is always `ERR0024`. As a side effect, the error code `ERR0002` used for case when no application ID was set in request is no longer returned.

The validation of requests is now stricter and more complete to ensure data integrity. In case you get the `ERR0024` error in your integration with PowerAuth server, please make sure the requests contain all parameters, as seen in REST API documentation available at `http[s]://[hostname]:[port]/powerauth-java-server/swagger-ui/index.html`.

### Removed Recovery Code Functionality

The recovery code feature has been removed from the REST API and services due to its insufficient protection against social engineering attacks.

Following error codes are no longer used:

| Error Code | Error Message                                                                                                      | Note |
|------------|--------------------------------------------------------------------------------------------------------------------|------|
| ERR0025    | Recovery code already exists.                                                                                      | Could not generate recovery code because a valid recovery code already exists. |
| ERR0026    | Too many failed attempts to generate recovery code.                                                                | In order to uniquely identify a recovery code, a random recovery code (4x5 characters in Base32 encoding) is generated. In a very unlikely case of a collision, server attempts to generate a new one, at most 10 times. When the new recovery code generation fails 10 times, this error is returned. |
| ERR0027    | Recovery code was not found.                                                                                       | An action was attempted on a recovery code which does not exist. |
| ERR0028    | Invalid recovery code.                                                                                             | Used combination of recovery code and PUK is invalid. |
| ERR0029    | Invalid recovery configuration.                                                                                    | Recovery code configuration is missing or incomplete. |
