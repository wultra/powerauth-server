# Migration from 1.10.x to 2.0.0

### Updated Package Names

Package names in Java code have been updated from historical `io.getlime` to `com.wultra`. Please update package imports in your source code which uses any `io.getlime` packages from PowerAuth server.

### Updated Validations in REST API

We have unified validations in PowerAuth server REST API. The error code returned for failed request validations is always `ERR0024`. As a side effect, the error code `ERR0002` used for case when no application ID was set in request is no longer returned.

The validation of requests is now stricter and more complete to ensure data integrity. In case you get the `ERR0024` error in your integration with PowerAuth server, please make sure the requests contain all parameters, as seen in REST API documentation available at `http[s]://[hostname]:[port]/powerauth-java-server/swagger-ui/index.html`.
