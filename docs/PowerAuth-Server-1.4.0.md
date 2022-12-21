# Migration from 1.3.x to 1.4.0

This guide contains instructions for migration from PowerAuth Server version `1.3.x` to version `1.4.0`.

## Change in PowerAuth Token Verification

In earlier versions of PowerAuth Server, the token verification endpoint `/rest/v3/token/validate` returned an error in case the activation used by the token was not active. In order to always return activation status as part of the response, we changed the endpoint behaviour and removed the error handling for inactive activations. This change unifies the business logic with signature verification endpoint.

Before change:

```java
try {
    final ValidateTokenResponse response = powerauthClient.validateToken(request);
    // regular business logic
} catch (PowerAuthClientException ex) {
    // error handling for inactive activation and all other errors
}
```

After change:
```java
try {
    final ValidateTokenResponse response = powerauthClient.validateToken(request);
    if (response.getActivationStatus() != ActivationStatus.ACTIVE) {
        // error handling for inactive activations
    }
} catch (PowerAuthClientException ex) {
    // error handling for all other errors
}
```

Adaptation to this change is required only in case this endpoint is called directly on PowerAuth server. In case you use the `@PowerAuthToken` annotation for token validation, no changes are required.

## Database Changes

### Add Risk Flags to Operations and Templates

Add a column `risk_flags` to the templates and operations.

#### PostgreSQL

```sql
ALTER TABLE pa_operation
    ADD COLUMN risk_flags VARCHAR(255);

ALTER TABLE pa_operation_template
    ADD COLUMN risk_flags VARCHAR(255);
```

#### Oracle

```sql
ALTER TABLE pa_operation
    ADD risk_flags VARCHAR2(255 CHAR);

ALTER TABLE pa_operation_template
    ADD risk_flags VARCHAR2(255 CHAR);
```

#### MySQL

```sql
ALTER TABLE pa_operation
    ADD COLUMN risk_flags varchar(255);

ALTER TABLE pa_operation_template
    ADD COLUMN risk_flags varchar(255);
```

### Added Database Indexes

```sql
CREATE INDEX pa_activation_expiration on pa_activation (activation_status, timestamp_activation_expire);
CREATE INDEX pa_operation_status_exp_idx ON pa_operation(timestamp_expires, status);
```
