# Migration from 1.4.x to 1.5.0

This guide contains instructions for migration from PowerAuth Server version `1.4.x` to version `1.5.0`.

## Spring Boot 3

The PowerAuth Server was upgraded to Spring Boot 3, Spring Framework 6, and Hibernate 6.
It requires Java 17 or newer.

Remove this property.

`spring.jpa.properties.hibernate.temp.use_jdbc_metadata_defaults=false`

Make sure that you use dialect without version.

```properties
# spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
# spring.jpa.database-platform=org.hibernate.dialect.OracleDialect
```

## Support for PowerAuth Protocol Version 3.2

This release adds support for PowerAuth protocol version 3.2, which adds several enhancements:
- Simplified configuration of PowerAuth Mobile SDK
- Protection against replay attacks in ECIES scheme
- Time synchronization between PowerAuth mobile SDK and server

### Simplified Configuration of PowerAuth Mobile SDK. 

You can use the `mobileSdkConfig` value from `POST /rest/v3/application/detail`, see [REST API documentation](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-getapplicationdetail). This value contains encoded master public key, application key and application secret.

Starting with version 1.5.x you can use this single configuration Base-64 encoded string for configuring the PowerAuth mobile SDK instead of using three separated configuration parameters.

## SOAP Removal

In 1.5.x, we definitely removed the SOAP interface and only support RESTful API.

## Protocol V2 End-of-Life

In 1.5.x, we definitely removed the legacy V2 protocol support and only support versions 3.x and newer. With this change, we also unified package name for model classes to `com.wultra.security.powerauth.client.model.*`.

## Database Changes

### Add Signature Data in an Easy to Parse Structure

Add following columns:
 - `signature_metadata` - metadata related to the signature calculation
 - `signature_data_body` - data used for the signature verification

#### PostgreSQL

```sql
ALTER TABLE pa_signature_audit ADD COLUMN signature_metadata TEXT;
ALTER TABLE pa_signature_audit ADD COLUMN signature_data_body TEXT;
```

#### Oracle

```sql
ALTER TABLE PA_SIGNATURE_AUDIT ADD COLUMN SIGNATURE_METADATA CLOB;
ALTER TABLE PA_SIGNATURE_AUDIT ADD COLUMN SIGNATURE_DATA_BODY CLOB;
```


### Add Proximity Check Support

Add following columns:
- `pa_operation.totp_seed` - Optional TOTP seed used for proximity check, base64 encoded.
- `pa_operation_template.proximity_check_enabled` - Whether proximity check should be used.


#### PostgreSQL

```sql
ALTER TABLE pa_operation ADD COLUMN totp_seed VARCHAR(24);
ALTER TABLE pa_operation_template ADD COLUMN proximity_check_enabled BOOLEAN NOT NULL DEFAULT FALSE;
```


#### Oracle

```sql
ALTER TABLE PA_OPERATION ADD COLUMN TOTP_SEED VARCHAR2(24 CHAR);
ALTER TABLE PA_OPERATION_TEMPLATE ADD COLUMN PROXIMITY_CHECK_ENABLED NUMBER(1, 0) DEFAULT 0 NOT NULL;
```

### Added Table for Detecting Replay Attacks

A new table `pa_unique_values` was added to store unique values sent in requests, so that replay attacks are prevented.

#### PostgreSQL

```sql
CREATE TABLE pa_unique_value (
    unique_value      VARCHAR(255) NOT NULL PRIMARY KEY,
    type              INTEGER NOT NULL,
    timestamp_expires TIMESTAMP NOT NULL
);

CREATE INDEX pa_unique_value_expiration ON pa_unique_value(timestamp_expires);
```

#### Oracle

```sql
--
-- DDL for Table PA_UNIQUE_VALUE
--
CREATE TABLE PA_UNIQUE_VALUE (
    unique_value      VARCHAR2(255 CHAR) NOT NULL PRIMARY KEY,
    type              NUMBER(10,0) NOT NULL,
    timestamp_expires TIMESTAMP NOT NULL
);

CREATE INDEX pa_unique_value_expiration ON pa_unique_value(timestamp_expires);
```

### Drop MySQL Support

Since version `1.5.0`, MySQL database is not supported anymore.


## Dependencies

PostgreSQL JDBC driver is already included in the WAR file.
Oracle JDBC driver remains optional and must be added to your deployment if desired.


## RESTful integration Changes

PowerAuth restful integration libraries in version `1.5.0` have the following important changes:

- `@PowerAuthEncryption` annotation now use `enum EncryptionScope` scope parameter provided by this library instead of low level `enum EciesScope`:
  - Please update your imports to `import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionScope;`
  - Replace usage of `EciesScope` with `EncryptionScope`, for example:
    ```java
    @PowerAuthEncryption(scope = EncryptionScope.APPLICATION_SCOPE)
    ```
- `EciesEncryptionContext` class is replaced with `EncryptionContext`
  - Please update your imports to `import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionContext;`
  - Replace usage of `EciesEncryptionContext` to `EncryptionContext`
