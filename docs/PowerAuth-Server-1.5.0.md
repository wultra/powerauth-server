# Migration from 1.4.x to 1.5.0

This guide contains instructions for migration from PowerAuth Server version `1.3.x` to version `1.5.0`.

## Spring Boot 3

The PowerAuth Server was upgraded to Spring Boot 3 and Spring Framework 6.
It requires Java 17 or newer.

Remove this property.

`spring.jpa.properties.hibernate.temp.use_jdbc_metadata_defaults=false`

## SOAP Removal

In 1.5.x, we definitely removed the SOAP interface and only support RESTful API.

## Protocol V2 End-of-Life

In 1.5.x, we definitely removed the legacy V2 protocol support and only support versions 3.x and newer. With this change, we also unified package name for model classes to `com.wultra.security.powerauth.client.model.*`.

## Database Changes

### Add Signature Data in an Easy to Parse Structure

Add following columns:
 - `signature_data_method` - HTTP method used for the signature verification
 - `signature_data_uri_id` - identifier of given URI of the resource used for the signature verification
 - `signature_data_body` - data used for the signature verification

#### PostgreSQL

```sql
ALTER TABLE pa_signature_audit ADD COLUMN signature_data_method VARCHAR(32);
ALTER TABLE pa_signature_audit ADD COLUMN signature_data_uri_id VARCHAR(255);
ALTER TABLE pa_signature_audit ADD COLUMN signature_data_body TEXT;
```

#### Oracle

```sql
ALTER TABLE PA_SIGNATURE_AUDIT ADD COLUMN SIGNATURE_DATA_METHOD VARCHAR2(32 CHAR);
ALTER TABLE PA_SIGNATURE_AUDIT ADD COLUMN SIGNATURE_DATA_URI_ID VARCHAR2(255 CHAR);
ALTER TABLE PA_SIGNATURE_AUDIT ADD COLUMN SIGNATURE_DATA_BODY CLOB;
```

### Drop MySQL Support

Since version `1.5.0`, MySQL database is not supported anymore.
