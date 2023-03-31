# Migration from 1.4.x to 1.5.0

This guide contains instructions for migration from PowerAuth Server version `1.3.x` to version `1.5.0`.

## SOAP Removal

In 1.5.x, we definitely removed the SOAP interface and only support RESTful API.

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
