# Migration from 1.8.x to 1.9.0

This guide contains instructions for migration from PowerAuth Server version `1.8.x` to version `1.9.0`.


## Database Changes

For convenience, you can use liquibase for your database migration.

For manual changes use SQL scripts:

- [PostgreSQL script](./sql/postgresql/migration_1.8.0_1.9.0.sql)
- [Oracle script](./sql/oracle/migration_1.8.0_1.9.0.sql)
- [MSSQL script](./sql/mssql/migration_1.8.0_1.9.0.sql)

### Added pa_temporary_key Table

To facilitate a new feature of temporary keys, we added a new `pa_temporary_key` table to store the key pairs.

### Add encryption_mode Column

A new column `encryption_mode` has been added to the `pa_application_config` table to enable encryption of configuration values.

## REST API Changes

### Added Services for Temporary Keys

The API now publishes new endpoints related to the temporary key management:

- `POST /rest/v3/keystore/create` - Creates a new temporary key pair
- `POST /rest/v3/keystore/remove` - Removes a temporary key pair

### ECDSA Signature Verification in JOSE Format

The method `POST /rest/v3/signature/ecdsa/verify` now supports validation of ECDSA signature in JOSE format, thanks to added `signatureFormat` request attribute (`DER` or `JOSE` values).