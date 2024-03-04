# Migration from 1.6.x to 1.7.0

This guide contains instructions for migration from PowerAuth Server version `1.6.x` to version `1.7.0`.

## Database Changes

For convenience you can use liquibase for your database migration.

For manual changes use SQL scripts:

- [PostgreSQL script](./sql/postgresql/migration_1.6.0_1.7.0.sql)
- [Oracle script](./sql/oracle/migration_1.6.0_1.7.0.sql)
- [MSSQL script](./sql/mssql/migration_1.6.0_1.7.0.sql)

### Updated DB Schema for FIDO2 Support

Following columns have been added to table `pa_activation` for FIDO2 support:
- `external_id` - external identifier of the activation
- `protocol` - protocol enumeration: `powerauth` or `fido2`

The data type for column `extras` in table `pa_activation` was changed to `VARCHAR` / `VARCHAR2` to support larger data.

### New Database Table for Application Configuration

A new database table `pa_application_config` has been added: 
- `id` - application configuration row identifier
- `application_id` - application identifier
- `config_key` - configuration key
- `config_values` - list of configuration values

Following parameters can be configured:
- `fido2_attestation_fmt_allowed` - allowed attestation formats for FIDO2 registrations, unset value means all attestation formats are allowed
- `fido2_aaguids_allowed` - allowed AAGUIDs for FIDO2 registration, unset value means all AAGUIDs are allowed
