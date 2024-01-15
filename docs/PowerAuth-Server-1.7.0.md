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
- `external_id` - external identifier for the activation
- `protocol` - protocol enumeration: `POWERAUTH` or `FIDO2`

The data type for column `extras` in table `pa_activation` was changed to `TEXT`.
