# Migration from 1.7.x to 1.8.0

This guide contains instructions for migration from PowerAuth Server version `1.7.x` to version `1.8.0`.

## Database Changes

For convenience, you can use liquibase for your database migration.

For manual changes use SQL scripts:

- [PostgreSQL script](./sql/postgresql/migration_1.7.0_1.8.0.sql)
- [Oracle script](./sql/oracle/migration_1.7.0_1.8.0.sql)
- [MSSQL script](./sql/mssql/migration_1.7.0_1.8.0.sql)

### Updated Index on pa_operation Table

Existing database index `pa_operation_status_exp` on the `pa_operation` table was modified to improve performance of the
process of expiration of pending operations.
