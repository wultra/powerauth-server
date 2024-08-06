# Migration from 1.8.x to 1.9.0

This guide contains instructions for migration from PowerAuth Server version `1.8.x` to version `1.9.0`.


## Database Changes

For convenience, you can use liquibase for your database migration.

For manual changes use SQL scripts:

- [PostgreSQL script](./sql/postgresql/migration_1.8.0_1.9.0.sql)
- [Oracle script](./sql/oracle/migration_1.8.0_1.9.0.sql)
- [MSSQL script](./sql/mssql/migration_1.8.0_1.9.0.sql)


### Add encryption_mode Column

A new column `encryption_mode` has been added to the `pa_application_config` table to enable encryption of configuration values.
