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

### Add Transports Column to pa_fido2_authenticator

A new column `transports` has been added to the `pa_fido2_authenticator` table. The column allows you to assign
transport hints to a FIDO2 Authenticator registered in the table. These transport hints will be used to build allow
credential list or exclude credential list during WebAuthn ceremonies, serving as a fallback if the client fails to
provide transport hints when registering a new credential. The format of the column is a list of authenticator transport
values supported by the WebAuthn protocol, serialized as a JSON array.

### Add status_reason Column

A new column `status_reason` has been added to the `pa_operation` table.
It provides optional details why the status changed.
The value should be sent in the form of a computer-readable code, not a free-form text.

### MSSQL Server Snapshot Isolation

In case you use PowerAuth server with Microsoft SQL server, enable the SNAPSHOT isolation to avoid deadlocks.

You can enable the SNAPSHOT isolation mode using following query:

```sql
ALTER DATABASE [powerauth_database] SET ALLOW_SNAPSHOT_ISOLATION ON;
ALTER DATABASE [powerauth_database] SET READ_COMMITTED_SNAPSHOT ON;
```

The SNAPSHOT transaction isolation level is enforced automatically by PowerAuth server when database sessions are started using following query:

```sql
SET TRANSACTION ISOLATION LEVEL SNAPSHOT;
```