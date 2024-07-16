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

### Idempotency-Key of Callback URL Events

Callback URL Events now include an `Idempotency-Key` in the HTTP request header. It is a unique key to recognize retries
of the same request.

### New Database Table for Callback Events Monitoring

A new `pa_application_callback_event` table has been created to monitor Callback URL Events. This change introduces
the additional benefit of setting a retry strategy for individual Callback URL Events and monitoring the state of each
dispatched event. The table contains following columns:
- `id` - Event identifier, used also as the `Idempotency-Key`.
- `application_callback_id` - Reference for corresponding Callback URL record in the `pa_application_callback` table.
- `callback_data` - Data payload of the Callback URL Event.
- `status` - Current state of the Callback URL Event.
- `timestamp_created` - Creation timestamp of the Callback URL Event.
- `timestamp_last_call` - Timestamp of the last time the Callback URL Event was sent.
- `timestamp_next_call` - Timestamp of the next scheduled time to send the Callback URL Event.
- `timestamp_delete_after` - Timestamp after which the Callback URL Event record should be deleted from the table.
- `attempts` - Number of dispatch attempts made for the Callback URL Event.

### Add Columns to Configure Callback Retry Strategy

New columns has been added to the `pa_application_callback` table. These columns provide additional configuration
options for the retry strategy with an exponential backoff algorithm. Namely:
- `max_attempts` to set the maximum number of attempts to dispatch a callback,
- `initial_backoff` to set the initial backoff period before the next send attempt in milliseconds, and
- `retention_period` to set the duration for which is the callback event stored.

These settings at the individual callback level overrides the global default settings at the application level.
