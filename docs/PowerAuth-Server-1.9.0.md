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

* A new column `encryption_mode` has been added to the `pa_application_config` table to enable encryption of configuration values.
* A new column `encryption_mode` has been added to the `pa_application_callback` table to enable encryption of authentication values.

### New Database Table for Callback Events Monitoring

A new `pa_application_callback_event` table has been created to monitor Callback URL Events. This change introduces
the additional benefit of setting a retry strategy for individual Callback URL Events and monitoring the state of each
dispatched event. The table contains following columns:
- `id` - Event identifier, generated using sequence `pa_app_callback_event_seq`.
- `application_callback_id` - Reference for corresponding Callback URL record in the `pa_application_callback` table.
- `callback_data` - Data payload of the Callback URL Event.
- `status` - Current state of the Callback URL Event.
- `timestamp_created` - Creation timestamp of the Callback URL Event.
- `timestamp_last_call` - Timestamp of the last attempt to send the Callback URL Event.
- `timestamp_next_call` - Timestamp of the next scheduled time to send the Callback URL Event.
- `timestamp_delete_after` - Timestamp after which the Callback URL Event record should be deleted from the table.
- `timestamp_rerun_after` - Timestamp after which the Callback URL Event record in processing state should be rerun.
- `attempts` - Number of dispatch attempts made for the Callback URL Event.
- `idempotency_key` - UUID used as the `Idempotency-Key`.

The `pa_application_callback_event` table comes with following indices:
- `pa_app_cb_event_status_idx` on `(status)`,
- `pa_app_cb_event_ts_del_idx` on `(timestamp_delete_after)`.

### New Configuration Properties for Callback Events Monitoring

New configuration options has been added to modify the Callback URL Events monitoring and retry policy.
See the [Callback URL Events Configuration section](./Configuration-Properties.md#callback-url-events-configuration)
for further details.

### Add Columns to Configure Callback Retry Strategy

New columns has been added to the `pa_application_callback` table. These columns provide additional configuration
options for the retry strategy with an exponential backoff algorithm. Namely:
- `max_attempts` to set the maximum number of attempts to dispatch a callback,
- `initial_backoff` to set the initial backoff period before the next send attempt, and
- `retention_period` to set the duration for which is the callback event stored.

These settings at the individual callback level overrides the global default settings at the application level.


## REST API Changes

### Added Services for Temporary Keys

The API now publishes new endpoints related to the temporary key management:

- `POST /rest/v3/keystore/create` - Creates a new temporary key pair
- `POST /rest/v3/keystore/remove` - Removes a temporary key pair

### Deprecated Parameter activationOtpValidation in Init Activation

The parameter `activationOtpValidation` is deprecated.
Use the `activationOtp` parameter during activation init or activation commit to control the OTP check.
Use the `commitPhase` parameter for specifying when the activation should be committed.

### ECDSA Signature Verification in JOSE Format

The method `POST /rest/v3/signature/ecdsa/verify` now supports validation of ECDSA signature in JOSE format, thanks to added `signatureFormat` request attribute (`DER` as a default value, or `JOSE`).

## Other Changes

### Idempotency-Key of Callback URL Events

Callback URL Events now include an `Idempotency-Key` in the HTTP request header. It is a unique key to recognize retries
of the same request.
