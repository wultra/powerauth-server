# Migration from 1.9.x to 1.10.0

This guide contains instructions for migration from PowerAuth Server version `1.9.x` to version `1.10.0`.


## Database Changes

For convenience, you can use liquibase for your database migration.

For manual changes use SQL scripts:

- [PostgreSQL script](./sql/postgresql/migration_1.9.0_1.10.0.sql)
- [Oracle script](./sql/oracle/migration_1.9.0_1.10.0.sql)
- [MSSQL script](./sql/mssql/migration_1.9.0_1.10.0.sql)


### Added Colum additional_data to the Table pa_activation

To facilitate a new feature of adding attributes for activation during creation/initiation, we added a new column `additional_data` to the table `pa_activation`.


## REST API Changes


### Activation Additional Data

It is possible to specify optional _additional data_ during activation creation or initialization.
The structure is customer-specific, for example `{"jti":"unique_value"}`.
The attribute name is `additionalData` and available in these endpoints:

- `POST /rest/v3/activation/create`
- `POST /rest/v3/activation/init`


### Updated Validations

We have unified validations in PowerAuth server REST API. The error code returned for failed request validations is always `ERR0024`. As a side effect, the error code `ERR0002` used for the case when no application ID was set in request is no longer returned.

The validation of requests is now stricter and more complete to ensure data integrity. In case you get the `ERR0024` error in your integration with PowerAuth server, please make sure the requests contain all parameters, as seen in REST API documentation available at `http[s]://[hostname]:[port]/powerauth-java-server/swagger-ui/index.html`.
