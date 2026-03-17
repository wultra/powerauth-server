# Migration from 2.0.x to 2.1.0

## REST API Changes

### POST /fido2/assertions

The `$.requestObject.applicationId` attribute used to verify the challenge can be approved by given application is no longer mandatory. If not present, the user ID retrieved from `$.requestObject.response.userHandle` is used to determine the application ID. 

### POST /fido2/assertions/challenge

The response contains a new `$.responseObject.operationId` attribute representing the operation ID the assertion is associated with.

## Database Changes

For convenience, you can use liquibase for your database migration.

For manual changes use SQL scripts:

- [PostgreSQL script](sql/postgresql/migration_1.10.0_2.0.0.sql)
- [Oracle script](sql/oracle/migration_1.10.0_2.0.0.sql)
- [MSSQL script](sql/mssql/migration_1.10.0_2.0.0.sql)

