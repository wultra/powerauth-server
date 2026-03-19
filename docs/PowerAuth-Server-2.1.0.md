# Migration from 2.0.x to 2.1.0

## REST API Changes

### POST /fido2/assertions

The `$.requestObject.applicationId` attribute used to verify the challenge can be approved by given application is no longer mandatory. If not present, the user ID retrieved from `$.requestObject.response.userHandle` is used to determine the application ID. 

### POST /fido2/assertions/challenge

The response contains a new `$.responseObject.operationId` attribute representing the operation ID the assertion is associated with.

## Database Changes

For convenience, you can use Liquibase for your database migration.

> **Note:** The migration adds a unique constraint on `pa_activation(application_id, activation_code)`.
> On large tables this index build can take a significant amount of time and may cause an outage.
> Consider running the Liquibase migration manually during a maintenance window before upgrading the application.

### `pa_activation` Table

* Dropped the non-unique index `pa_activation_code` on column `activation_code`.
* Added a unique constraint `pa_activation_code_application_uk` on columns `(application_id, activation_code)` to enforce activation code uniqueness at the database level per application.
