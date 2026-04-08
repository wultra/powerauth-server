# Migration from 2.0.x to 2.1.0

## REST API Changes

### POST /fido2/assertions

The `$.requestObject.applicationId` attribute used to verify the challenge can be approved by given application is no longer mandatory. If not present, the user ID retrieved from `$.requestObject.response.userHandle` is used to determine the application ID. 

### POST /fido2/assertions/challenge

The response contains a new `$.responseObject.operationId` attribute representing the operation ID the assertion is associated with.

## Database Changes

For convenience, you can use Liquibase for your database migration.

### `pa_activation` Table

The migration applies the following changes in order:

1. **Backfill NULL `activation_code` values** _(legacy databases only)_ — if any rows have a `NULL` activation code, they are updated with a unique `LEGACY-<uuid>` placeholder value. This step is automatically **skipped** (marked as ran) if no NULL values exist, which is the expected case for all databases managed by Liquibase since 1.4.x.

2. **Add `NOT NULL` constraint** on `activation_code` — aligns the DB schema with the JPA entity definition. This is a fast operation (metadata-only on MSSQL when no NULLs exist; full table scan on PostgreSQL and Oracle).

3. **Add unique constraint** `pa_activation_code_application_uk` on `(activation_code, application_id)` — enforces activation code uniqueness at the database level per application, replacing the previous application-level check. **This is an index build and can take significant time on large tables** (see performance data below).

4. **Drop the old non-unique index** `pa_activation_code` on `activation_code` — replaced by the unique constraint above (near-instant operation).

> ⚠️ **Maintenance window recommended.**
> Step 3 (index build) locks the table and can take several minutes on large deployments.
> Consider running the Liquibase migration manually during a maintenance window before upgrading the application.

> ⚠️ **Legacy databases with NULL `activation_code` values.**
> Step 1 (backfill) will UPDATE any rows with NULL `activation_code`.
> If you have a large number of such rows and want to control this operation separately
> (e.g., run it with custom batching or during off-hours), execute the following SQL **before**
> running the Liquibase migration:
>
> _PostgreSQL:_
> ```sql
> UPDATE pa_activation SET activation_code = 'LEGACY-' || gen_random_uuid()::text WHERE activation_code IS NULL;
> ```
> _Oracle:_
> ```sql
> UPDATE pa_activation SET activation_code = 'LEGACY-' || LOWER(RAWTOHEX(SYS_GUID())) WHERE activation_code IS NULL;
> ```
> _MSSQL:_
> ```sql
> UPDATE pa_activation SET activation_code = 'LEGACY-' + LOWER(CONVERT(varchar(36), NEWID())) WHERE activation_code IS NULL;
> ```
> Once done, Liquibase will detect no NULLs remain and automatically skip step 1.

### Performance Reference

Index build time measured on a 10M-row table:

| Database | ADD UNIQUE (step 3) |
|----------|:-------------------:|
| Oracle 23ai Free | ~7 s |
| PostgreSQL 18 | ~19 s |
| Azure SQL Edge 2.0 | ~22 s |
| MS SQL Server 2022 | ~89 s |
| Oracle 19c Enterprise | ~252 s |
