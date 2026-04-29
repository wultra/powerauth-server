# Migration from 2.0.x to 2.1.0

## REST API Changes

### POST /fido2/assertions

The `$.requestObject.applicationId` attribute used to verify the challenge can be approved by given application is no longer mandatory. If not present, the user ID retrieved from `$.requestObject.response.userHandle` is used to determine the application ID. 

### POST /fido2/assertions/challenge

The response contains a new `$.responseObject.operationId` attribute representing the operation ID the assertion is associated with.

#### POST /rest/v4/activation/status

The request contains a new parameter `includeStatusBlob` which controls whether the activation status blob is included in the response. By default, the status blob is included.

### POST /rest/v3/signature/list

The data type of the `signatureType` field in each element of the response list has been updated to `String`. The field
values remain unchanged and continue to represent the same set of signature types in the existing format.

### POST /rest/v4/audit/list

The data type of the `signatureType` field in each element of the response list has been updated to `String`. The field
values remain unchanged and continue to represent the same set of signature types in the existing format.

## Database Changes

For convenience, you can use Liquibase for your database migration.

### `pa_activation` Table

The migration applies the following changes in order:

1. **Backfill NULL `activation_code` values** _(legacy databases only)_ — if any rows have a `NULL` activation code, they are updated with a unique `LEGACY-<uuid>` placeholder value. This step is automatically **skipped** (marked as ran) if no NULL values exist, which is the expected case for all databases managed by Liquibase since 1.4.x.

2. _(MSSQL only)_ **Drop the old non-unique index** `pa_activation_code` — MSSQL blocks `ALTER COLUMN` when a dependent index exists. This step is automatically **skipped** on PostgreSQL and Oracle.

3. **Add `NOT NULL` constraint** on `activation_code` — aligns the DB schema with the JPA entity definition. This is a fast operation (metadata-only on MSSQL when no NULLs exist; full table scan on PostgreSQL and Oracle).

4. **Add unique constraint** `pa_activation_code_application_uk` on `(activation_code, application_id)` — enforces activation code uniqueness at the database level per application, replacing the previous application-level check. **This is an index build and can take significant time on large tables** (see performance data below).

5. _(PostgreSQL, Oracle)_ **Drop the old non-unique index** `pa_activation_code` — replaced by the unique constraint above (near-instant operation). Automatically skipped on MSSQL (already dropped in step 2).

> ⚠️ **Maintenance window recommended.**
> Step 4 (index build) locks the table and can take several minutes on large deployments.
> Consider running the Liquibase migration manually during a maintenance window before upgrading the application.

> ⚠️ **MSSQL: brief index gap during migration.**
> On MSSQL, step 2 drops the old `pa_activation_code` index before the new unique constraint is created in step 4.
> During this window, queries filtering on `activation_code` alone will perform a full table scan.
> The gap is bounded by steps 3 and 4 only, which are fast operations on MSSQL (metadata-only NOT NULL + index build).
> Plan the migration during a maintenance window to avoid query performance impact.

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

#### Performance Reference

Index build time measured on a 10M-row table:

| Database | ADD UNIQUE (step 3) |
|----------|:-------------------:|
| Oracle 23ai Free | ~7 s |
| PostgreSQL 18 | ~19 s |
| Azure SQL Edge 2.0 | ~22 s |
| MS SQL Server 2022 | ~89 s |

### `audit_log` Table

Added a new indexed column `subject_id` holding an identifier linking the audit record to an entity it is related to (e.g. user ID for user-related audit records).

<!-- begin box warning -->
The auditing tables may be already updated in your database schema if the database schema is not separated for different PowerAuth applications. In case the column `audit_log.subject_id` and its index `audit_log_subject_id_idx` are already present, you can safely skip this migration step.
<!-- end -->

## Other Changes

### Removal of Deprecated Signature / Authentication Code Types

Since PowerAuth SDK version 1.7.0, client-side support has been limited to the following signature types
(referred to in current terminology as authentication code types):

- `POSSESSION`
- `POSSESSION_KNOWLEDGE`
- `POSSESSION_BIOMETRY`

The remaining types:

- `KNOWLEDGE`
- `BIOMETRY`
- `POSSESSION_KNOWLEDGE_BIOMETRY`

remained available on the server side only for backward compatibility with older SDK versions. As of this release,
server-side components support for these deprecated types has also been removed.

Any occurrence of a removed signature type stored in the `pa_operation.signature_type` or
`pa_operation_template.signature_type` columns is now ignored during processing. In the rare case where an operation
template contains only removed signature types, operations created from that template will not receive any allowed
signature type and therefore cannot be approved. In such cases, update the affected template to use one of the supported
signature types. Otherwise, this change is not expected to have practical impact, and no database migration is required.
