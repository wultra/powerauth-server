# Migration from 2.1.x to 2.2.0

## Database Changes

For convenience, you can use Liquibase for the database migration.

### Table `pa_signature_audit`

The database table `pa_signature_audit` has been extended with new columns used for asymmetric signatures:
- column `signature_algorithm` with type `VARCHAR(32)` - algorithm used for the signature (symmetric: `PowerAuth-V3`, or `PowerAuth-V4`; asymmetric: `ECDSA_P256`, `ECDSA_P384`, `MLDSA_65`, or `MLDSA_87`)
- column `signature_format` with type `varchar(32)` - format of the signature (symmetric: `DECIMAL`, or `BASE64`; asymmetric: `DER` or `JOSE`)
- column `signature_asymmetric` with type `CLOB` - value of the asymmetric signature (ECDSA, ML-DSA); stored as `CLOB` because post-quantum (ML-DSA) signatures exceed the maximum `VARCHAR` length on Oracle

The existing `signature` column has been made nullable. It keeps holding the authentication code for symmetric records (PowerAuth v3/v4); asymmetric-signature records leave it `NULL` and store their value in `signature_asymmetric` instead.

### Table `pa_activation`

The database table `pa_activation` has been extended with new columns to support the temporary activation block feature:
- column `timestamp_block_expire` with type `DATETIME` (nullable) - timestamp after which a temporary activation block is expired
- column `temporary_block_count` with type `BIGINT` (NOT NULL, DEFAULT 0) - counter of consecutive temporary blocks, used as exponent for the block-period multiplier

Existing rows are migrated with `temporary_block_count = 0` and `timestamp_block_expire = NULL`. Existing permanently blocked activations remain blocked until they are unblocked manually; only newly triggered `MAX_FAILED_ATTEMPTS` blocks are temporary.

A new index `pa_activation_block_expire_idx` on `pa_activation(timestamp_block_expire)` is added to support the scheduled expiration of temporary activation blocks. It is created as a partial/filtered index (`WHERE timestamp_block_expire IS NOT NULL` on PostgreSQL and SQL Server) so that only currently temporarily-blocked activations are indexed, keeping the index small and the scheduled sweep efficient. On Oracle a plain single-column index is used, since Oracle does not index all-null keys and therefore achieves the same effect.

## Temporary Activation Block Feature

A new feature automatically unblocks the activation after a configurable period when the block was caused by reaching the maximum number of failed authentication attempts. The feature applies to activations using cryptography protocol v4. Activations using older protocol versions continue to be blocked permanently.

After the temporary block period expires, the activation is returned to the `ACTIVE` state and one last authentication attempt is made available (`failed_attempts` is decremented by 1). If this last attempt fails, the activation is blocked again with a longer period; on successful authentication, the failed attempts counter and the temporary block counter are both reset.

The feature is disabled by default. The default configuration is with a 5-minute initial block period and a doubling multiplier for consecutive blocks. See [Configuration-Properties.md](Configuration-Properties.md) for the new properties:
- `powerauth.service.crypto.temporaryActivationBlock.enabled` (default `false`)
- `powerauth.service.crypto.temporaryActivationBlock.periodInMilliseconds` (default `300000`)
- `powerauth.service.crypto.temporaryActivationBlock.multiplier` (default `2`)
- `powerauth.service.scheduled.job.expireTemporaryActivationBlocks` (default `5000`)

## Configuration Store Feature

A new secure configuration store allows publishing of scoped key–value configuration that the mobile
SDK can read using end-to-end encryption. It addresses values that would otherwise be hardcoded in the mobile
app and enables per-device secure storage.

Two scopes are supported:

- `APPLICATION` — configuration visible to all users of the application.
- `ACTIVATION` — configuration visible only in the context of the activation.

The configuration is stored in the new dedicated `pa_config_store` table (see below), 
and the `config_data` value is encrypted at rest using the configured 
per-record encryption algorithm. Entries are managed through the management API
(`/rest/v4/config-store/create`, `/rest/v4/config-store/list`, `/rest/v4/config-store/remove`). 
The SDK-facing delivery is read through `/rest/v4/config-store/fetch` (a server-to-server read API); 
the SDK E2EE is terminated at the enrollment server, which calls this endpoint 
and encrypts the response to the SDK. See [Web Services - Methods (V4)](./WebServices-Methods-V4.md) 
for the request/response details.

### Table `pa_config_store`

A new database table `pa_config_store` has been added to store the secure configuration values. The configuration store holds scoped key-value configuration as a JSON document, either at the application level or per-activation.

## REST API Changes

### Signature Audit Response

The `SignatureAuditResponse.Item` object has been extended with new fields for asymmetric signature auditing:
- `signatureAlgorithm` (`String`) - algorithm used for the signature
- `signatureFormat` (`String`) - format of the signature

### Activation Status / Activation Detail Response

The activation status responses have been extended with a new field:
- `timestampBlockExpire` (`Date`) - a timestamp after which the temporary activation block is expired (applies only to activations using cryptography protocol v4, null when no temporary block is in effect)

### Configuration Store

New v4 endpoints have been added for the secure configuration store (see
[Web Services - Methods (V4)](./WebServices-Methods-V4.md) for full request/response details):

- `POST /rest/v4/config-store/create` - create or update a single configuration item (management API)
- `POST /rest/v4/config-store/list` - list configuration items (management API)
- `POST /rest/v4/config-store/remove` - remove a single configuration item (management API)
- `POST /rest/v4/config-store/fetch` - fetch the scope-resolved configuration visible to an SDK caller
  (server-to-server read API consumed by the enrollment server)

## Dependency Updates

### Docker Base Image Upgrade

The Docker base image has been upgraded from `ibm-semeru-runtimes:open-21.0.9_10-jre-noble` (OpenJDK 21) to `ibm-semeru-runtimes:open-jdk-25.0.3.0-jre-noble` (OpenJDK 25).
No action is required.

### Spring Boot 4 and Jackson 3

PowerAuth Server has been migrated to Spring Boot 4 and Jackson 3.

<!-- begin box warning -->
**Known issue (fixed in 2.2.1):** As a side effect of the Jackson 3 upgrade, the operation callback timestamp attributes `timestampCreated`, `timestampExpires`, and `timestampFinalized` are serialized in the dispatched `OPERATION_STATUS_CHANGE` callback payload as ISO-8601 strings instead of the previous numeric epoch-millisecond values. Callback consumers that parse these attributes as numbers are affected. This is fixed in PowerAuth Server 2.2.1, which restores the numeric epoch-millisecond format. See [#2436](https://github.com/wultra/powerauth-server/issues/2436).
<!-- end -->
