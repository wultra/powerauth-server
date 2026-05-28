# Migration from 2.1.x to 2.2.0

## Database Changes

For convenience, you can use Liquibase for the database migration.

### Table `pa_signature_audit`

The database table `pa_signature_audit` has been extended with new columns used for asymmetric signatures:
- column `signature_algorithm` with type `VARCHAR(32)` - algorithm used for the signature (symmetric: `PowerAuth-V3`, or `PowerAuth-V4`; asymmetric: `ECDSA_P256`, `ECDSA_P384`, `MLDSA_65`, or `MLDSA_87`)
- column `signature_format` with type `varchar(32)` - format of the signature (symmetric: `DECIMAL`, or `BASE64`; asymmetric: `DER` or `JOSE`)
- column `signature` type was changed to `VARCHAR(8000)` to accommodate larger PQC signatures

### Table `pa_activation`

The database table `pa_activation` has been extended with new columns to support the temporary activation block feature:
- column `timestamp_block_expire` with type `DATETIME` (nullable) - timestamp after which a temporary activation block is expired
- column `temporary_block_count` with type `BIGINT` (NOT NULL, DEFAULT 0) - counter of consecutive temporary blocks, used as exponent for the block-period multiplier

Existing rows are migrated with `temporary_block_count = 0` and `timestamp_block_expire = NULL`. Existing permanently blocked activations remain blocked until they are unblocked manually; only newly triggered `MAX_FAILED_ATTEMPTS` blocks are temporary.

## Temporary Activation Block Feature

A new feature automatically expires the activation block after a configurable period when the block was caused by reaching the maximum number of failed authentication attempts. The feature applies to activations using cryptography protocol v4. Activations using older protocol versions continue to be blocked permanently.

After the temporary block period expires, the activation is returned to the `ACTIVE` state and one last authentication attempt is made available (`failed_attempts` is decremented by 1). If this last attempt fails, the activation is blocked again with a longer period; on successful authentication, the failed attempts counter and the temporary block counter are both reset.

The feature is disabled by default. The default configuration is with a 5-minute initial block period and a doubling multiplier for consecutive blocks. See [Configuration-Properties.md](Configuration-Properties.md) for the new properties:
- `powerauth.service.crypto.temporaryActivationBlock.enabled` (default `false`)
- `powerauth.service.crypto.temporaryActivationBlock.periodInMilliseconds` (default `300000`)
- `powerauth.service.crypto.temporaryActivationBlock.multiplier` (default `2`)
- `powerauth.service.scheduled.job.expireTemporaryActivationBlocks` (default `5000`)

## REST API Changes

### Signature Audit Response

The `SignatureAuditResponse.Item` object has been extended with new fields for asymmetric signature auditing:
- `signatureAlgorithm` (`String`) - algorithm used for the signature
- `signatureFormat` (`String`) - format of the signature

### Activation Status / Activation Detail Response

The activation status responses have been extended with a new field:
- `timestampBlockExpire` (`Date`) - timestamp after which a temporary activation block is expired (null when no temporary block is in effect)

