# Migration from 2.1.x to 2.2.0

## Database Changes

For convenience, you can use Liquibase for the database migration.

### Table `pa_signature_audit`

The database table `pa_signature_audit` has been extended with new columns used for asymmetric signatures:
- column `signature_algorithm` with type `VARCHAR(32)` - algorithm used for the signature (symmetric: `PowerAuth-V3`, or `PowerAuth-V4`; asymmetric: `ECDSA_P256`, `ECDSA_P384`, `MLDSA_65`, or `MLDSA_87`)
- column `signature_format` with type `varchar(32)` - format of the signature (symmetric: `DECIMAL`, or `BASE64`; asymmetric: `DER` or `JOSE`)
- column `signature` type was changed to `VARCHAR(8000)` to accommodate larger PQC signatures

## REST API Changes

### Signature Audit Response

The `SignatureAuditResponse.Item` object has been extended with new fields for asymmetric signature auditing:
- `signatureAlgorithm` (`String`) - algorithm used for the signature
- `signatureFormat` (`String`) - format of the signature


## Dependency Updates


### Docker Base Image Upgrade

The Docker base image has been upgraded from `ibm-semeru-runtimes:open-21.0.9_10-jre-noble` (OpenJDK 21) to `ibm-semeru-runtimes:open-jdk-25.0.3.0-jre-noble` (OpenJDK 25).
No action is required.


### Spring Boot 4 and Jackson 3

PowerAuth Server has been migrated to Spring Boot 4 and Jackson 3.
