# Database Structure

<!-- TEMPLATE database -->

You can download DDL scripts for supported databases:

- [Oracle - Create Database Schema](./sql/oracle/create_schema.sql)
- [PostgreSQL - Create Database Schema](./sql/postgresql/create_schema.sql)
- [MS SQL - Create Database Schema](./sql/mssql/create_schema.sql)

See the overall database schema:

![Database structure](./images/arch_db_structure.png)

## ShedLock

The PowerAuth Server uses ShedLock to synchronize scheduled operations.
See the [SchedLock documentation](https://github.com/lukas-krecan/ShedLock#jdbctemplate) for the details.

## Table Documentation

This chapter explains individual tables and their columns. The column types are used from PostgreSQL dialect, other databases use types that are equivalent (mapping is usually straight forward).

<!-- begin database table pa_application -->
### Applications Table

Stores applications used in the PowerAuth Server.

#### Columns

| Name  | Type         | Info          | Note                                                  |
|-------|--------------|---------------|-------------------------------------------------------|
| id    | BIGINT(20)   | autoincrement | Unique application record ID.                         |
| name  | VARCHAR(255) | -             | Application identifier, for example "mobile-banking". |
| roles | VARCHAR(255) | -             | Application roles as a JSON array.                    |
<!-- end -->

<!-- begin database table pa_application_version -->
### Application Versions Table

Stores application versions for the applications stored in `pa_application` table.

#### Columns

| Name               | Type         | Info                            | Note                                                                                                                              |
|--------------------|--------------|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| id                 | BIGINT(20)   | primary key, autoincrement      | Unique application version identifier.                                                                                            |
| application_id     | BIGINT(20)   | foreign key: pa\_application.id | Related application ID.                                                                                                           |
| name               | VARCHAR(255) | -                               | Version identifier.                                                                                                               |
| application_key    | VARCHAR(255) | index                           | Application key related to this version. Should be indexed for fast lookup, since this is the identifier client applications use. |
| application_secret | VARCHAR(255) | -                               | Application secret related to this version.                                                                                       |
| supported          | INT(11)      | -                               | Flag indicating if this version is supported or not (0 = not supported, 1..N = supported).                                        |
<!-- end -->

<!-- begin database table pa_application_config -->
### Application Configuration Table

Stores configuration records for applications defined in the `pa_application` table.

#### Columns

| Name            | Type         | Info                             | Note                                                                                                                                                                                                                                      |
|-----------------|--------------|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id              | BIGINT(20)   | primary key, autoincrement       | Unique application configuration identifier.                                                                                                                                                                                              |
| application_id  | BIGINT(20)   | foreign key: pa\_application.id  | Related application ID.                                                                                                                                                                                                                   |
| config_key      | VARCHAR(255) | index, NOT NULL                  | Configuration key names: `fido2_attestation_fmt_allowed`, `fido2_aaguids_allowed`, `fido2_root_ca_certs`, `oauth2_providers`, `cryptography_algorithms_supported`, `disable_biometry_unlock_kek_device_private`, or `activation_transfer` |
| config_values   | TEXT         | -                                | Configuration values serialized in JSON format.                                                                                                                                                                                           |
| encryption_mode | VARCHAR(255) | DEFAULT 'NO_ENCRYPTION' NOT NULL | Encryption mode for stored values: `NO_ENCRYPTION` (plaintext), `AES_HMAC` (legacy), or `AEAD_KMAC` (current).                                                                                                                            |
<!-- end -->

<!-- begin database table pa_config_store -->
### Configuration Store Table

Stores the secure configuration store as a JSON document. A record is either application-level (when `activation_id` is `NULL`) or per-activation. The configuration is delivered to the mobile SDK over end-to-end encryption based on the configured scope.

Uniqueness is enforced by a unique index on `(application_id, activation_id, config_scope)`, which constrains per-device records (`activation_id IS NOT NULL`) to at most one document per activation on every database.

#### Columns

| Name                   | Type         | Info                                       | Note                                                                                                           |
|------------------------|--------------|--------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| id                     | BIGINT(20)   | primary key, autoincrement                 | Unique configuration store record identifier.                                                                  |
| application_id         | BIGINT(20)   | NOT NULL, foreign key: pa\_application.id  | Related application ID.                                                                                        |
| activation_id          | VARCHAR(37)  | foreign key: pa\_activation.activation\_id | Related activation ID. `NULL` for application-level records.                                                   |
| config_scope           | VARCHAR(32)  | NOT NULL                                   | Configuration scope: `APPLICATION` or `ACTIVATION`.                                                            |
| config_data            | TEXT         | -                                          | Configuration values serialized as a JSON document.                                                            |
| encryption_mode        | varchar(255) | DEFAULT 'NO_ENCRYPTION' NOT NULL           | Encryption mode for stored values: `NO_ENCRYPTION` (plaintext), `AES_HMAC` (legacy), or `AEAD_KMAC` (current). |
| timestamp_created      | DATETIME     | NOT NULL                                   | Timestamp of the record creation.                                                                              |
| timestamp_last_updated | DATETIME     | -                                          | Timestamp of the last record update.                                                                           |
<!-- end -->

<!-- begin database table pa_activation -->
### Activations Table

Stores activations. Activation is a unit associating signature / transport and encryption keys to a specific user and application.

#### Columns

| Name                          | Type          | Info                                      | Note                                                                                                                                                                                                                                                                                       |
|-------------------------------|---------------|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| activation_id                 | VARCHAR(37)   | primary key, UUID (level 4)               | Unique activation ID. Uses UUID Level 4 format, for example "099e5e30-47b1-41c7-b49b-3bf28e811fca".                                                                                                                                                                                        |
| application_id                | BIGINT(20)    | NOT NULL, foreign key: pa\_application.id | Associated application ID.                                                                                                                                                                                                                                                                 |
| user_id                       | VARCHAR(255)  | NOT NULL, index                           | Associated user ID.                                                                                                                                                                                                                                                                        |
| activation_name               | VARCHAR(255)  | -                                         | Name of the activation, typically a name of the client device, for example "John's iPhone 6"                                                                                                                                                                                               |
| activation_code               | VARCHAR(255)  | index                                     | Activation code used during the activation process. Uses 4x5 characters in Base32 encoding separated by a "-" character, for example "KA4PD-RTIE2-KOP3U-H53EA".                                                                                                                            |
| activation_status             | INT(11)       | NOT NULL                                  | Activation status: 1=CREATED, 2=PENDING_COMMIT, 3=ACTIVE, 4=BLOCKED, 5=REMOVED.                                                                                                                                                                                                            |
| activation_otp                | VARCHAR(255)  | -                                         | Activation OTP value.                                                                                                                                                                                                                                                                      |
| activation_otp_validation     | INT(11)       | NOT NULL, DEFAULT 0                       | OTP validation mode: 0=NONE, 1=ON_KEY_EXCHANGE, 2=ON_COMMIT.                                                                                                                                                                                                                               |
| blocked_reason                | VARCHAR(255)  | -                                         | Reason why activation is blocked (used when activation_status = 4, BLOCKED).                                                                                                                                                                                                               |
| counter                       | BIGINT(20)    | NOT NULL                                  | Activation counter (legacy).                                                                                                                                                                                                                                                               |
| ctr_data                      | VARCHAR(255)  | -                                         | Hash-based counter data (legacy), Base64-encoded.                                                                                                                                                                                                                                          |
| device_public_key_base64      | VARCHAR(255)  | -                                         | Device public key (legacy), Base64-encoded.                                                                                                                                                                                                                                                |
| device_public_key_id          | BIGINT        | foreign key: pa\_device\_public\_key.id   | ID of the associated device public keys for V4 algorithms.                                                                                                                                                                                                                                 |
| server_private_key_base64     | VARCHAR(255)  | -                                         | Server private key (legacy), Base64-encoded.                                                                                                                                                                                                                                               |
| server_private_key_encryption | INT(11)       | NOT NULL, DEFAULT 0                       | Encryption of legacy server private key: 0=NO_ENCRYPTION, 1=AES_HMAC (legacy), 2=AEAD_KMAC (current).                                                                                                                                                                                      |
| server_public_key_base64      | VARCHAR(255)  | -                                         | Server public key (legacy), Base64-encoded.                                                                                                                                                                                                                                                |
| server_private_key_id         | BIGINT        | foreign key: pa\_server\_private\_key.id  | ID of the associated server private keys for V4 algorithms.                                                                                                                                                                                                                                |
| server_public_key_id          | BIGINT        | foreign key: pa\_server\_public\_key.id   | ID of the associated server public keys for V4 algorithms.                                                                                                                                                                                                                                 |
| activation_fingerprint        | VARCHAR(255)  | -                                         | Fingerprint of the activation.                                                                                                                                                                                                                                                             |
| shared_secret                 | VARCHAR(255)  | -                                         | Derived shared secret value.                                                                                                                                                                                                                                                               |
| shared_secret_encryption      | INT(11)       | NOT NULL, DEFAULT 0                       | Encryption for `shared_secret`: 0=NO_ENCRYPTION, 1=AES_HMAC (legacy), 2=AEAD_KMAC (current).                                                                                                                                                                                               |
| biometric_factor_enabled      | INT(11)       | -                                         | Indication whether biometric factor is enabled                                                                                                                                                                                                                                             |
| biometric_factor_key_next     | VARCHAR(255)  | -                                         | Next biometry factor key                                                                                                                                                                                                                                                                   |
| knowledge_factor_key          | VARCHAR(255)  | -                                         | Current knowledge factor key                                                                                                                                                                                                                                                               |
| knowledge_factor_key_next     | VARCHAR(255)  | -                                         | Next knowledge factor key                                                                                                                                                                                                                                                                  |
| extras                        | VARCHAR(4000) | -                                         | Any application specific information.                                                                                                                                                                                                                                                      |
| platform                      | VARCHAR(255)  | -                                         | User device platform.                                                                                                                                                                                                                                                                      |
| device_info                   | VARCHAR(255)  | -                                         | User device information.                                                                                                                                                                                                                                                                   |
| flags                         | VARCHAR(255)  | -                                         | Activation flags as a JSON array.                                                                                                                                                                                                                                                          |
| external_id                   | VARCHAR(255)  | -                                         | External identifier related to the activation.                                                                                                                                                                                                                                             |
| protocol                      | VARCHAR(32)   | NOT NULL, DEFAULT 'powerauth'             | Security protocol: `powerauth` (default) or `fido2`.                                                                                                                                                                                                                                       |
| failed_attempts               | BIGINT(20)    | NOT NULL                                  | Number of failed authentication verification attempts.                                                                                                                                                                                                                                     |
| max_failed_attempts           | BIGINT(20)    | NOT NULL, DEFAULT 5                       | Number of maximum allowed failed authentication verification attempts. After value of "failed_attempts" matches this value, activation becomes blocked (activation_status = 4, BLOCKED).                                                                                                   |
| timestamp_block_expire        | DATETIME      | index                                     | Timestamp after which a temporary activation block is automatically expired. Applies only to activations using cryptography protocol v4. NULL when no temporary block is in effect.                                                                                                        |
| temporary_block_count         | BIGINT(20)    | NOT NULL, DEFAULT 0                       | Counter of consecutive temporary blocks for v4 activations. Used as exponent for the configured multiplier: the n-th consecutive block lasts `temporaryActivationBlock.periodInMilliseconds * temporaryActivationBlock.multiplier^(n-1)` ms. Reset to zero on a successful authentication. |
| timestamp_activation_expire   | DATETIME      | NOT NULL                                  | Timestamp until which the activation must be committed. In case activation is not committed until this period, it will become REMOVED.                                                                                                                                                     |
| timestamp_created             | DATETIME      | NOT NULL                                  | Timestamp of the record creation.                                                                                                                                                                                                                                                          |
| timestamp_last_used           | DATETIME      | NOT NULL                                  | Timestamp of the last authentication verification attempt.                                                                                                                                                                                                                                 |
| timestamp_last_change         | DATETIME      | -                                         | Timestamp of the last activation modification.                                                                                                                                                                                                                                             |
| version                       | INT(11)       | NOT NULL, DEFAULT 2                       | Cryptography protocol version.                                                                                                                                                                                                                                                             |
| commit_phase                  | INT(11)       | -                                         | Commit phase behavior: 0 = ON_COMMIT (default), 1 = ON_KEY_EXCHANGE.                                                                                                                                                                                                                       |
| additional_data               | TEXT          | -                                         | Optional additional data, structure is customer-specific JSON. Could be set during creation or initialization.                                                                                                                                                                             |
| crypto_algorithm              | VARCHAR(32)   | -                                         | Cryptography algorithm used during activation.                                                                                                                                                                                                                                             |
| confirmation_pending          | BOOLEAN       | DEFAULT FALSE                             | Whether an activation confirmation is pending.                                                                                                                                                                                                                                             |
| upgrade_confirmation_pending  | BOOLEAN       | DEFAULT FALSE                             | Whether an upgrade confirmation is pending.                                                                                                                                                                                                                                                |
| ctr_data_v4                   | VARCHAR(255)  | -                                         | Counter data used by cryptography protocol v4.                                                                                                                                                                                                                                             |
| parent_activation_id          | VARCHAR(37)   | -                                         | The parent activation ID. Mandatory when `transfer_type` is present.                                                                                                                                                                                                                       |
| transfer_type                 | VARCHAR(32)   | -                                         | The activation transfer type (`SPAWN`, or `MOVE`). Mandatory when `parent_activation_id` is present.                                                                                                                                                                                       |
| master_keypair_id             | BIGINT(20)    | foreign key: pa\_master\_keypair.id       | Master key pair used during activation.                                                                                                                                                                                                                                                    |
<!-- end -->

<!-- begin database table pa_master_keypair -->
### Master Key Pair Table

Stores master key pairs associated with applications and used during the activation process.

#### Columns

| Name                           | Type         | Info                            | Note                                                                     |
|--------------------------------|--------------|---------------------------------|--------------------------------------------------------------------------|
| id                             | BIGINT(20)   | primary key, autoincrement      | Unique master key pair ID.                                               |
| application_id                 | BIGINT(20)   | foreign key: pa\_application.id | Associated application ID.                                               |
| name                           | VARCHAR(255) | -                               | Name of the key pair.                                                    |
| master_key_private_base64      | VARCHAR(255) | -                               | Legacy private key encoded as Base64.                                    |
| master_key_public_base64       | VARCHAR(255) | -                               | Legacy public key encoded as Base64.                                     |
| master_private_keys            | TEXT         | -                               | Private keys used for newer cryptography algorithms serialized as JSON.  |
| master_private_keys_encryption | INT(11)      | NOT NULL, DEFAULT 0             | Encryption: 0=NO_ENCRYPTION, 1=AES_HMAC (legacy), 2=AEAD_KMAC (current). |
| master_public_keys             | TEXT         | -                               | Public keys used for newer cryptography algorithms serialized as JSON.   |
| timestamp_created              | DATETIME     | NOT NULL                        | Timestamp of creation.                                                   |
<!-- end -->

<!-- begin database table pa_signature_audit -->
### Signature Audit Records Table

Stores the records with values used for attempts for the signature validation.

#### Columns

| Name                | Type         | Info                                       | Note                                                                      |
|---------------------|--------------|--------------------------------------------|---------------------------------------------------------------------------|
| id                  | BIGINT(20)   | primary key, autoincrement                 | Unique record ID.                                                         |
| activation_id       | VARCHAR(37)  | foreign key: pa\_activation.activation\_id | Associated activation ID.                                                 |
| activation_counter  | BIGINT(20)   | -                                          | Activation counter at the moment of signature validation.                 |
| activation_ctr_data | VARCHAR(255) | -                                          | Activation hash based counter data at the moment of signature validation. |
| activation_status   | INT(11)      | -                                          | Activation status at the moment of signature validation.                  |
| additional_info     | VARCHAR(255) | -                                          | Additional information related to the signature request in JSON format.   |
| data_base64         | TEXT         | -                                          | Data passed as the base for the signature, encoded as Base64.             |
| signature_type      | VARCHAR(255) | -                                          | Requested type of the signature.                                          |
| signature           | VARCHAR(255) | -                                          | Provided value of the authentication code (symmetric records). Null for asymmetric-signature records. |
| signature_asymmetric | TEXT        | -                                          | Provided value of the asymmetric signature (ECDSA, ML-DSA), stored as CLOB. Null for symmetric authentication-code records. |
| signature_algorithm | VARCHAR(32)  | -                                          | Algorithm used for the signature (symmetric: `PowerAuth-V3`, or `PowerAuth-V4`; asymmetric: `ECDSA_P256`, `ECDSA_P384`, `MLDSA_65`, or `MLDSA_87`). |
| signature_format    | VARCHAR(32)  | -                                          | Format of the signature (symmetric: `DECIMAL`, or `BASE64`; asymmetric: `DER` or `JOSE`). |
| signature_metadata  | TEXT         | -                                          | JSON with signature metadata related to the signature calculation.        |
| signature_data_body | TEXT         | -                                          | Data used for the signature verification.                                 |
| valid               | INT(11)      | -                                          | Flag indicating if the provided signature was valid.                      |
| note                | TEXT         | -                                          | Additional information about the validation result.                       |
| timestamp_created   | DATETIME     | index                                      | A timestamp of the validation attempt.                                    |
| version             | INT(11)      | -                                          | PowerAuth protocol version.                                               |
| signature_version   | VARCHAR(255) | -                                          | PowerAuth signature version.                                              |
<!-- end -->

<!-- begin database table pa_integration -->
### Integration Credentials Table

Stores credentials for applications that integrate with PowerAuth Server.

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | VARCHAR(37) | primary key | Unique integration ID, UUID Level 4 format. |
| name | VARCHAR(255) | - | Integration name, anything that visually identifies the associated application. |
| client_token | VARCHAR(37) | index | Integration username, UUID Level 4 format. |
| client_secret | VARCHAR(37) | - | Integration password, UUID Level 4 format. |
<!-- end -->

<!-- begin database table pa_application_callback -->
### Application Callback URL Table

Stores callback URLs - per-application endpoints that are notified whenever an activation or operation status changes.

#### Columns

| Name            | Type         | Info                             | Note                                                                                                                       |
|-----------------|--------------|----------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| id              | VARCHAR(37)  | primary key                      | Unique callback URL identifier, UUID Level 4 format.                                                                       |
| application_id  | BIGINT(20)   | foreign key: pa\_application.id  | Associated application ID.                                                                                                 |
| name            | VARCHAR(255) | -                                | Callback name, anything that visually identifies the callback purpose.                                                     |
| callback_url    | TEXT         | -                                | Callback URL value, any URL that can receive activation update callback.                                                   |
| type            | VARCHAR(64)  | -                                | Callback type: `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`.                                                    |
| attributes      | TEXT         | -                                | Callback attributes as a key-value map, serialized into JSON.                                                              |
| authentication  | TEXT         | -                                | Callback HTTP request authentication configuration, serialized into JSON.                                                  |
| encryption_mode | VARCHAR(255) | DEFAULT 'NO_ENCRYPTION' NOT NULL | Encryption of authentication values: `NO_ENCRYPTION` means plaintext, `AES_HMAC` for AES encryption with HMAC-based index. |
| max_attempts | INTEGER | - | Maximum number of attempts to dispatch a callback. |
| initial_backoff | VARCHAR(64) | - | Initial backoff period before the next send attempt, stored as a ISO 8601 string. |
| retention_period | VARCHAR(64) | - | Minimal duration for which is a completed callback event persisted, stored as a ISO 8601 string. |
| enabled | BOOLEAN | - | Indicator specifying whether the Callback URL should be used. |
| timestamp_created | DATETIME | DEFAULT NOW() NOT NULL | Timestamp when the record was created. |
| timestamp_last_updated | DATETIME | - | Timestamp of the last update of the record via the Callback Management API. |
<!-- end -->

<!-- begin database table pa_token -->
### Token Store Table

Stores tokens used for token-based authentication.

#### Columns

| Name              | Type         | Info                                      | Note                                                     |
|-------------------|--------------|-------------------------------------------|----------------------------------------------------------|
| token_id          | VARCHAR(37)  | primary key                               | Unique identifier of the token.                          |
| token_secret      | VARCHAR(255) | -                                         | Secret value used for computing the token digest.        |
| activation_id     | VARCHAR(37)  | foreign key: pa\_activation.activation_id | Reference to associated activation.                      |
| signature_type    | VARCHAR(255) | -                                         | Type of the signature that was used to issue this token. |
| timestamp_created | DATETIME     | -                                         | Timestamp of the record creation.                        |
<!-- end -->

<!-- begin database table pa_activation_history -->
### Activation History Table

Stores a log of activation changes.

#### Columns

| Name               | Type         | Info                                      | Note                                                                                                                                                                            |
|--------------------|--------------|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id                 | BIGINT(20)   | primary key                               | Unique record ID.                                                                                                                                                               |
| activation_id      | VARCHAR(37)  | foreign key: pa\_activation.activation_id | Reference to associated activation.                                                                                                                                             |
| activation_status  | INT(11)      | index                                     | Activation status, can be one of following values:<br><br>1 - CREATED<br>2 - PENDING_COMMIT<br>3 - ACTIVE<br>4 - BLOCKED<br>5 - REMOVED                                         |
| event_reason       | VARCHAR(255) | -                                         | Reason why activation was changed.                                                                                                                                              |
| external_user_id   | VARCHAR(255) | -                                         | External user ID of user who caused change of the activation (e.g. banker user ID). In case the value is null the change was caused by the user associated with the activation. |
| timestamp_created  | DATETIME     | -                                         | Timestamp of the record creation.                                                                                                                                               |
| activation_version | INT(2)       | -                                         | Activation version                                                                                                                                                              |
| activation_name    | VARCHAR(255) | -                                         | Activation name.                                                                                                                                                                |
<!-- end -->

<!-- begin database table pa_recovery_code -->
### Recovery Code Table

Stores information about recovery codes.

#### Columns

| Name                  | Type         | Info                                      | Note                                                                                                                                                                    |
|-----------------------|--------------|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id                    | BIGINT(20)   | primary key                               | Unique record ID.                                                                                                                                                       |
| recovery_code         | VARCHAR(23)  | index                                     | Recovery code used for recovering an activation. Uses 4x5 characters in Base32 encoding separated by a "-" character, for example "KA4PD-RTIE2-KOP3U-H53EA".            |
| application_id        | BIGINT(20)   | foreign key: pa\_application.id           | Related application ID.                                                                                                                                                 |
| user_id               | VARCHAR(255) | index                                     | Associated user ID.                                                                                                                                                     |
| activation_id         | VARCHAR(37)  | foreign key: pa\_activation.activation_id | Reference to associated activation.                                                                                                                                     |
| status                | INT(11)      | -                                         | Recovery code status, can be one of following values:<br><br>1 - CREATED<br>2 - ACTIVE<br>3 - BLOCKED<br>4 - REVOKED                                                    |
| failed_attempts       | BIGINT(20)   | -                                         | Number of failed activation recovery attempts.                                                                                                                          |
| max_failed_attempts   | BIGINT(20)   | -                                         | Number of maximum allowed failed activation recovery attempts. After value of "failed_attempts" matches this value, recovery code becomes blocked (status = 3, BLOCKED) |
| timestamp_created     | DATETIME     | -                                         | Timestamp of record creation.                                                                                                                                           |
| timestamp_last_used   | DATETIME     | -                                         | Timestamp of record last usage.                                                                                                                                         |
| timestamp_last_change | DATETIME     | -                                         | Timestamp of record last change.                                                                                                                                        |
<!-- end -->

<!-- begin database table pa_recovery_puk -->
### Recovery PUK Table

Stores information about recovery PUKs.

#### Columns

| Name                  | Type         | Info                                      | Note                                                                                              |
|-----------------------|--------------|-------------------------------------------|---------------------------------------------------------------------------------------------------|
| id                    | BIGINT(20)   | primary key                               | Unique record ID.                                                                                 |
| recovery_code_id      | BIGINT(20)   | foreign key: pa\_recovery\_code.id, index | Related recovery code.                                                                            |
| puk                   | VARCHAR(255) | -                                         | Recovery PUK value (optionally encrypted).                                                        |
| puk_encryption        | INT(11)      | -                                         | Encryption type for PUK (0 = NO_ENCRYPTION, 1 = AES_HMAC)                                         |
| puk_index             | INT(11)      | index                                     | Index of the PUK (value starts by 1).                                                             |
| status                | INT(11)      | -                                         | Recovery PUK status, can be one of following values: <br><br>1 - VALID<br>2 - USED<br>3 - INVALID |
| timestamp_last_change | DATETIME     | -                                         | Timestamp of record last change.                                                                  |
<!-- end -->

<!-- begin database table pa_recovery_config -->
### Recovery Configuration Table

Stores configuration of activation recovery and recovery postcards.

#### Columns

| Name                          | Type         | Info                            | Note                                                                |
|-------------------------------|--------------|---------------------------------|---------------------------------------------------------------------|
| id                            | BIGINT(20)   | primary key                     | Unique record ID.                                                   |
| application_id                | BIGINT(20)   | foreign key: pa\_application.id | Related application ID.                                             |
| activation_recovery_enabled   | INT(1)       | -                               | Whether activation recovery is enabled.                             |
| recovery_postcard_enabled     | INT(1)       | -                               | Whether recovery postcard is enabled.                               |
| allow_multiple_recovery_codes | INT(1)       | -                               | Whether multiple recovery codes are allowed per user.               |
| postcard_private_key_base64   | VARCHAR(255) | -                               | Base64 encoded EC server private key for recovery postcard.         |
| postcard_public_key_base64    | VARCHAR(255) | -                               | Base64 encoded EC server public key for recovery postcard.          |
| remote_public_key_base64      | VARCHAR(255) | -                               | Base64 encoded EC printing center public key for recovery postcard. |
| postcard_priv_key_encryption  | INT(1)       | -                               | Private key encryption mode; 0 for no-encryption, 1 for AES_HMAC.   |
<!-- end -->

<!-- begin database table pa_operation -->
### Operations

Table stores operations, i.e., the login attempts or payment approvals, that are created in external systems.

#### Columns

| Name                | Type         | Info        | Note                                                                                                                             |
|---------------------|--------------|-------------|----------------------------------------------------------------------------------------------------------------------------------|
| id                  | varchar(37)  | primary key | Unique operation ID.                                                                                                             |
| user_id             | varchar(255) | -           | Related user ID.                                                                                                                 |
| template_name       | varchar(255) | -           | Template name used for creating the operation.                                                                                   |
| external_id         | varchar(255) | -           | Identifier in external system.                                                                                                   |
| activation_flag     | varchar(255) | -           | Activation flag.                                                                                                                 |
| operation_type      | varchar(255) | -           | Name of the type of operation.                                                                                                   |
| data                | text         | -           | Data of the operation that enter the final signature.                                                                            |
| parameters          | text         | -           | JSON-encoded parameters that were used while creating the operation.                                                             |
| additional_data     | text         | -           | Allow storing operation context.                                                                                                 |
| status              | integer      | -           | Status of the operation.                                                                                                         |
| status_reason       | varchar(32)  | -           | Optional details why the status changed. The value should be sent in the form of a computer-readable code, not a free-form text. |
| signature_type      | varchar(255) | -           | Comma-separated list of allowed signature types.                                                                                 |
| failure_count       | bigint       | -           | Number of already failed attempts to approve the operation.                                                                      |
| max_failure_count   | bigint       | -           | Maximum allowed number of failed attempts when approving the operation.                                                          |
| timestamp_created   | timestamp    | -           | Timestamp of when the operation was created.                                                                                     |
| timestamp_expires   | timestamp    | -           | Timestamp of when the operation will expire.                                                                                     |
| timestamp_finalized | timestamp    | -           | Timestamp of when the operation reached the terminal state (approved, rejected, expired, etc.).                                  |
| risk_flags          | varchar(255) | -           | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`.                                                 |
| totp_seed           | varchar(24)  | -           | Optional TOTP seed used for proximity check, base64 encoded.                                                                     |
| activation_id       | varchar(37)  | -           | Activation ID, a foreign key.                                                                                                    |
<!-- end -->

<!-- begin database table pa_operation_template -->
### Operation Templates

Table stores operation templates that are used while creating the operations.

#### Columns

| Name                    | Type         | Info        | Note                                                                             |
|-------------------------|--------------|-------------|----------------------------------------------------------------------------------|
| id                      | varchar(37)  | primary key | Unique template ID.                                                              |
| template_name           | varchar(255) | -           | Template name.                                                                   |
| operation_type          | varchar(255) | -           | Name of the type of operation.                                                   |
| data_template           | varchar(255) | -           | Template string for the data that will enter signature later.                    |
| signature_type          | varchar(255) | -           | Comma-separated list of allowed signature types.                                 |
| max_failure_count       | bigint       | -           | Maximum allowed number of failed attempts when approving the operation.          |
| expiration              | bigint       | -           | Operation expiration in seconds (300 = 5 minutes).                               |
| risk_flags              | varchar(255) | -           | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| proximity_check_enabled | boolean      | -           | Whether proximity check is enabled and TOTP seed should be generated.            |
<!-- end -->

<!-- begin database table pa_operation_application -->
### Operations

Table stores operations, i.e., the login attempts or payment approvals, that are created in external systems.

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| application_id | bigint | part of primary key | Related application ID. |
| operation_id | varchar(37)  | part of primary key | Related operation ID. |
<!-- end -->

<!-- begin database table pa_fido2_authenticator -->
### FIDO2 Authenticators

Table stores details about FIDO2 Authenticators.

#### Columns

| Name           | Type         | Info        | Note                                                   |
|----------------|--------------|-------------|--------------------------------------------------------|
| aaguid         | varchar(255) | primary key | Identifier of the FIDO2 authenticator.                 |
| description    | varchar(255) | -           | Human-readable description of the FIDO2 authenticator. |
| signature_type | varchar(255) | -           | Signature type provided by the FIDO2 authenticator.    |
| transports     | varchar(255) | -           | JSON array of transport hints for WebAuthn ceremonies. |
<!-- end -->

<!-- begin database table pa_temporary_key -->
### Temporary Keys

Table stores details about temporary key pairs used for data encryption.

#### Columns

| Name                   | Type         | Info                                                             | Note                                                                                                |
|------------------------|--------------|------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| id                     | VARCHAR(37)  | primary key                                                      | Identifier of the temporary key pair.                                                               |
| application_key        | VARCHAR(32)  | NOT NULL, foreign key: pa\_application\_version.application\_key | Identifier of the application version (application key).                                            |
| activation_id          | VARCHAR(37)  | foreign key: pa\_activation.activation\_id                       | Identifier of an associated activation (activation ID).                                             |
| private_key_encryption | INT(11)      | -                                                                | Encryption indicator for private key 0=NO_ENCRYPTION, 1=AES_HMAC (legacy), 2=AEAD_KMAC (current).   |
| private_key_base64     | VARCHAR(255) | -                                                                | Temporary private key encoded as Base64.                                                            |
| public_key_base64      | VARCHAR(255) | -                                                                | Temporary public key encoded as Base64.                                                             |
| secret_key_base64      | VARCHAR(255) | -                                                                | Base64-encoded shared secret key.                                                                   |
| secret_key_encryption  | INT(11)      | -                                                                | Encryption indicator for shared secret 0=NO_ENCRYPTION, 1=AES_HMAC (legacy), 2=AEAD_KMAC (current). |
| timestamp_expires      | DATETIME     | index                                                            | Timestamp when the temporary key pair expires.                                                      |
<!-- end -->

<!-- begin database table pa_application_callback_event -->
### Callback URL Events

Table stores Callback URL Events to monitor processing of the callbacks.

#### Columns

| Name                    | Type        | Info        | Note                                                                                     |
|-------------------------|-------------|-------------|------------------------------------------------------------------------------------------|
| id                      | bigint      | primary key | Identifier of the Callback URL Event.                                                    |
| application_callback_id | varchar(37) | -           | Reference to configuration of the Callback URL Event in `pa_application_callback` table. |
| callback_data           | text        | -           | Data payload of the Callback URL Event.                                                  |
| status                  | varchar(32) | -           | Current status of the Callback URL Event.                                                |
| timestamp_created       | timestamp   | NOT NULL    | Timestamp of the Callback URL Event creation.                                            |
| timestamp_last_call     | timestamp   | -           | Timestamp of the last attempt to send the Callback URL Event.                            |
| timestamp_next_call     | timestamp   | NOT NULL    | Timestamp of the next scheduled time to send the Callback URL Event.                     |
| timestamp_delete_after  | timestamp   | NOT NULL    | Timestamp after which the Callback URL Event record can be deleted from the table.       |
| timestamp_rerun_after   | timestamp   | -           | Timestamp after which the Callback URL Event in processing state will be rerun.          |
| attempts                | integer     | -           | Number of dispatch attempts made for the Callback URL Event.                             |
| idempotency_key         | varchar(36) | -           | Idempotency key associated with the Callback URL Event.                                  |
<!-- end -->

<!-- begin database table pa_unique_value -->
### Unique Value

Table stores unique values sent in requests, so that replay attacks are prevented.

#### Columns

| Name              | Type         | Info        | Note                                                                               |
|-------------------|--------------|-------------|------------------------------------------------------------------------------------|
| unique_value      | varchar(255) | primary key | Unique value.                                                                      |
| type              | integer      | -           | Value type, 0 - MAC_TOKEN, 1 - ECIES_APPLICATION_SCOPE, 2 - ECIES_ACTIVATION_SCOPE |
| timestamp_expires | timestamp    | -           | Timestamp when the value expires.                                                  |
<!-- end -->

<!-- begin database table pa_device_public_key -->
### Device Public Key

Table stores device public keys associated with activations.

#### Columns

| Name     | Type   | Info        | Note                                         |
|----------|--------|-------------|----------------------------------------------|
| id       | bigint | primary key | Identifier of the device public key record.  |
| key_data | text   | -           | Device public keys for V4 algorithms (JSON). |
<!-- end -->

<!-- begin database table pa_server_public_key -->
### Server Public Key

Table stores server public keys associated with activations.

#### Columns

| Name     | Type   | Info        | Note                                         |
|----------|--------|-------------|----------------------------------------------|
| id       | bigint | primary key | Identifier of the server public key record.  |
| key_data | text   | -           | Server public keys for V4 algorithms (JSON). |
<!-- end -->

<!-- begin database table pa_server_private_key -->
### Server Private Key

Table stores server private keys associated with activations.

#### Columns

| Name                | Type    | Info                | Note                                                                                    |
|---------------------|---------|---------------------|-----------------------------------------------------------------------------------------|
| id                  | bigint  | primary key         | Identifier of the server private key record.                                            |
| key_data            | text    | -                   | Server private keys for V4 algorithms (JSON).                                           |
| key_data_encryption | integer | not null, default 0 | Encryption for `key_data`: 0=NO_ENCRYPTION, 1=AES_HMAC (legacy), 2=AEAD_KMAC (current). |
<!-- end -->
