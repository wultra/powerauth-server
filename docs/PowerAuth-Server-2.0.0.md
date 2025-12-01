# Migration from 1.10.x to 2.0.0

## Update Database Encryption Configuration

PowerAuth Server 2.0.0 introduces a new default database encryption algorithm used for encrypting sensitive values stored in the database, such as master private keys, activation private keys, temporary keys, callback authentication, and other sensitive data. This encryption is done by the PowerAuth server application and it should be used on top of database encryption at rest to avoid leakage of sensitive data.

### New Default Encryption Algorithm: `AEAD_KMAC`

The algorithm `AEAD_KMAC` is now the default database encryption algorithm. It uses:

* a 256-bit master DB encryption key  
* KMAC-256 for per-record key derivation  
* Authenticated encryption using an AEAD scheme based on AES-256

This offers improved security with post-quantum grade encryption.

### Required Action: Configure a 256-bit Base64-Encoded Encryption Key

To use the default algorithm, configure the following property:

```
powerauth.server.db.master.encryption.aead-kmac.key=<base64-encoded-256-bit-key>
```

The server will not start if `AEAD_KMAC` is the default algorithm but the key is missing or invalid.

### How to Generate a Valid 256-bit Encryption Key

Use any cryptographically secure random generator to produce a 32-byte key and encode it in Base64.

#### Linux / macOS

```
head -c 32 /dev/urandom | base64
```

#### OpenSSL

```
openssl rand -base64 32
```

Paste the generated value into the configuration property.

### Securing the Encryption Key

The master database encryption key is a highly sensitive secret and must be protected. Do not store this key directly in configuration files, source control, or container images. Use a secure secret management solution (such as a vault or encrypted configuration provider) to supply the key to the application at runtime and restrict access only to the PowerAuth Server process.

### Switching to NO_ENCRYPTION

If you are upgrading a non-production environment, you may override the default encryption algorithm:

```
powerauth.server.db.master.encryption.algorithm=NO_ENCRYPTION
```

When using `NO_ENCRYPTION`, no database encryption keys are required, and sensitive values will be stored in plaintext.

### Legacy Encryption Algorithm Configuration

The `AES_HMAC` encryption algorithm is legacy and should not be used in PowerAuth server 2.0.0 or higher.
In case you used this encryption algorithm previously, keep the configured key in property `powerauth.server.db.master.encryption.key` to allow decryption of existing data.

## Database Changes

For convenience, you can use liquibase for your database migration.

For manual changes use SQL scripts:

- [PostgreSQL script](sql/postgresql/migration_1.10.0_2.0.0.sql)
- [Oracle script](sql/oracle/migration_1.10.0_2.0.0.sql)
- [MSSQL script](sql/mssql/migration_1.10.0_2.0.0.sql)

### Added new columns for cryptography protocol version 4

Following columns were added for keys used in cryptography protocol version 4:

* A new column `device_public_keys` has been added to the `pa_activation` table to store device public keys for new cryptography algorithms.
* A new column `server_private_keys` has been added to the `pa_activation` table to store server private keys for new cryptography algorithms.
* A new column `server_private_keys_encryption` has been added to the `pa_activation` table to configure encryption of private keys.
* A new column `server_public_keys` has been added to the `pa_activation` table to store server public keys for new cryptography algorithms.
* A new column `shared_secret` has been added to the `pa_activation` table to store share secret for new cryptography algorithms.
* A new column `shared_secret_encryption` has been added to the `pa_activation` table to configure encryption of shared secret values.
* A new column `confirmation_pending` has been added to the `pa_activation` table to store whether activation confirmation is pending.
* A new column `upgrade_confirmation_pending` has been added to the `pa_activation` table to store whether activation upgrade confirmation is pending.
* A new column `master_private_keys` has been added to the `pa_master_keypair` table to store master private keys for new cryptography algorithms.
* A new column `master_public_keys` has been added to the `pa_master_keypair` table to store master public keys for new cryptography algorithms.

Following columns were added for dynamic keys used in cryptography protocol version 4:

* A new column `biometric_factor_enabled` has been added to the `pa_activation` table to track whether biometric factor is enabled.
* A new column `biometric_factor_key` has been added to the `pa_activation` table to store current biometric factor key.
* A new column `biometric_factor_key_next` has been added to the `pa_activation` table to store next biometric factor key.
* A new column `knowledge_factor_key` has been added to the `pa_activation` table to store current knowledge factor key.
* A new column `knowledge_factor_key_next` has been added to the `pa_activation` table to store next knowledge factor key.

### Added new columns for activation spawn or move

The columns `parent_activation_id` and `transfer_type` were added to the `pa_activation` table to track activation spawn or move.

## Updated Package Names

Package names in Java code have been updated from historical `io.getlime` to `com.wultra`. Please update package imports in your source code which uses any `io.getlime` packages from PowerAuth server.

## REST API Changes

### Updated Validations in REST API

We have unified validations in PowerAuth server REST API. The error code returned for failed request validations is always `ERR0024`. As a side effect, the error code `ERR0002` used for case when no application ID was set in request is no longer returned.

The validation of requests is now stricter and more complete to ensure data integrity. In case you get the `ERR0024` error in your integration with PowerAuth server, please make sure the requests contain all parameters, as seen in REST API documentation available at `http[s]://[hostname]:[port]/powerauth-java-server/swagger-ui/index.html`.

### Removed Recovery Code Functionality

The recovery code feature has been removed from the REST API and services due to its insufficient protection against social engineering attacks.

Following error codes are no longer used:

| Error Code | Error Message                                                                                                      | Note |
|------------|--------------------------------------------------------------------------------------------------------------------|------|
| ERR0025    | Recovery code already exists.                                                                                      | Could not generate recovery code because a valid recovery code already exists. |
| ERR0026    | Too many failed attempts to generate recovery code.                                                                | In order to uniquely identify a recovery code, a random recovery code (4x5 characters in Base32 encoding) is generated. In a very unlikely case of a collision, server attempts to generate a new one, at most 10 times. When the new recovery code generation fails 10 times, this error is returned. |
| ERR0027    | Recovery code was not found.                                                                                       | An action was attempted on a recovery code which does not exist. |
| ERR0028    | Invalid recovery code.                                                                                             | Used combination of recovery code and PUK is invalid. |
| ERR0029    | Invalid recovery configuration.                                                                                    | Recovery code configuration is missing or incomplete. |

Following endpoints are no longer available:

- `POST /rest/v3/recovery/revoke`
- `POST /rest/v3/recovery/lookup`
- `POST /rest/v3/recovery/create`
- `POST /rest/v3/recovery/confirm`
- `POST /rest/v3/recovery/config/update`
- `POST /rest/v3/recovery/config/detail`
- `POST /rest/v3/activation/recovery/create`

### Updated Operation Data

Callback property `signatureType` name was changed to `authenticationCodeType` for operation callbacks. Please check that services processing operation callbacks do not rely on this property, otherwise update the property name.

Audit records for operation callbacks have also been updated to reflect the property change from `signatureType` to `authenticationCodeType`.

### Init Activation Request

New attributes `parentActivationId` and `transferType` have been introduced to track activation spawn or move.
It may be passed to the init activation request and later on be available in the activation detail.

### New Error Codes

The following error codes were added. These errors occur when cryptography algorithm support is disabled or requested cryptography version is not supported.

| Error Code | Error Message                                   | Note                                                                                        |
|------------|-------------------------------------------------|---------------------------------------------------------------------------------------------|
| ERR0046    | Cryptography algorithm is not supported.        | In case the crytography algorithm is not supported because of application configuration.    |
| ERR0047    | Cryptography protocol version is not supported. | In case the cryptography protocol version is not supported because of global configuration. |
|            |                                                 |                                                                                             |

These errors may be returned during REST API calls which use cryptography based on PowerAuth server configuration.

### Updated MAC Token Request Timestamp Validations

We have unified validations in PowerAuth server REST API. The error code returned for failed MAC token request timestamp validation is always `ERR0024`. As a side effect, error codes `ERR0030` and `ERR0044` used for the case when MAC token request timestamp validation fails are no longer returned.

## Configuration Updates

Following property names were changed:
- `powerauth.service.crypto.signatureMaxFailedAttempts` is now `powerauth.service.crypto.authenticationCodeMaxFailedAttempts`
- `powerauth.service.crypto.signatureValidationLookahead` is now `powerauth.service.crypto.authenticationCodeValidationLookahead`
- `powerauth.service.crypto.offlineSignatureComponentLength` is now `powerauth.service.crypto.offlineAuthenticationCodeComponentLength`

Usually there is no reason to change these configuration properties, default values are used in most of the deployments. Please double-check if this change affects existing deployments.

New configuration property was added:
- `powerauth.service.crypto.minSupportedProtocolVersion` - configures the minimum version of protocol which is supported by the server. The version `3` is supported by default, and it can be disabled by switching this value to `4`.

Following configuration properties were removed:
- `powerauth.service.recovery.maxFailedAttempts` - removed due to removed recovery functionality
- `powerauth.service.token.timestamp.validity` - token validity unified with request expiration validation
