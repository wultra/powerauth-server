# Database Structure

<!-- TEMPLATE database -->

You can download DDL scripts for supported databases:

- [Oracle - Create Database Schema](./sql/oracle/create_schema.sql)
- [MySQL - Create Database Schema](./sql/mysql/create_schema.sql)
- [PostgreSQL - Create Database Schema](./sql/postgresql/create_schema.sql)

The drop scripts are available for supported databases:

- [Oracle - Drop Tables and Sequences](./sql/oracle/delete_schema.sql)
- [MySQL - Drop Tables](./sql/mysql/delete_schema.sql)
- [PostgreSQL - Drop Tables and Sequences](./sql/postgresql/delete_schema.sql)

See the overall database schema:

![Database structure](./images/arch_db_structure.png)

## ShedLock

The PowerAuth Server uses ShedLock to synchronize scheduled operations. You need to create appropriate DB table, i.e.:

```sql
CREATE TABLE shedlock (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    lock_until TIMESTAMP NOT NULL,
    locked_at TIMESTAMP NOT NULL,
    locked_by VARCHAR(255) NOT NULL
);
```

See the [SchedLock documentation](https://github.com/lukas-krecan/ShedLock#jdbctemplate) for the details.

## Table Documentation

This chapter explains individual tables and their columns. The column types are used from MySQL dialect, other databases use types that are equivalent (mapping is usually straight forward).

<!-- begin database table pa_application -->
### Applications Table

Stores applications used in the PowerAuth Server.

#### Schema

```sql
CREATE TABLE "pa_application"
(
    "id"                          INTEGER NOT NULL PRIMARY KEY,
    "name"                        VARCHAR(255) NOT NULL,
    "roles"                       VARCHAR(255)
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20) | autoincrement | Unique application ID. |
| name | VARCHAR(255) | - | Application name, for example "Mobile Banking". |
<!-- end -->

<!-- begin database table pa_application_version -->
### Application Versions Table

Stores application versions for the applications stored in `pa_application` table.

#### Schema

```sql
CREATE TABLE "pa_application_version"
(
    "id"                 INTEGER NOT NULL PRIMARY KEY,
    "application_id"     INTEGER NOT NULL,
    "application_key"    VARCHAR(255),
    "application_secret" VARCHAR(255),
    "name"               VARCHAR(255),
    "supported"          BOOLEAN
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20)  | primary key, autoincrement | Unique application version identifier. |
| application_id | BIGINT(20)  | foreign key: pa\_application.id | Related application ID. |
| name | VARCHAR(255) | - | Version name. |
| application_key | VARCHAR(255) | index | Application key related to this version. Should be indexed to allow a fast lookup, since this is an identifier client applications use. |
| application_secret | VARCHAR(255) | - | Application secret related to this version. |
| supported | INT(11) | - | Flag indicating if this version is supported or not (0 = not supported, 1..N = supported) |
<!-- end -->

<!-- begin database table pa_activation -->
### Activations Table

Stores activations. Activation is a unit associating signature / transport and encryption keys to a specific user and application.

#### Schema

```sql
CREATE TABLE "pa_activation"
(
    "activation_id"                 VARCHAR(37) NOT NULL PRIMARY KEY,
    "application_id"                INTEGER NOT NULL,
    "user_id"                       VARCHAR(255) NOT NULL,
    "activation_name"               VARCHAR(255),
    "activation_code"               VARCHAR(255),
    "activation_status"             INTEGER NOT NULL,
    "activation_otp"                VARCHAR(255),
    "activation_otp_validation"     INTEGER DEFAULT 0 NOT NULL,
    "blocked_reason"                VARCHAR(255),
    "counter"                       INTEGER NOT NULL,
    "ctr_data"                      VARCHAR(255),
    "device_public_key_base64"      VARCHAR(255),
    "extras"                        VARCHAR(255),
    "platform"                      VARCHAR(255),
    "device_info"                   VARCHAR(255),
    "flags"                         VARCHAR(255),
    "failed_attempts"               INTEGER NOT NULL,
    "max_failed_attempts"           INTEGER DEFAULT 5 NOT NULL,
    "server_private_key_base64"     VARCHAR(255) NOT NULL,
    "server_private_key_encryption" INTEGER DEFAULT 0 NOT NULL,
    "server_public_key_base64"      VARCHAR(255) NOT NULL,
    "timestamp_activation_expire"   TIMESTAMP (6) NOT NULL,
    "timestamp_created"             TIMESTAMP (6) NOT NULL,
    "timestamp_last_used"           TIMESTAMP (6) NOT NULL,
    "timestamp_last_change"         TIMESTAMP (6),
    "master_keypair_id"             INTEGER,
    "version"                       INTEGER DEFAULT 2
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| activation_id  | VARCHAR(37) | primary key, UUID (level 4) | Unique activation ID. Uses UUID Level 4 format, for example "099e5e30-47b1-41c7-b49b-3bf28e811fca". |
| activation_code | VARCHAR(255) | index | Activation code used during the activation process. Uses 4x5 characters in Base32 encoding separated by a "-" character, for example "KA4PD-RTIE2-KOP3U-H53EA". |
| activation_otp | VARCHAR(255) | - | Activation OTP value |
| activation_otp_validation | INT(11) | - | Activation OTP validation, can be one of following values:<br><br>0 - NONE<br>1 - ON_KEY_EXCHANGE<br>2 - ON_COMMIT |
| activation_status  | INT(11) | - | Activation status, can be one of following values:<br><br>1 - CREATED<br>2 - PENDING_COMMIT<br>3 - ACTIVE<br>4 - BLOCKED<br>5 - REMOVED |
| blocked_reason | VARCHAR(255) | - | Reason why activation is blocked (used when activation_status = 4, BLOCKED). |
| activation_name  | VARCHAR(255 | - | Name of the activation, typically a name of the client device, for example "John's iPhone 6" |
| application_id  | BIGINT(20) | foreign key: pa\_application.id | Associated application ID. |
| user_id  | VARCHAR(255) | index | Associated user ID. |
| extras  | TEXT | - | Any application specific information. |
| counter  | BIGINT(20) | - | Activation counter. |
| ctr_data | VARCHAR(255) | - | Activation hash based counter data. |
| device_public_key_base64  | TEXT | - | Device public key, encoded in Base64 encoding. |
| failed_attempts  | BIGINT(20) | - | Number of failed signature verification attempts. |
| max_failed_attempts | BIGINT(20) | - | Number of maximum allowed failed signature verification attempts. After value of "failed_attempts" matches this value, activation becomes blocked (activation_status = 4, BLOCKED) |
| server_private_key_base64 | TEXT | - | Server private key, encoded as Base64 |
| server_private_key_encryption | INT(11) | - | Indication whether server private key is encrypted (0 = no encryption, 1 = AES_HMAC)
| server_public_key_base64 | TEXT | - | Server public key, encoded as Base64 |
| master_keypair_id | BIGINT(20) | foreign key: pa\_master\_keypair.id | Master Key Pair identifier, used during the activation process |
| timestamp_created | DATETIME | - | Timestamp of the record creation. |
| timestamp_activation_expire | DATETIME | - | Timestamp until which the activation must be committed. In case activation is not committed until this period, it will become REMOVED. |
| timestamp_last_used | DATETIME | - | Timestamp of the last signature verification attempt. |
| timestamp_last_change | DATETIME | - | Timestamp of the last signature verification attempt. |
| version | BIGINT(2) | - | Cryptography protocol version. |
| platform | VARCHAR(255) | - | User device platform. |
| device_info | VARCHAR(255) | - | User device information. |
<!-- end -->

<!-- begin database table pa_master_keypair -->
### Master Key Pair Table

Stores master key pairs associated with applications and used during the activation process.

#### Schema

```sql
CREATE TABLE "pa_master_keypair"
(
    "id"                            INTEGER NOT NULL PRIMARY KEY,
    "application_id"                INTEGER NOT NULL,
    "master_key_private_base64"     VARCHAR(255) NOT NULL,
    "master_key_public_base64"      VARCHAR(255) NOT NULL,
    "name"                          VARCHAR(255),
    "timestamp_created"             TIMESTAMP (6) NOT NULL
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20) | primary key, autoincrement | Unique master key pair ID. |
| application_id | BIGINT(20) | foreign key: pa\_application.id | Associated application ID. |
| name | VARCHAR(255) | - | Name of the key pair. |
| master_key_private_base64 | TEXT | - | Private key encoded as Base64 |
| master_key_public_base64 | TEXT | - | Public key encoded as Base64 |
| timestamp_created | DATETIME | - | Timestamp of creation. |
<!-- end -->

<!-- begin database table pa_signature_audit -->
### Signature Audit Records Table

Stores the records with values used for attempts for the signature validation.

#### Schema

```sql
CREATE TABLE "pa_signature_audit"
(
    "id"                  BIGINT NOT NULL PRIMARY KEY,
    "activation_id"       VARCHAR(37) NOT NULL,
    "activation_counter"  INTEGER NOT NULL,
    "activation_ctr_data" VARCHAR(255),
    "activation_status"   INTEGER,
    "additional_info"     VARCHAR(255),
    "data_base64"         TEXT,
    "note"                VARCHAR(255),
    "signature_type"      VARCHAR(255) NOT NULL,
    "signature"           VARCHAR(255) NOT NULL,
    "timestamp_created"   TIMESTAMP (6) NOT NULL,
    "valid"               BOOLEAN,
    "version"             INTEGER DEFAULT 2,
    "signature_version"   VARCHAR(255)
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20) | primary key, autoincrement | Unique record ID. |
| activation_id | BIGINT(20) | foreign key: pa\_activation.activation\_id | Associated activation ID. |
| activation_counter | BIGINT(20) | - | Activation counter at the moment of signature validation. |
| activation_ctr_data | BIGINT(2) | - | Activation hash based counter data at the moment of signature validation. |
| activation_status | INT(11) | - | Activation status at the moment of signature validation. |
| additional_info | VARCHAR(255) | - | Additional information related to the signature request in JSON format. |
| data_base64 | TEXT | - | Data passed as the base for the signature, encoded as Base64. |
| signature_type | VARCHAR(255) | - | Requested type of the signature. |
| signature | VARCHAR(255) | - | Provided value of the signature. |
| valid | INT(11) | - | Flag indicating if the provided signature was valid. |
| note | TEXT | - | Additional information about the validation result. |
| timestamp_created | DATETIME | index | A timestamp of the validation attempt. |
| version | BIGINT(2) | - | PowerAuth protocol version. |
<!-- end -->

<!-- begin database table pa_integration -->
### Integration Credentials Table

Stores credentials for applications that integrate with PowerAuth Server.

#### Schema

```sql
CREATE TABLE "pa_integration"
(
    "id"                 VARCHAR(37) NOT NULL PRIMARY KEY,
    "name"               VARCHAR(255),
    "client_token"       VARCHAR(37) NOT NULL,
    "client_secret"      VARCHAR(37) NOT NULL
);
```

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

#### Schema

```sql
CREATE TABLE "pa_application_callback"
(
    "id"                 VARCHAR(37) NOT NULL PRIMARY KEY,
    "application_id"     INTEGER NOT NULL,
    "name"               VARCHAR(255),
    "callback_url"       TEXT NOT NULL,
    "type"               VARCHAR(64) DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL,
    "attributes"         TEXT NOT NULL
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | VARCHAR(37) | primary key | Unique callback URL identifier, UUID Level 4 format. |
| application_id | BIGINT(20) | foreign key: pa\_application.id | Associated application ID. |
| name | VARCHAR(255) | - | Callback name, anything that visually identifies the callback purpose. |
| callback_url | TEXT | - | Callback URL value, any URL that can receive activation update callback. |
| type | VARCHAR(64) | - | Callback type: `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`. |
| attributes | TEXT | - | Callback attributes as a key-value map, serialized into JSON. |
<!-- end -->

<!-- begin database table pa_token -->
### Token Store Table

Stores tokens used for token-based authentication.

#### Schema

```sql
CREATE TABLE "pa_token"
(
    "token_id"           VARCHAR(37) NOT NULL PRIMARY KEY,
    "token_secret"       VARCHAR(255) NOT NULL,
    "activation_id"      VARCHAR(255) NOT NULL,
    "signature_type"     VARCHAR(255) NOT NULL,
    "timestamp_created"  TIMESTAMP (6) NOT NULL
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| token_id | VARCHAR(37) | primary key | Unique identifier of the token. |
| token_secret | VARCHAR(255) | - | Secret value used for computing the token digest. |
| activation_id | VARCHAR(37) | foreign key: pa\_activation.activation_id | Reference to associated activation. |
| signature_type | VARCHAR(255) | - | Type of the signature that was used to issue this token. |
| timestamp_created | DATETIME | - | Timestamp of the record creation. |
<!-- end -->

<!-- begin database table pa_activation_history -->
### Activation History Table

Stores a log of activation changes.

#### Schema

```sql
CREATE TABLE "pa_activation_history"
(
    "id"                 BIGINT NOT NULL PRIMARY KEY,
    "activation_id"      VARCHAR(37) NOT NULL,
    "activation_status"  INTEGER,
    "event_reason"       VARCHAR(255),
    "external_user_id"   VARCHAR(255),
    "timestamp_created"  TIMESTAMP (6) NOT NULL
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | INT(37) | primary key | Unique record ID. |
| activation_id | VARCHAR(37) | foreign key: pa\_activation.activation_id | Reference to associated activation. |
| activation_status | INT(11) | index | Activation status, can be one of following values:<br><br>1 - CREATED<br>2 - PENDING_COMMIT<br>3 - ACTIVE<br>4 - BLOCKED<br>5 - REMOVED |
| event_reason | VARCHAR(255) | - | Reason why activation was changed. |
| external_user_id | VARCHAR(255) | - | External user ID of user who caused change of the activation (e.g. banker user ID). In case the value is null the change was caused by the user associated with the activation. |
| timestamp_created | DATETIME | - | Timestamp of the record creation. |
<!-- end -->

<!-- begin database table pa_recovery_code -->
### Recovery Code Table

Stores information about recovery codes.

#### Schema

```sql
CREATE TABLE "pa_recovery_code" (
    "id"                    BIGINT NOT NULL PRIMARY KEY,
    "recovery_code"         VARCHAR(23) NOT NULL,
    "application_id"        INTEGER NOT NULL,
    "user_id"               VARCHAR(255) NOT NULL,
    "activation_id"         VARCHAR(37),
    "status"                INTEGER NOT NULL,
    "failed_attempts"       INTEGER DEFAULT 0 NOT NULL,
    "max_failed_attempts"   INTEGER DEFAULT 10 NOT NULL,
    "timestamp_created"     TIMESTAMP (6) NOT NULL,
    "timestamp_last_used"   TIMESTAMP (6),
    "timestamp_last_change" TIMESTAMP (6)
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | INT(37) | primary key | Unique record ID. |
| recovery_code | VARCHAR(23) | index | Recovery code used for recovering an activation. Uses 4x5 characters in Base32 encoding separated by a "-" character, for example "KA4PD-RTIE2-KOP3U-H53EA". |
| application_id | BIGINT(20)  | foreign key: pa\_application.id | Related application ID. |
| user_id  | VARCHAR(255) | index | Associated user ID. |
| activation_id | VARCHAR(37) | foreign key: pa\_activation.activation_id | Reference to associated activation. |
| status  | INT(11) | - | Recovery code status, can be one of following values:<br><br>1 - CREATED<br>2 - ACTIVE<br>3 - BLOCKED<br>4 - REVOKED |
| failed_attempts  | BIGINT(20) | - | Number of failed activation recovery attempts. |
| max_failed_attempts | BIGINT(20) | - | Number of maximum allowed failed activation recovery attempts. After value of "failed_attempts" matches this value, recovery code becomes blocked (status = 3, BLOCKED) |
| timestamp_created | DATETIME | - | Timestamp of record creation. |
| timestamp_last_used | DATETIME | - | Timestamp of record last usage. |
| timestamp_last_change | DATETIME | - | Timestamp of record last change. |
<!-- end -->

<!-- begin database table pa_recovery_puk -->
### Recovery PUK Table

Stores information about recovery PUKs.

#### Schema

```sql
CREATE TABLE "pa_recovery_puk" (
    "id"                    BIGINT NOT NULL PRIMARY KEY,
    "recovery_code_id"      BIGINT NOT NULL,
    "puk"                   VARCHAR(255),
    "puk_encryption"        INTEGER DEFAULT 0 NOT NULL,
    "puk_index"             BIGINT NOT NULL,
    "status"                INTEGER NOT NULL,
    "timestamp_last_change" TIMESTAMP (6)
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | INT(37) | primary key | Unique record ID. |
| recovery_code_id | INT(37) | foreign key: pa_recovery_code.id, index | Related recovery code. |
| puk | VARCHAR(255) | - | Recovery PUK value (optionally encrypted). |
| puk_encryption | INT(11) | - | Encryption type for PUK (0 = NO_ENCRYPTION, 1 = AES_HMAC) |
| puk_index | INT(11) | index | Index of the PUK (value starts by 1). |
| status | INT(11) | - | Recovery PUK status, can be one of following values: <br><br>1 - VALID<br>2 - USED<br>3 - INVALID |
| timestamp_last_change | DATETIME | - | Timestamp of record last change. |
<!-- end -->

<!-- begin database table pa_recovery_config -->
### Recovery Configuration Table

Stores configuration of activation recovery and recovery postcards.

#### Schema

```sql
CREATE TABLE "pa_recovery_config" (
    "id"                              INTEGER NOT NULL PRIMARY KEY,
    "application_id"                  INTEGER NOT NULL,
    "activation_recovery_enabled"     BOOLEAN NOT NULL DEFAULT FALSE,
    "recovery_postcard_enabled"       BOOLEAN NOT NULL DEFAULT FALSE,
    "allow_multiple_recovery_codes"   BOOLEAN NOT NULL DEFAULT FALSE,
    "postcard_private_key_base64"     VARCHAR(255),
    "postcard_public_key_base64"      VARCHAR(255),
    "remote_public_key_base64"        VARCHAR(255),
    "postcard_priv_key_encryption"    INTEGER DEFAULT 0 NOT NULL
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | INT(37) | primary key | Unique record ID. |
| application_id | BIGINT(20)  | foreign key: pa\_application.id | Related application ID. |
| activation_recovery_enabled | INT(1) | - | Whether activation recovery is enabled. |
| recovery_postcard_enabled | INT(1) | - | Whether recovery postcard is enabled. |
| allow_multiple_recovery_codes | INT(1) | - | Whether multiple recovery codes are allowed per user. |
| postcard_private_key_base64 | VARCHAR(255) | - | Base64 encoded EC server private key for recovery postcard. |
| postcard_public_key_base64 | VARCHAR(255) | - | Base64 encoded EC server public key for recovery postcard. |
| remote_public_key_base64 | VARCHAR(255) | - | Base64 encoded EC printing center public key for recovery postcard. |
<!-- end -->

<!-- begin database table pa_operation -->
### Operations

Table stores operations, i.e., the login attempts or payment approvals, that are created in external systems.

#### Schema

```sql
CREATE TABLE "pa_operation" (
    "id"                    VARCHAR(37) NOT NULL PRIMARY KEY,
    "user_id"               VARCHAR(255) NOT NULL,
    "application_id"        BIGINT NOT NULL,
    "template_id"           BIGINT,
    "external_id"           VARCHAR(255),
    "operation_type"        VARCHAR(255) NOT NULL,
    "data"                  TEXT NOT NULL,
    "parameters"            TEXT,
    "status"                INTEGER NOT NULL,
    "signature_type"        VARCHAR(255) NOT NULL,
    "failure_count"         BIGINT DEFAULT 0 NOT NULL,
    "max_failure_count"     BIGINT NOT NULL,
    "timestamp_created"     TIMESTAMP NOT NULL,
    "timestamp_expires"     TIMESTAMP NOT NULL,
    "timestamp_finalized"   TIMESTAMP
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | varchar(37) | primary key | Unique operation ID. |
| user_id | varchar(255)  | - | Related user ID. |
| application_id | bigint | - | Related application ID. |
| template_id | bigint | - | Template ID used for creating the operation. |
| external_id | varchar(255) | - | Identifier in external system. |
| operation_type | varchar(255) | - | Name of the type of operation. |
| data | text | - | Data of the operation that enter the final signature. |
| parameters | text | - | JSON-encoded parameters that were used while creating the operation. |
| status | integer | - | Status of the operation. |
| signature_type | varchar(255) | - | Comma-separated list of allowed signature types. |
| failure_count | bigint | - | Number of already failed attempts to approve the operation. |
| max_failure_count | bigint | - | Maximum allowed number of failed attempts when approving the operation. |
| timestamp_created | timestamp | - | Timestamp of when the operation was created. |
| timestamp_expires | timestamp | - | Timestamp of when the operation will expire. |
| timestamp_finalized | timestamp | - | Timestamp of when the operation reached the terminal state (approved, rejected, expired, etc.). |
<!-- end -->

<!-- begin database table pa_operation_template -->
### Operation Templates

Table stores operation templates that are used while creating the operations.

#### Schema

```sql
CREATE TABLE "pa_operation_template" (
    "id"                    BIGINT NOT NULL PRIMARY KEY,
    "template_name"         VARCHAR(255) NOT NULL,
    "operation_type"        VARCHAR(255) NOT NULL,
    "data_template"         VARCHAR(255) NOT NULL,
    "signature_type"        VARCHAR(255) NOT NULL,
    "max_failure_count"     BIGINT NOT NULL,
    "expiration"            BIGINT NOT NULL
);
```

#### Columns

| Name | Type | Info | Note |
|------|------|---------|------|
| id | varchar(37) | primary key | Unique template ID. |
| template_name | varchar(255)  | - | Template name. |
| operation_type | varchar(255)  | - | Name of the type of operation. |
| data_template | varchar(255)  | - | Template string for the data that will enter signature later. |
| signature_type | varchar(255)  | - | Comma-separated list of allowed signature types. |
| max_failure_count | bigint | - | Maximum allowed number of failed attempts when approving the operation. |
| expiration | bigint | - | Operation expiration in seconds (300 = 5 minutes). |
<!-- end -->