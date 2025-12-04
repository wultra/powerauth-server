# Encrypting Records in Database

To improve protection of sensitive data stored in the database, such as master private keys, activation private keys, temporary keys, callback authentication, and other sensitive data, PowerAuth Server supports two layers of protection:

- Database-level encryption (transparent data encryption)
- Application-level per-record encryption

Both should be enabled in production deployments.

## Transparent Data Encryption

As a basic security measure, we suggest using data encryption support of your database engine to protect the records stored in the database. Most of the database engines support the mechanism of "transparent data encryption", see for example:

- [Oracle](https://docs.oracle.com/en/database/oracle/oracle-database/26/shard/using-transparent-data-encryption.html)
- [PostgreSQL](https://www.postgresql.org/docs/current/encryption-options.html)
- [MS SQL](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption)

## Additional Application Level Per-Record Encryption

To separate database administrators from the access to raw private records, you can additionally encrypt database records such as server private keys in the database using application level record encryption.

The algorithm `AEAD_KMAC` is the default database encryption algorithm. It uses:

* a 256-bit master DB encryption key
* KMAC-256 for per-record key derivation
* Authenticated encryption using an AEAD scheme based on AES-256

This provides high security with AES-256 encryption and KMAC-256 key derivation, which are resistant to known quantum attacks.

### Configuration Application Level Per-Record Encryption

To configure the additional database record encryption, you need to set the following property to the application:

```
powerauth.server.db.master.encryption.aead-kmac.key=[32 random bytes Base64 encoded, for example 'mC92FrUKjMCqIKW5qVOduxRlBeEQ+fLsQjPxf1k9ow8=']
```

<!-- begin box warning -->
In case you lose the original master DB encryption key, there is no way to recover original data and your users will need to re-activate their mobile applications.
<!-- end -->

The value of the key must be 32 random bytes, Base64 encoded.

The algorithm for application-level encryption is controlled by:

```
powerauth.server.db.master.encryption.algorithm=AEAD_KMAC
```

Allowed values:
- `NO_ENCRYPTION` - use for non-production environments only,
- `AES_HMAC` (legacy) - AES-16 with HMAC-based key derivation, do not use
- `AEAD_KMAC` (current) - encryption algorithm with AEAD using AES-256 for encryption and KMAC-256 for key derivation

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

### Using HashiCorp Vault

Instead of providing a hard-coded value of `powerauth.server.db.master.encryption.aead-kmac.key` in your application properties, you can also [use a HashiCorp Vault to store the database encryption key securely](./Using-HashiCorp-Vault.md). For high security environment, this is the preferred way of storing the database encryption key.

### Legacy Encryption Algorithm Configuration

The `AES_HMAC` encryption algorithm is legacy and should not be used in PowerAuth server 2.0.0 or higher.
In case you used this encryption algorithm previously, keep the configured key in property `powerauth.server.db.master.encryption.key` to allow decryption of existing data.

### Switching to NO_ENCRYPTION

If you are upgrading a non-production environment, you may override the default encryption algorithm:

```
powerauth.server.db.master.encryption.algorithm=NO_ENCRYPTION
```

When using `NO_ENCRYPTION`, no database encryption keys are required, and sensitive values will be stored in plaintext.


### Note on Private Key Encryption Cryptography

`AEAD-KMAC` encryption in PowerAuth Server uses a 32-byte master database key from which a unique per-record encryption key is derived using `KMAC-256`, with the derivation based on identity attributes such as user ID and activation ID (depending on the encrypted database column). Additional attributes are also used as associated data (AD) for the AEAD operation, binding each ciphertext to the specific record so that swapping or tampering causes decryption to fail. Encryption and decryption use the PowerAuth AEAD primitive (seal / open), producing authenticated ciphertext. This design guarantees confidentiality, integrity, and strong protection against record-level manipulation.

### Note on the Backward Compatibility

Every database record carries an information about how it was created - with encryption or without encryption. In case you do not use encryption in the beginning, you can turn it on anytime later. However, the records that were created before you enabled the encryption will remain un-encrypted. You need to convert them manually in the database in case you need them encrypted.

More problematic situation is changing the master encryption key. The server currently has no easy way to re-encrypt the records with the new key and hence the conversion must be performed using a custom database migration.