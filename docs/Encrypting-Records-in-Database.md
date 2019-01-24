# Encrypting Records in Database

In order to improve the security of the keys stored in the database, we recommend taking following additional steps when configuring your database and database access.

## Transparent Data Encryption

As a basic security measure, we suggest using data encryption support of your database engine to protect the records stored in the database. Most of the database engines support the mechanism of "transparent data encryption", see for example:

- [Oracle](https://docs.oracle.com/en/database/oracle/oracle-database/12.2/asoag/asopart1.html)
- [PostgreSQL](https://www.postgresql.org/docs/11/encryption-options.html)
- [MySQL](https://dev.mysql.com/doc/mysql-secure-deployment-guide/5.7/en/secure-deployment-data-encryption.html)

## Additional Private Key Encryption

To separate database administrators from the access to the raw private keys, you can additionally encrypt server private keys in the database using an application level record encryption.

### Enabling Private Key Encryption

In order to enable the additional server private key encryption, you need to set the following property to the application:

```
powerauth.server.db.master.encryption.key=MTIzNDU2Nzg5MDEyMzQ1Ng==
```

The value of the key must be 16 random bytes, Base64 encoded.

### Note to Private Key Encryption Cryptography

In case additional private key encryption is enabled, PowerAuth Server uses application level encryption/decryption routines whenever storing/loading a `KEY_SERVER_PRIVATE` value takes place. For this purpose, a new key `MASTER_DB_ENCRYPTION_KEY` is introduced. Also, since there is the good old rule "Same data should result in different encrypted values", a random `IV` value for the encryption is generated and stored with the value for the purpose of a later decryption.

Pseudo-code for the encryption and decryption routines is following:

```java
public byte[] encrypt(byte[] orig, SecretKey derivedDbEncryptionKey) {
    byte[] iv = Bytes.random(16);
    byte[] encrypted = aes.encrypt(orig, iv, derivedDbEncryptionKey);
    byte[] record = iv.append(encrypted)
    return record;
}

public byte[] decrypt(byte[] record, SecretKey derivedDbEncryptionKey) {
    byte[] iv = record.byteRange(0, 16); // offset, length
    byte[] encrypted = record.byteRange(16, -1); // offset, remaining
    byte[] orig = aes.decrypt(encrypted, iv, derivedDbEncryptionKey);
    return orig;
}
```

In order to achieve a consistency between activation record and encrypted server private key (to prevent a partial record swap attack, where admin replaces part of the record with own known values), we pay special attention to how we derive the encryption key from `MASTER_DB_ENCRYPTION_KEY` in the above mentioned routines. The encryption key `DERIVED_DB_ENCRYPTION_KEY` is derived from the master DB encryption key `MASTER_DB_ENCRYPTION_KEY` using a [KDF_INTERNAL](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Basic-definitions.md) function, with a user ID and activation ID in concatenated String as a base for deriving the `index`, like so:

```java
public SecretKey deriveSecretKey(SecretKey masterDbEncryptionKey, String userId, String activationId) {
    // Use concatenated user ID and activation ID bytes as index for KDF_INTERNAL
    byte[] index = (userId + "&" + activationId).getBytes();
    // Derive secretKey from master DB encryption key using KDF_INTERNAL with constructed index
    return KDF_INTERNAL.deriveSecretKeyHmac(masterDbEncryptionKey, index);
}
```

### Note on the Backward Compatibility

Every database record carries an information about how it was created - with encryption or without encryption. In case you do not use encryption in the beginning, you can turn it on anytime later. However, the records that were created before you enabled the encryption will remain un-encrypted. You need to convert them manually in the database in case you need them encrypted.

More problematic situation is changing the master encryption key. The server currently has no easy way to re-encrypt the records with the new key and hence the conversion must be performed using a custom database migration.

**In case you lose the original master DB encryption key, there is no way to recover original data and your users will need to re-activate their mobile applications.**