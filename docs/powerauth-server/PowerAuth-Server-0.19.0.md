# Migration from 0.18.0 to 0.19.0

This guide contains instructions for migration from PowerAuth Server version 0.18.0 to version 0.19.0.

## Database changes

Following DB changes occurred between version 0.18.0 and 0.19.0:

## New database columns

* Table `pa_activation` - added column `server_private_key_encryption` that indicates what application level encryption type is used to protect server private key.

Migration scripts are available for Oracle and MySQL.

DB migration script for Oracle:
```sql
--
--  Added Column SERVER_PRIVATE_KEY_ENCRYPTION in Table PA_ACTIVATION
--

ALTER TABLE PA_ACTIVATION ADD SERVER_PRIVATE_KEY_ENCRYPTION NUMBER(10,0) DEFAULT 0 NOT NULL;
```

DB migration script for MySQL:
```sql
--
--  Added column server_private_key_encryption in table pa_activation
--

ALTER TABLE `pa_activation` ADD COLUMN `server_private_key_encryption` INT(11) DEFAULT 0 NOT NULL;
```

### Migration of sequences on Oracle

In PowerAuth server versions up to 0.18.0 a single database sequence `HIBERNATE_SEQUENCE` was used for ID generation in most database tables (with exception of sequence `ACTIVATION_HISTORY_SEQ` introduced in release 0.18.0). It is preferable to use a dedicated sequence for generating IDs for different tables, thus in PowerAuth server version 0.19.0 this single sequence is migrated into multiple sequences.

The migration consists of following steps:

1. Create new database sequences

This step can be executed while PowerAuth server is running. The PL/SQL script below allows up to `10000` new records to be generated before PowerAuth 0.19.0 is deployed (most of these records are audit records for signature verification in table `PA_SIGNATURE_AUDIT`). Depending on the time required for the deployment of PowerAuth 0.19.0 you can increase the value of expected new database records to a value higher than `10000`.

```sql
DECLARE
  value INTEGER;
  value_history INTEGER;
BEGIN
  SELECT (HIBERNATE_SEQUENCE.nextval) + 10000
  INTO value
  FROM DUAL;

  SELECT (ACTIVATION_HISTORY_SEQ.nextval) + 10000
  INTO value_history
  FROM DUAL;

  -- Branch sequence PA_APPLICATION_SEQ from HIBERNATE_SEQUENCE
  execute immediate 'CREATE SEQUENCE PA_APPLICATION_SEQ MINVALUE ' || value || ' MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH ' || value || ' CACHE 20 NOORDER NOCYCLE';

  -- Branch sequence PA_APPLICATION_VERSION_SEQ from HIBERNATE_SEQUENCE
  execute immediate 'CREATE SEQUENCE PA_APPLICATION_VERSION_SEQ MINVALUE ' || value || ' MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH ' || value || ' CACHE 20 NOORDER NOCYCLE';

  -- Branch sequence PA_MASTER_KEYPAIR_SEQ from HIBERNATE_SEQUENCE
  execute immediate 'CREATE SEQUENCE PA_MASTER_KEYPAIR_SEQ MINVALUE ' || value || ' MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH ' || value || ' CACHE 20 NOORDER NOCYCLE';

  -- Branch sequence PA_SIGNATURE_AUDIT_SEQ from HIBERNATE_SEQUENCE
  execute immediate 'CREATE SEQUENCE PA_SIGNATURE_AUDIT_SEQ MINVALUE ' || value || ' MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH ' || value || ' CACHE 20 NOORDER NOCYCLE';

  -- Create new sequence PA_ACTIVATION_HISTORY_SEQ with value from ACTIVATION_HISTORY_SEQ
  execute immediate 'CREATE SEQUENCE PA_ACTIVATION_HISTORY_SEQ MINVALUE ' || value_history || ' MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH ' || value_history || ' CACHE 20 NOORDER NOCYCLE';

end;
/
```

In case you create the sequences by a different user than owner of the PowerAuth schema, grant privileges on these sequences to the user used for PowerAuth (change `powerauth` to actual DB schema name in case it differs in your deployment):
```sql
GRANT ALL PRIVILEGES ON powerauth.PA_APPLICATION_SEQ TO powerauth;
GRANT ALL PRIVILEGES ON powerauth.PA_APPLICATION_VERSION_SEQ TO powerauth;
GRANT ALL PRIVILEGES ON powerauth.PA_MASTER_KEYPAIR_SEQ TO powerauth;
GRANT ALL PRIVILEGES ON powerauth.PA_SIGNATURE_AUDIT_SEQ TO powerauth;
GRANT ALL PRIVILEGES ON powerauth.PA_ACTIVATION_HISTORY_SEQ TO powerauth;
```

2. Deploy PowerAuth version 0.19.0.

The application is restarted during deployment. Once the application is deployed, new database sequences created in script from step 1 are used.

3. Drop old sequences.

Once PowerAuth version 0.19.0 is deployed, the old sequences are no longer required and can be dropped. However, if you want to be able do downgrade PowerAuth you can keep the sequences in database until version 0.19.0 is fully tested.

```sql
  -- Drop old sequence HIBERNATE_SEQUENCE
  DROP SEQUENCE HIBERNATE_SEQUENCE;
  -- Drop old sequence ACTIVATION_HISTORY_SEQ
  DROP SEQUENCE ACTIVATION_HISTORY_SEQ;
```

## Configuration changes

### Master DB encryption key

We implemented application level encryption for server private keys. 

Encryption of private keys can be enabled by setting the following property in`application.properties` (don't reuse this exact key):

```
powerauth.server.db.master.encryption.key=MTIzNDU2Nzg5MDEyMzQ1Ng==
```

When the property value is empty (default), encryption is not performed.

For additional details, see: [Encrypting Records in Database](./Encrypting-Records-in-Database.md).

## Java 9 support

PowerAuth version 0.19.0 supports Java 9. However, due to the short support cycle of Java 9 we recommend to use Java 8 in production for PowerAuth and wait with Java upgrade for Java 11 which will be the next long-term support release.

## JMX disabled by default

Spring JMX (Java Management Extensions) is now disabled by default. This change slightly decreases startup time of PowerAuth and avoids unecessary exposing of information about PowerAuth data sources. 

If you want to enable Spring JMX, you can re-enable it using configuration property:

```properties
spring.jmx.enabled=true
```

## Upgrade to Spring boot 2

The whole PowerAuth stack now uses Spring boot 2. In case you integrate your application with PowerAuth using client APIs we recommend to migrate your application to Spring boot 2 to avoid compatiblity issues.

## Improved logging of PowerAuth

The whole PowerAuth stack now logs additional information on INFO log level. Depending on number of requests from mobile devices the log files can increase in size. 

In case you run into disk space issues due to log size, we recommend you take one of the following actions:
* Configure log rotation in web container which hosts PowerAuth.
* Change the default log level to `WARN` using configuration property:
```properties
logging.level.root=WARN
```
* Allocate more disk space for logs.

## Offline signature endpoints

In previous releases, there was only one common endpoint for offline signature payloads: 
* `createOfflineSignaturePayload`

In release 0.19.0 this endpoint has been split into two endpoints depending on whether the signature is personalized or non-personalized:
* `createPersonalizedOfflineSignaturePayload`
* `createNonPersonalizedOfflineSignaturePayload` 

For more information about migration to the new endpoints, see [Offline Signatures](./Offline-Signatures.md).

## Updated error codes

Due to new functionality the list of [PowerAuth server error codes](./Server-Error-Codes.md) has been updated. If you are not using the error code list, you can ignore this change.