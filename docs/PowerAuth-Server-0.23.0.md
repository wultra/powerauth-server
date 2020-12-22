# Migration from 0.22.0 to 0.23.0

This guide contains instructions for migration from PowerAuth Server version `0.22.0` to version `0.23.0`.

## Bouncy Castle Library Update to Version 1.64

Bouncy Castle library has been updated to version `1.64`. The newest version of Bouncy Castle library can be downloaded from: [https://www.bouncycastle.org/download/bcprov-jdk15on-164.jar](https://www.bouncycastle.org/download/bcprov-jdk15on-164.jar)

Installation on **Java 8**:
- Update Bouncy Castle library the `lib/ext` folder of the Java runtime

Installation on **Java 11**:
- Tomcat: update Bouncy Castle library in `CATALINA_HOME/lib`
- JBoss / Wildfly: update Bouncy Castle library global module
- Other web containers: follow instructions for installing a global library for the web container
- Standalone mode: PowerAuth Server can no longer be started from command line because of missing Bouncy Castle library in the war file. Contact us if you want to run PowerAuth Server in standalone mode.

For more details about installation of the library see [Installing Bouncy Castle](./Installing-Bouncy-Castle.md).

## Database Changes

Following DB changes occurred between version 0.22.0 and 0.23.0:
- Table `pa_application` - added not null constraint to column `name`, inserted default `application_id` where null
- Table `pa_application` - added unique index constraint to column `name`
  - This index is mandatory. The script will fail when there are already duplicated names. In such case ensure unique
  values manually and repeat adding the unique index constraint.

Migration script for Oracle:
```sql
UPDATE "PA_APPLICATION" SET NAME = CONCAT('application_', id) WHERE NAME IS NULL;
ALTER TABLE "PA_APPLICATION" MODIFY "NAME" NOT NULL;
CREATE UNIQUE INDEX "PA_APPLICATION_NAME" ON PA_APPLICATION(NAME);
ALTER TABLE "PA_SIGNATURE_AUDIT" ADD "SIGNATURE_VERSION" VARCHAR2(255 CHAR);
```

Migration script for MySQL:
```sql
UPDATE `pa_application` SET `name` = CONCAT('application_', `id`) WHERE `name` IS NULL;
ALTER TABLE `pa_application` MODIFY COLUMN `name` VARCHAR(255) NOT NULL;
CREATE UNIQUE INDEX `pa_application_name` ON `pa_application`(`name`);
ALTER TABLE `pa_signature_audit` ADD `signature_version` varchar(255);
```

Migration script for PostgreSQL:
```sql
UPDATE "pa_application" SET name = CONCAT('application_', id) WHERE name IS NULL;
ALTER TABLE "pa_application" ALTER COLUMN "name" SET NOT NULL;
CREATE UNIQUE INDEX "pa_application_name" ON PA_APPLICATION(NAME);
ALTER TABLE "pa_signature_audit" ADD "signature_version" VARCHAR(255);
```

## PowerAuth Protocol Version 3.1

PowerAuth protocol version `3.1` support has been introduced in PowerAuth server version `0.23.0`. 

The main changes in PowerAuth protocol are following:
- Improved information entropy in PowerAuth online signatures. The signature is now encoded into BASE64 instead of decimal string.
- Improved protection of encrypted status blob against possible replay attacks. 
- Improved protection of payload encrypted by our ECIES scheme.
- Improved protocol reliability by allowing the mobile client to synchronize its counter with the server.

The changes of cryptography are documented in details in the [powerauth-crypto](https://github.com/wultra/powerauth-crypto) project. 

### SOAP Interface Changes

PowerAuth server in version `0.23.0` slightly changed SOAP interface for protocol version `3` (namespace `http://getlime.io/security/powerauth/v3`):

- `VerifySignatureRequest` request object has now required parameter `signatureVersion`. The client must provide the version of signature obtained from `X-PowerAuth-Authorization` header.
- `VaultUnlockRequest` request object has now required parameter `signatureVersion`. The client must provide the version of signature obtained from `X-PowerAuth-Authorization` header.
- `GetActivationStatusRequest` request object has now new optional parameter `challenge`, which is now provided by `V3.1` mobile clients.
- `GetActivationStatusResponse` response object has now new optional parameter `encryptedStatusBlobNonce`, which is provided only if `challenge` in request is present.

The following request objects were updated due to changes in our ECIES encryption scheme. The optional parameter `nonce` must be provided for protocol `V3.1` and later: 

- `PrepareActivationRequest` request object now contains optional parameter `nonce`.
- `CreateActivationRequest` request object now contains optional parameter `nonce`.
- `VaultUnlockRequest` request object now contains optional parameter `nonce`.
- `CreateTokenRequest` request object now contains optional parameter `nonce`.
- `StartUpgradeRequest` request object now contains optional parameter `nonce`.
- `ConfirmRecoveryCodeRequest` request object now contains optional parameter `nonce`.
- `RecoveryCodeActivationRequest` request object now contains optional parameter `nonce`.


You can access the WSDL files in following URLs:
- version `3`: `http://localhost:8080/powerauth-java-server/soap/serviceV3.wsdl`
- version `2`: `http://localhost:8080/powerauth-java-server/soap/serviceV2.wsdl`

### Client API Changes

Both Spring and Axis2 clients have been updated to support version `3.1` of PowerAuth protocol. The most important change is in the method which provides information about the activation status:

- `getActivationStatus(activationId)` method no longer provides `encryptedStatusBlob` in the response, so it's no longer usable for PowerAuth standard RESTful API implementation.
- `getActivationStatusWithEncryptedStatusBlob(activationId, challenge)` is a new method that returns an activation information, together with the `encryptedStatusBlob` (and `encryptedStatusBlobNonce`, if `V3.1` mobile client is getting the status)

The reason for the change is that the original function is no longer usable for PowerAuth standard RESTful API implementation purposes, because the `challenge` parameter is now required for `V3.1` status blob encryption.

## Database record encryption

If you turned on additional database record encryption in any previous PowerAuth Server version (see [Encrypting Records in Database](Encrypting-Records-in-Database.md#additional-record-encryption)), please contact us at [support@wultra.com](mailto:support@wultra.com). The encryption scheme has been slightly changed, so we can help you with the migration.

## SOAP Endpoint Changes

### Revoking Recovery Codes on Activation Removal

We added an optional `revokeRecoveryCodes` attribute to [activation removal service call](WebServices-Methods.md#method-removeactivation). This flag indicates if recovery codes that are associated with removed activation should be also revoked. By default, the value of the flag is `false`, hence omitting the flag results in the same behavior as before this change. 
