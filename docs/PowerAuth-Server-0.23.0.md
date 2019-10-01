# Migration from 0.22.0 to 0.23.0

This guide contains instructions for migration from PowerAuth Server version `0.22.0` to version `0.23.0`.

## Database Changes

Following DB changes occurred between version 0.22.0 and 0.23.0:
- Table `pa_application` - added not null constraint to column `name`, inserted default `application_%id` where null
- Table `pa_application` - added unique index constraint to column `name`
  - This index is mandatory. The script will fail when there are already duplicated names. In such case ensure unique
  values manually and repeat adding the unique index constraint.

Migration script for Oracle:
```sql
UPDATE "PA_APPLICATION" SET NAME = CONCAT('application_', id) WHERE NAME IS NULL;
ALTER TABLE "PA_APPLICATION" ALTER COLUMN NAME SET NOT NULL;
CREATE UNIQUE INDEX PA_APPLICATION_NAME ON PA_APPLICATION(NAME);
```

Migration script for MySQL:
```sql
UPDATE `pa_application` SET `name` = CONCAT('application_', `id`) WHERE `name` IS NULL;
ALTER TABLE `pa_application` ALTER COLUMN `name` SET NOT NULL;
CREATE UNIQUE INDEX `pa_application_name` ON `pa_application`(`name`);
```

Migration script for PostgreSQL:
```sql
UPDATE "pa_application" SET name = CONCAT('application_', id) WHERE name IS NULL;
ALTER TABLE "pa_application" ALTER COLUMN name SET NOT NULL;
CREATE UNIQUE INDEX PA_APPLICATION_NAME ON PA_APPLICATION(NAME);
```

## PowerAuth Protocol Version 3.1

PowerAuth protocol version `3.1` support has been introduced in PowerAuth server version `0.23.0`. 

The main changes in PowerAuth protocol are following:
- Improved information entropy in PowerAuth online signatures. The signature is now encoded into BASE64 instead of decimal string.
- Improved protection of encrypted status blob against possible replay attacks. 

The changes of cryptography are documented in details in the [powerauth-crypto](https://github.com/wultra/powerauth-crypto) project. 

### SOAP Interface Changes

PowerAuth server in version `0.23.0` slightly changed SOAP interface for protocol version `3` (namespace `http://getlime.io/security/powerauth/v3`):

- `VerifySignatureRequest` request object has now required parameter `signatureVersion`. The client must provide the version of signature obtained from `X-PowerAuth-Authorization` header.
- `VaultUnlockRequest` request object has now required parameter `signatureVersion`. The client must provide the version of signature obtained from `X-PowerAuth-Authorization` header.
- `GetActivationStatusRequest` request object has now new optional parameter `challenge`, which is now provided by `V3.1` mobile clients.
- `GetActivationStatusResponse` response object has now new optional parameter `encryptedStatusBlobNonce`, which is provided only if `challenge` in request is present.

You can access the WSDL files in following URLs:
- version `3`: `http://localhost:8080/powerauth-java-server/soap/serviceV3.wsdl`
- version `2`: `http://localhost:8080/powerauth-java-server/soap/serviceV2.wsdl`

### Client API Changes

Both Spring and Axis2 clients have been updated to support version `3.1` of PowerAuth protocol. The most important change is in the method which provides information about the activation status:

- `getActivationStatus(activationId)` method no longer provides `encryptedStatusBlob` in the response, so it's no longer usable for PowerAuth standard RESTful API implementation.
- `getActivationStatusWithEncryptedStatusBlob(activationId, challenge)` is a new method that returns an activation information, together with the `encryptedStatusBlob` (and `encryptedStatusBlobNonce`, if `V3.1` mobile client is getting the status)

The reason for the change is that the original function is no longer usable for PowerAuth standard RESTful API implementation purposes, because the `challenge` parameter is now required for `V3.1` status blob encryption.