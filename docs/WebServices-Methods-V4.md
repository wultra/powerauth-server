# Web Services - Methods

This is reference documentation of the methods published by the PowerAuth Server REST services.

The REST service methods can be browsed using Swagger on deployed PowerAuth instance:

- http://localhost:8080/powerauth-java-server/swagger-ui.html

The following `v4` methods are published using the service:

- System Status
  - [getSystemStatus](#method-getsystemstatus)
  - [getErrorCodeList](#method-geterrorcodelist)
- Application Management
  - [getApplicationList](#method-getapplicationlist)
  - [getApplicationDetail](#method-getapplicationdetail)
  - [lookupApplicationByAppKey](#method-lookupapplicationbyappkey)
  - [createApplication](#method-createapplication)
  - [createApplicationVersion](#method-createapplicationversion)
  - [unsupportApplicationVersion](#method-unsupportapplicationversion)
  - [supportApplicationVersion](#method-supportapplicationversion)
  - [getApplicationConfig](#method-getapplicationconfig)
  - [createApplicationConfig](#method-createapplicationconfig)
  - [removeApplicationConfig](#method-removeapplicationconfig)
- Activation Management
  - [getActivationListForUser](#method-getactivationlistforuser)
  - [initActivation](#method-initactivation)
  - [prepareActivation](#method-prepareactivation)
  - [createActivation](#method-createactivation)
  - [updateActivationOtp](#method-updateactivationotp)
  - [updateActivationName](#method-updateactivationname)
  - [commitActivation](#method-commitactivation)
  - [confirmActivation](#method-confirmactivation)
  - [getActivationStatus](#method-getactivationstatus)
  - [removeActivation](#method-removeactivation)
  - [blockActivation](#method-blockactivation)
  - [unblockActivation](#method-unblockactivation)
  - [lookupActivations](#method-lookupactivations)
  - [updateStatusForActivations](#method-updatestatusforactivations)
- DSA Signature Verification
  - [signAsymmetric](#method-signasymmetric)
  - [verifyAsymmetricSignature](#method-verifyasymmetricsignature)
- JWT Signature Verification
  - [signJwt](#method-signjwt)
  - [verifyJwtSignature](#method-verifyjwtsignature)
- Offline Authentication
  - [createNonPersonalizedOfflineAuthPayload](#method-createnonpersonalizedofflineauthpayload)
  - [createPersonalizedOfflineAuthPayload](#method-createpersonalizedofflineauthpayload)
  - [verifyOfflineAuthentication](#method-verifyofflineauthentication)
- Token-Based Authentication
  - [createToken](#method-createtoken)
  - [validateToken](#method-validatetoken)
  - [removeToken](#method-removetoken)
- Vault Unlocking
  - [vaultUnlock](#method-vaultunlock)
- Audit Log
  - [getAuditLog](#method-getauditlog)
- Activation History
  - [getActivationHistory](#method-getactivationhistory)
- Integration Management
  - [createIntegration](#method-createintegration)
  - [getIntegrationList](#method-getintegrationlist)
  - [removeIntegration](#method-removeintegration)
- Callback URL Management
  - [createCallbackUrl](#method-createcallbackurl)
  - [updateCallbackUrl](#method-updatecallbackurl)
  - [getCallbackUrlList](#method-getcallbackurllist)
  - [removeCallbackUrl](#method-removecallbackurl)
- End-To-End Encryption
  - [extractEncryptor](#method-extractencryptor)
- Activation Versioning
  - [startUpgrade](#method-startupgrade)
  - [commitUpgrade](#method-commitupgrade)
- Activation Flags
  - [listActivationFlags](#method-listactivationflags)
  - [addActivationFlags](#method-addactivationflags)
  - [updateActivationFlags](#method-updateactivationflags)
  - [removeActivationFlags](#method-removeactivationflags)
- Application Roles
  - [listApplicationRoles](#method-listapplicationroles)
  - [addApplicationRoles](#method-addapplicationroles)
  - [updateApplicationRoles](#method-updateapplicationroles)
  - [removeApplicationRoles](#method-removeapplicationroles)
- Operations
  - [createOperation](#method-createoperation)
  - [operationDetail](#method-operationdetail)
  - [operationClaim](#method-operationclaim)
  - [findPendingOperationsForUser](#method-findpendingoperationsforuser)
  - [findAllOperationsForUser](#method-findalloperationsforuser)
  - [findAllOperationsByExternalId](#method-findalloperationsbyexternalid)
  - [cancelOperation](#method-canceloperation)
  - [approveOperation](#method-approveoperation)
  - [failApprovalOperation](#method-failapproveoperation)
  - [rejectOperation](#method-rejectoperation)
- Operation Templates
  - [createOperationTemplate](#method-createoperationtemplate)
  - [getAllTemplates](#method-getalltemplates)
  - [getTemplateDetail](#method-gettemplatedetail)
  - [updateOperationTemplate](#method-updateoperationtemplate)
  - [removeOperationTemplate](#method-removeoperationtemplate)
- Dynamic Factor Keys
  - [changePassword](#method-changepassword)
  - [addBiometry](#method-addbiometry)
  - [removeBiometry](#method-removebiometry)
- Temporary Keys
  - [createTemporaryKey](#method-createtemporarykey)
  - [removeTemporaryKey](#method-removetemporarykey)
- Telemetry
  - [report](#method-report)

## System status

Methods used for getting the PowerAuth Server system status.

### Method 'getSystemStatus'

Get the server status information.

#### Request

REST endpoint: `POST /rest/v4/status`

`GetSystemStatusRequest`

- _no attributes_

#### Response

`GetSystemStatusResponse`

| Type       | Name                     | Description                                                                                                                                                               |
|------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`   | `status`                 | A constant value "OK".                                                                                                                                                    |
| `String`   | `applicationName`        | A name of the application, the default value is `powerauth`. The value may be overriden by setting`powerauth.service.applicationName` property.                           |
| `String`   | `applicationDisplayName` | A human readable name of the application, default value is "PowerAuth Server". The value may be overriden by setting `powerauth.service.applicationDisplayName` property. |
| `String`   | `applicationEnvironment` | An identifier of the environment, by default, the value is empty. The value may be overriden by setting `powerauth.service.applicationEnvironment` property.              |
| `String`   | `version`                | Version of PowerAuth server.                                                                                                                                              |
| `String`   | `buildTime`              | Timestamp when the powerauth-server.war file was built.                                                                                                                   |
| `DateTime` | `timestamp`              | A current system timestamp.                                                                                                                                               |

### Method 'getErrorCodeList'

Get the list of all error codes that PowerAuth Server can return.

#### Request

REST endpoint: `POST /rest/v4/error/list`

`GetErrorCodeListRequest`

| Type     | Name       | Description          |
|----------|------------|----------------------|
| `String` | `language` | Language code (ISO). |

#### Response

`GetErrorCodeListResponse`

| Type      | Name     | Description             |
|-----------|----------|-------------------------|
| `Error[]` | `errors` | A collection of errors. |

`GetErrorCodeListResponse.Error`

| Type     | Name    | Description                             |
|----------|---------|-----------------------------------------|
| `String` | `code`  | A code of the error.                    |
| `String` | `value` | A localized message for the error code. |

## Application management

Methods related to the management of applications and application versions.

### Method 'getApplicationList'

Get list of all applications that are present in this PowerAuth Server instance.

#### Request

REST endpoint: `POST /rest/v4/application/list`

`GetApplicationListRequest`

- _no attributes_

#### Response

`GetApplicationListResponse`

| Type            | Name           | Description                         |
|-----------------|----------------|-------------------------------------|
| `Application[]` | `applications` | A collection of application objects |

`GetApplicationListRequest.Application`

| Type       | Name               | Description                       |
|------------|--------------------|-----------------------------------|
| `String`   | `applicationId`    | Application ID                    |
| `String[]` | `applicationRoles` | Roles assigned to the application |

### Method 'getApplicationDetail'

Get detail of application with given ID or name, including the list of versions.

#### Request

REST endpoint: `POST /rest/v4/application/detail`

`GetApplicationDetailRequest`

| Type     | Name            | Description       |
|----------|-----------------|-------------------|
| `String` | `applicationId` | An application ID |

#### Response

`GetApplicationDetailResponse`

| Type        | Name                  | Description                                          |
|-------------|-----------------------|------------------------------------------------------|
| `String`    | `applicationId`       | An application ID                                    |
| `String[]`  | `applicationRoles`    | Roles assigned to the application                    |
| `Version[]` | `versions`            | Collection of application versions                   |
| `String[]`  | `supportedAlgorithms` | Cryptography algorithms supproted by the application |

`GetApplicationDetailResponse.Version`

| Type      | Name                   | Description                                                                                                         |
|-----------|------------------------|---------------------------------------------------------------------------------------------------------------------|
| `String`  | `applicationVersionId` | An identifier of an application version                                                                             |
| `String`  | `applicationKey`       | A key (identifier) of an application, associated with given application version                                     |
| `String`  | `applicationSecret`    | An application secret associated with this version                                                                  |
| `String`  | `mobileSdkConfig`      | PowerAuth mobile SDK configuration which includes encoded master public key, application key and application secret |
| `boolean` | `supported`            | Flag indicating if this application is supported                                                                    |

### Method 'lookupApplicationByAppKey'

Find application using application key.

#### Request

REST endpoint: `POST /rest/v4/application/detail/version`

`LookupApplicationByAppKeyRequest`

| Type     | Name             | Description                                                                     |
|----------|------------------|---------------------------------------------------------------------------------|
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |

#### Response

`LookupApplicationByAppKeyResponse`

| Type     | Name            | Description                     |
|----------|-----------------|---------------------------------|
| `String` | `applicationId` | An identifier of an application |

### Method 'createApplication'

Create a new application with given name.

#### Request

REST endpoint: `POST /rest/v4/application/create`

`CreateApplicationRequest`

| Type     | Name            | Description       |
|----------|-----------------|-------------------|
| `String` | `applicationId` | An application ID |

#### Response

`CreateApplicationResponse`

| Type       | Name               | Description                       |
|------------|--------------------|-----------------------------------|
| `String`   | `applicationId`    | An identifier of an application   |
| `String[]` | `applicationRoles` | Roles assigned to the application |

### Method 'createApplicationVersion'

Create a new application version with given name for a specified application.

#### Request

REST endpoint: `POST /rest/v4/application/version/create`

`CreateApplicationVersionRequest`

| Type     | Name                   | Description                       |
|----------|------------------------|-----------------------------------|
| `String` | `applicationId`        | An identifier of an application   |
| `String` | `applicationVersionId` | An application version identifier |

#### Response

`CreateApplicationVersionResponse`

| Type      | Name                   | Description                                                                     |
|-----------|------------------------|---------------------------------------------------------------------------------|
| `String`  | `applicationVersionId` | An identifier of an application version                                         |
| `String`  | `applicationKey`       | A key (identifier) of an application, associated with given application version |
| `String`  | `applicationSecret`    | An application secret associated with this version                              |
| `boolean` | `supported`            | Flag indicating if this application is supported                                |

### Method 'unsupportApplicationVersion'

Mark application version with given ID as "unsupported". Signatures constructed using application key and application secret associated with this versions will be rejected as invalid.

#### Request

REST endpoint: `POST /rest/v4/application/version/unsupport`

`UnsupportApplicationVersionRequest`

| Type     | Name                   | Description                             |
|----------|------------------------|-----------------------------------------|
| `String` | `applicationVersionId` | An identifier of an application version |

#### Response

`UnsupportApplicationVersionResponse`

| Type      | Name                   | Description                                      |
|-----------|------------------------|--------------------------------------------------|
| `String`  | `applicationVersionId` | An identifier of an application version          |
| `boolean` | `supported`            | Flag indicating if this application is supported |

### Method 'supportApplicationVersion'

Mark application version with given ID as "supported". Signatures constructed using application key and application secret associated with this versions will be evaluated the standard way.

#### Request

REST endpoint: `POST /rest/v4/application/version/support`

`SupportApplicationVersionRequest`

| Type     | Name                   | Description                             |
|----------|------------------------|-----------------------------------------|
| `String` | `applicationVersionId` | An identifier of an application version |

#### Response

`SupportApplicationVersionResponse`

| Type      | Name                   | Description                                      |
|-----------|------------------------|--------------------------------------------------|
| `String`  | `applicationVersionId` | An identifier of an application version          |
| `boolean` | `supported`            | Flag indicating if this application is supported |

### Method 'getApplicationConfig'

Get application configuration detail.

#### Request

REST endpoint: `POST /rest/v4/application/config/detail`

`GetApplicationConfigRequest`

| Type     | Name            | Description                     |
|----------|-----------------|---------------------------------|
| `String` | `applicationId` | An identifier of an application |

#### Response

`GetApplicationConfigResponse`

| Type                                 | Name                 | Description                        |
|--------------------------------------|----------------------|------------------------------------|
| `String`                             | `applicationId`      | An identifier of an application    |
| `List<ApplicationConfigurationItem>` | `applicationConfigs` | List of application configurations |

The `ApplicationConfigurationItem` record contains following parameters: 
  - `String key` - configuration key name
  - `List<Object> values` - configuration values

Following configuration keys are expected:

- `fido2_attestation_fmt_allowed` - list of allowed attestation formats for FIDO2 registrations, unset value means all attestation formats are allowed
- `fido2_aaguids_allowed` - list of allowed AAGUIDs for FIDO2 registration, unset value means all AAGUIDs are allowed
- `fido2_root_ca_certs` - list of trusted root CA certificates for certificate validation in PEM format
- `oauth2_providers` - configuration of OAuth 2.0 providers, see [OpenID Connect (OIDC) Activation](./OIDC-Activation.md) for details
- `activation_transfer` - configuration of activation transfer, see [Activation Transfer](./Activation-Transfer.md) for details
- `cryptography_algorithms_supported` - list of supported cryptography algorithms, an array of string values, allowed values: `EC_P256`, `EC_P384`, `EC_P384_ML_L3`, `EC_P384_ML_L5`, when not configured all algorithms are supported
- `disable_biometry_unlock_kek_device_private` - use a single value `true` to disable usage of the biometric factor for unlocking the key `KEK_DEVICE_PRIVATE`

### Method 'createApplicationConfig'

Create application configuration.

#### Request

REST endpoint: `POST /rest/v4/application/config/create`

`CreateApplicationConfigRequest`

| Type           | Name            | Description                                               |
|----------------|-----------------|-----------------------------------------------------------|
| `String`       | `applicationId` | An identifier of an application                           |
| `String`       | `key`           | Application configuration key name                        |
| `List<Object>` | `values`        | Application configuration values serialized as JSON array |

The following configuration keys are accepted:

- `fido2_attestation_fmt_allowed` - list of allowed attestation formats for FIDO2 registrations, unset value means all attestation formats are allowed
- `fido2_aaguids_allowed` - list of allowed AAGUIDs for FIDO2 registration, unset value means all AAGUIDs are allowed
- `fido2_root_ca_certs` - list of trusted root CA certificates for certificate validation in PEM format
- `oauth2_providers` - configuration of OAuth 2.0 providers, see [OpenID Connect (OIDC) Activation](./OIDC-Activation.md) for details
- `activation_transfer` - configuration of activation transfer, see [Activation Transfer](./Activation-Transfer.md) for details
- `cryptography_algorithms_supported` - list of supported cryptography algorithms, an array of string values, allowed values: `EC_P256`, `EC_P384`, `EC_P384_ML_L3`, `EC_P384_ML_L5`, when not configured all algorithms are supported
- `disable_biometry_unlock_kek_device_private` - use a single value `true` to disable usage of the biometric factor for unlocking the key `KEK_DEVICE_PRIVATE`

#### Response

`CreateApplicationConfigResponse`

| Type           | Name            | Description                        |
|----------------|-----------------|------------------------------------|
| `String`       | `applicationId` | An identifier of an application    |
| `String`       | `key`           | Application configuration key name |
| `List<Object>` | `values`        | Application configuration values   |

### Method 'removeApplicationConfig'

Delete an application configuration.

#### Request

REST endpoint: `POST /rest/v4/application/config/remove`

`RemoveApplicationConfigRequest`

| Type     | Name            | Description                        |
|----------|-----------------|------------------------------------|
| `String` | `applicationId` | An identifier of an application    |
| `String` | `key`           | Application configuration key name |

#### Response

_empty response_

## Activation management

Methods related to activation management.

### Method 'initActivation'

Create (initialize) a new activation for given user and application. If the optional `activationOtp` parameter is set, then the same value of activation OTP must be later provided for the confirmation.

After calling this method, a new activation record is created in CREATED state.

#### Request

REST endpoint: `POST /rest/v4/activation/init`

`InitActivationRequest`

| Type                      | Name                        | Description                                                                                                                         |
|---------------------------|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `String`                  | `protocol`                  | Activation protocol. Allowed values: `powerauth`, `fido2`.                                                                          |
| `String`                  | `userId`                    | An identifier of a user.                                                                                                            |
| `String`                  | `applicationId`             | An identifier of an application.                                                                                                    |
| `DateTime`                | `timestampActivationExpire` | Timestamp after when the activation cannot be completed anymore.                                                                    |
| `Long`                    | `maxFailureCount`           | How many failures are allowed for this activation.                                                                                  |
| `ActivationOtpValidation` | `activationOtpValidation`   | *Deprecated* optional activation OTP validation mode.                                                                               |
| `CommitPhase`             | `commitPhase`               | Optional parameter to specify when the activation should be committed. Allowed values: `ON_COMMIT` (default) and `ON_KEY_EXCHANGE`. |
| `String`                  | `activationOtp`             | Optional activation OTP.                                                                                                            |
| `String[]`                | `flags`                     | Optional list of activation flags.                                                                                                  |
| `Object`                  | `additionalData`            | The activation's custom attributes set through a private API in a free JSON structure.                                              |
| `String`                  | `parentActivationId`        | The parent activation ID. Mandatory when `transferType` is present.                                                                 |
| `String`                  | `transferType`              | The activation transfer type (`SPAWN`, or `MOVE`). Mandatory when `parentActivationId` is present.                                  |

This section describes how to change the activation commit flow:
- By default, the activation follows the state transition diagram described in [activation state documentation](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states). The activation gets committed by calling the [commit activation](#method-commitactivation) endpoint when it is in the `PENDING_COMMIT` state.
- In case you want the activation to be commited during key exchange, specify the `commitPhase` parameter with value `ON_KEY_EXCHANGE`. In this case, the activation transitions from `CREATED` state directly into `ACTIVE` state and no separate call is required for performing the activation commit.

In case you require activation OTP validation during activation, specify the `activationOtp` parameter. The phase when the OTP gets validated is controlled by the `commitPhase` parameter, either it is checked by default during commit (value `ON_COMMIT`) or during key exchange (value `ON_KEY_EXCHANGE`). When the `activationOtp` parameter is missing, OTP validation is not performed.

#### Response

`InitActivationResponse`

| Type                  | Name                   | Description                                                                                |
|-----------------------|------------------------|--------------------------------------------------------------------------------------------|
| `String`              | `activationId`         | A UUID4 identifier of an activation.                                                       |
| `String`              | `activationCode`       | Activation code which uses 4x5 characters in Base32 encoding separated by a "-" character. |
| `String`              | `activationSignature`  | *Deprecated* signature of the activation data using Master Server Private Key.             |
| `Map<String, String>` | `activationSignatures` | A map of algorithm identifiers to activation signatures.                                   |
| `String`              | `userId`               | An identifier of a user.                                                                   |
| `String`              | `applicationId`        | An identifier of an application.                                                           |

### Method 'prepareActivation'

Assure a key exchange between PowerAuth Client and PowerAuth Server and prepare the activation with given ID to be committed. Only activations in CREATED state can be prepared.

If optional `activationOtp` value is present in encrypted payload, then the value must match the OTP stored in activation's record and OTP validation mode must be ON_KEY_EXCHANGE.

After successfully calling this method, activation is in PENDING_COMMIT or ACTIVE state, depending on the presence of an activation OTP in ECIES payload:

| Situation                                           | State after `prepareActivation` |
|-----------------------------------------------------|---------------------------------|
| OTP is not required and is not provided             | `PENDING_COMMIT`                |
| OTP is required and is valid                        | `ACTIVE`                        |
| OTP is required, but is not valid                   | `CREATED`                       |
| OTP is required, but is not valid, no attempts left | `REMOVED`                       |

#### Request

REST endpoint: `POST /rest/v4/activation/prepare`

`PrepareActivationRequest`

| Type     | Name              | Description                                                                               |
|----------|-------------------|-------------------------------------------------------------------------------------------|
| `String` | `activationCode`  | Activation code which uses 4x5 characters in Base32 encoding separated by a "-" character |
| `String` | `applicationKey`  | A key (identifier) of an application, associated with given application version           |
| `String` | `temporaryKeyId`  | Identifier of the temporary key for encryption                                            |
| `String` | `encryptedData`   | Base64 encoded encrypted data (AEAD)                                                      |
| `String` | `nonce`           | Nonce value used for AEAD encryption                                                      |
| `String` | `protocolVersion` | Cryptography protocol version                                                             |
| `Long`   | `timestamp`       | Unix timestamp in milliseconds for AEAD                                                   |

Encrypted request should contain following data (as JSON):
- `sharedSecretRequest` – Shared secret request including:
  - `String algorithm` – Shared secret algorithm.
  - `String[] encapsulationKeys` – Encapsulation keys in order EC, PQC.
- `devicePublicKeys` – Device public keys including:
  - `String ecdsa` – ECDSA public key (base64).
  - `String mldsa` – Optional ML-DSA public key (base64).
- `activationName` – Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
- `activationOtp` – Optional activation OTP for confirmation.
- `externalId` – Optional external ID associated with activation.
- `platform` – User device platform, e.g. `ios`, `android`, `hw` and `unknown`.
- `deviceInfo` – Information about user device, e.g. `iPhone12,3`.
- `extras` – Any client side attributes associated with this activation, like a more detailed information about the client, etc.

#### Response

`PrepareActivationResponse`

| Type               | Name               | Description                                  |
|--------------------|--------------------|----------------------------------------------|
| `String`           | `activationId`     | A UUID4 identifier of an activation          |
| `String`           | `userId`           | User ID                                      |
| `String`           | `applicationId`    | An identifier of an application              |
| `String`           | `encryptedData`    | Base64 encoded encrypted data for AEAD       |
| `Long`             | `timestamp`        | Unix timestamp in milliseconds used for AEAD |
| `ActivationStatus` | `activationStatus` | An activation status                         |

Encrypted response contains following data (as JSON):
- `sharedSecretResponse` – Shared secret response including:
  - `String salt` - Salt used by KMAC algorithm during shared secret derivation. 
  - `String[] encapsulatedKeys` - Encapsulated keys in order EC, PQC.
- `serverPublicKeys` – Server public keys including:
  - `String ecdsa` - ECDSA public key (base64).
  - `String mldsa` - Optional ML-DSA public key (base64).
- `activationId` – Long numeric activation identifier
- `ctrData` – Initial counter data for hashing (base64)

### Method 'createActivation'

Create an activation for given user and application, with provided maximum number of failed attempts and expiration timestamp, including a key exchange between PowerAuth Client and PowerAuth Server. Prepare the activation to be committed later.

If optional `activationOtp` value is set, then the activation's OTP validation mode is set to `ON_COMMIT`. The same OTP value must be later provided in [CommitActivation](#method-commitactivation) method, to complete the activation.

After successfully calling this method, activation is in PENDING_COMMIT state.

#### Request

REST endpoint: `POST /rest/v4/activation/create`

`CreateActivationRequest`

| Type       | Name                        | Description                                                                           |
|------------|-----------------------------|---------------------------------------------------------------------------------------|
| `String`   | `userId`                    | User ID                                                                               |
| `DateTime` | `timestampActivationExpire` | Timestamp after when the activation cannot be completed anymore                       |
| `Long`     | `maxFailureCount`           | How many failures are allowed for this activation                                     |
| `String`   | `applicationKey`            | A key (identifier) of an application, associated with given application version       |
| `String`   | `temporaryKeyId`            | Identifier of the temporary key for encryption                                        |
| `String`   | `encryptedData`             | Base64 encoded encrypted data (AEAD)                                                  |
| `String`   | `nonce`                     | Nonce value used for AEAD encryption                                                  |
| `String`   | `activationOtp`             | Optional activation OTP                                                               |
| `String`   | `protocolVersion`           | Cryptography protocol version                                                         |
| `Long`     | `timestamp`                 | Unix timestamp in milliseconds for AEAD                                               |
| `Object`   | `additionalData`            | The activation's custom attributes set through a private API in a free JSON structure |

Encrypted request should contain following data (as JSON):
- `sharedSecretRequest` – Shared secret request including:
  - `String algorithm` – Shared secret algorithm.
  - `String[] encapsulationKeys` – Encapsulation keys in order EC, PQC.
- `devicePublicKeys` – Device public keys including:
  - `String ecdsa` – ECDSA public key (base64).
  - `String mldsa` – Optional ML-DSA public key (base64).
- `activationName` – Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
- `activationOtp` – Optional activation OTP for confirmation.
- `externalId` – Optional external ID associated with activation.
- `platform` – User device platform, e.g. `ios`, `android`, `hw` and `unknown`.
- `deviceInfo` – Information about user device, e.g. `iPhone12,3`.
- `extras` – Any client side attributes associated with this activation, like a more detailed information about the client, etc.

#### Response

`CreateActivationResponse`

| Type     | Name            | Description                                  |
|----------|-----------------|----------------------------------------------|
| `String` | `activationId`  | A UUID4 identifier of an activation          |
| `String` | `encryptedData` | Base64 encoded encrypted data for AEAD       |
| `Long`   | `timestamp`     | Unix timestamp in milliseconds used for AEAD |

Encrypted response contains following data (as JSON):
- `sharedSecretResponse` – Shared secret response including:
  - `String salt` - Salt used by KMAC algorithm during shared secret derivation.
  - `String[] encapsulatedKeys` - Encapsulated keys in order EC, PQC.
- `serverPublicKeys` – Server public keys including:
  - `String ecdsa` - ECDSA public key (base64).
  - `String mldsa` - Optional ML-DSA public key (base64).
- `activationId` – Long numeric activation identifier.
- `ctrData` – Initial counter data for hashing (base64).


### Method 'updateActivationOtp'

Update activation OTP for activation with given ID. Only non-expired activations in PENDING_COMMIT state, with OTP validation set to NONE or ON_COMMIT, can be altered. 

After successful, activation OTP is updated and the OTP validation is set to ON_COMMIT.

#### Request

REST endpoint: `POST /rest/v4/activation/otp/update`

`UpdateActivationOtpRequest`

| Type     | Name             | Description                                                                                       |
|----------|------------------|---------------------------------------------------------------------------------------------------|
| `String` | `activationId`   | An identifier of an activation                                                                    |
| `String` | `externalUserId` | User ID of user who changes the activation. Use null value if activation owner caused the change. |
| `String` | `activationOtp`  | A new value of activation OTP                                                                     |

#### Response

`UpdateActivationOtpResponse`

| Type      | Name           | Description                               |
|-----------|----------------|-------------------------------------------|
| `String`  | `activationId` | An identifier of an activation            |
| `boolean` | `updated`      | Flag indicating that OTP has been updated |

### Method 'updateActivationName'

Update activation name for activation with given ID.
No allowed for activation in status `CREATED`, `REMOVED`, or `BLOCKED`.

After successful, activation name is updated.

#### Request

REST endpoint: `POST /rest/v4/activation/name/update`

`UpdateActivationNameRequest`

| Type     | Name             | Description                                                                                       |
|----------|------------------|---------------------------------------------------------------------------------------------------|
| `String` | `activationId`   | An identifier of an activation.                                                                   |
| `String` | `externalUserId` | User ID of user who changes the activation. Use null value if activation owner caused the change. |
| `String` | `activationName` | A new value of activation name.                                                                   |

#### Response

`UpdateActivationNameResponse`

| Type               | Name               | Description                     |
|--------------------|--------------------|---------------------------------|
| `String`           | `activationId`     | An identifier of an activation  |
| `String`           | `activationName`   | A new value of activation name. |
| `ActivationStatus` | `activationStatus` | An activation status.           |

### Method 'commitActivation'

Commit activation with given ID. Only non-expired activations in PENDING_COMMIT state can be committed.

If optional `activationOtp` value is set, then the value must match the OTP stored in activation's record and OTP validation mode must be `ON_COMMIT`.

After successful commit, activation is in ACTIVE state.

#### Request

REST endpoint: `POST /rest/v4/activation/commit`

`CommitActivationRequest`

| Type     | Name             | Description                                                                                         |
|----------|------------------|-----------------------------------------------------------------------------------------------------|
| `String` | `activationId`   | An identifier of an activation                                                                      |
| `String` | `externalUserId` | User ID of user who committed the activation. Use null value if activation owner caused the change. |
| `String` | `activationOtp`  | An optional activation OTP for confirmation.                                                        |

#### Response

`CommitActivationResponse`

| Type      | Name           | Description                                     |
|-----------|----------------|-------------------------------------------------|
| `String`  | `activationId` | An identifier of an activation                  |
| `boolean` | `activated`    | Flag indicating if the activation was committed |

### Method 'confirmActivation'

Confirm activation with given ID.  

This method is used to confirm activations from the mobile SDK and set up biometry after the biometry setup is finished on the mobile device.  

#### Request

REST endpoint: `POST /rest/v4/activation/confirm`

`ConfirmActivationRequest`

| Type      | Name             | Description                                            |
|-----------|------------------|--------------------------------------------------------|
| `String`  | `activationId`   | Activation identifier                                  |
| `boolean` | `enableBiometry` | Enable biometric factor during activation confirmation |

#### Response

_empty response_

### Method 'getActivationStatus'

Get status information and all important details for activation with given ID.

#### Request

REST endpoint: `POST /rest/v4/activation/status`

`GetActivationStatusRequest`

| Type      | Name                | Description                                                    |
|-----------|---------------------|----------------------------------------------------------------|
| `String`  | `activationId`      | An identifier of an activation                                 |
| `boolean` | `includeStatusBlob` | Whether status blob is included in the response (default=true) |

#### Response

`GetActivationStatusResponse`

| Type                      | Name                         | Description                                                                                        |
|---------------------------|------------------------------|----------------------------------------------------------------------------------------------------|
| `String`                  | `activationId`               | An identifier of an activation                                                                     |
| `ActivationStatus`        | `activationStatus`           | An activation status                                                                               |
| `ActivationOtpValidation` | `activationOtpValidation`    | An activation OTP validation mode (*deprecated*)                                                   |
| `CommitPhase`             | `commitPhase`                | Specifies when activation is committed                                                             |
| `String`                  | `blockedReason`              | Reason why activation was blocked (default: NOT_SPECIFIED)                                         |
| `boolean`                 | `confirmationPending`        | Indicates if activation is waiting for external confirmation                                       |
| `String`                  | `activationName`             | An activation name                                                                                 |
| `String`                  | `userId`                     | An identifier of a user                                                                            |
| `String`                  | `protocol`                   | Activation protocol (`powerauth` or `fido2`)                                                       |
| `String`                  | `externalId`                 | External ID associated with activation                                                             |
| `String`                  | `extras`                     | Any custom attributes set through SDK                                                              |
| `String`                  | `platform`                   | User device platform, e.g. `ios`, `android`, `hw` and `unknown`                                    |
| `String`                  | `deviceInfo`                 | Information about user device, e.g. `iPhone12,3`                                                   |
| `Long`                    | `failedAttempts`             | Information about number of failed attempts.                                                       |
| `Long`                    | `maxFailedAttempts`          | Information about maximum number of allowed failed attempts.                                       |
| `String[]`                | `activationFlags`            | Activation flags                                                                                   |
| `String`                  | `applicationId`              | An identifier of an application                                                                    |
| `String[]`                | `applicationRoles`           | Application roles                                                                                  |
| `DateTime`                | `timestampCreated`           | A timestamp when the activation was created                                                        |
| `DateTime`                | `timestampLastUsed`          | A timestamp when the activation was last used                                                      |
| `DateTime`                | `timestampLastChange`        | A timestamp of last activation status change                                                       |
| `String`                  | `statusBlob`                 | Activation status blob (optional, depending on request)                                            |
| `String`                  | `activationCode`             | Activation code which uses 4x5 characters in Base32 encoding separated by a "-" character          |
| `String`                  | `activationSignature`        | A signature of the activation data using Master Server Private Key (*deprecated*)                  |
| `Map<String,String>`      | `activationSignatures`       | A map of algorithm identifiers to activation signatures                                            |
| `String`                  | `devicePublicKeyFingerprint` | Numeric fingerprint of device public key, used during activation for key verification              |
| `Long`                    | `version`                    | Activation version                                                                                 |
| `Object`                  | `additionalData`             | The activation's custom attributes set through a private API in a free JSON structure              |
| `String`                  | `parentActivationId`         | The parent activation ID. Mandatory when `transferType` is present.                                |
| `String`                  | `transferType`               | The activation transfer type (`SPAWN`, or `MOVE`). Mandatory when `parentActivationId` is present. |

### Method 'removeActivation'

Remove activation with given ID. This operation is irreversible. Activations can be removed in any state. After successfully calling this method, activation is in REMOVED state.

#### Request

REST endpoint: `POST /rest/v4/activation/remove`

`RemoveActivationRequest`

| Type     | Name             | Description                                                                                       |
|----------|------------------|---------------------------------------------------------------------------------------------------|
| `String` | `activationId`   | An identifier of an activation                                                                    |
| `String` | `externalUserId` | User ID of user who removed the activation. Use null value if activation owner caused the change. |

#### Response

`RemoveActivationResponse`

| Type      | Name           | Description                                   |
|-----------|----------------|-----------------------------------------------|
| `String`  | `activationId` | An identifier of an activation                |
| `boolean` | `removed`      | Flag indicating if the activation was removed |

### Method 'getActivationListForUser'

Get the list of all activations for given user and application ID. If no application ID is provided, return list of all activations for given user.

#### Request

REST endpoint: `POST /rest/v4/activation/list`

`GetActivationListForUserRequest`

| Type                 | Name                 | Description                                                                                                                                                                     |
|----------------------|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`             | `userId`             | An identifier of a user                                                                                                                                                         |
| `String`             | `applicationId`      | An identifier of an application                                                                                                                                                 |
| `ActivationStatus[]` | `activationStatuses` | Optional statuses according to which activations should be filtered. Return all activations if empty.                                                                           |
| `Integer`            | `pageNumber`         | Optional. The number of the page to fetch in the paginated results. Starts from 0, where 0 refers to the first page. If not provided, defaults to 0.                            |
| `Integer`            | `pageSize`           | Optional. The number of records per page in the paginated results. This determines the total number of records shown in each page of results. If not provided, defaults to 500. |
| `String[]`           | `protocols`          | Optional. Filter activations by activation protocol (`powerauth`, `fido2`).                                                                                                     |

#### Response

`GetActivationListForUserResponse`

| Type           | Name          | Description                                                                              |
|----------------|---------------|------------------------------------------------------------------------------------------|
| `String`       | `userId`      | An identifier of a user                                                                  |
| `Activation[]` | `activations` | A collection of activations for the given user ordered by `timestampCreated` descending. |

`GetActivationListForUserResponse.Activation`

| Type               | Name                    | Description                                                                                        |
|--------------------|-------------------------|----------------------------------------------------------------------------------------------------|
| `String`           | `activationId`          | An identifier of an activation                                                                     |
| `ActivationStatus` | `activationStatus`      | An activation status                                                                               |
| `String`           | `blockedReason`         | Reason why activation was blocked (default: NOT_SPECIFIED)                                         |
| `String`           | `activationName`        | An activation name                                                                                 |
| `String`           | `externalId`            | External ID associated with activation                                                             |
| `String`           | `protocol`              | Activation protocol (`powerauth`, `fido2`)                                                         |
| `String`           | `applicationName`       | Application name                                                                                   |
| `String`           | `extras`                | Any custom attributes set through SDK                                                              |
| `String`           | `platform`              | User device platform, e.g. `ios`, `android`, `hw` and `unknown`                                    |
| `String`           | `deviceInfo`            | Information about user device, e.g. `iPhone12,3`                                                   |
| `String[]`         | `activationFlags`       | Activation flags                                                                                   |
| `DateTime`         | `timestampCreated`      | A timestamp when the activation was created                                                        |
| `DateTime`         | `timestampLastUsed`     | A timestamp when the activation was last used                                                      |
| `DateTime`         | `timestampLastChange`   | A timestamp of last activation status change                                                       |
| `String`           | `userId`                | An identifier of a user                                                                            |
| `String`           | `applicationId`         | An identifier of an application                                                                    |
| `Long`             | `failedAttempts`        | Information about number of failed attempts.                                                       |
| `Long`             | `maxFailedAttempts`     | Information about maximum number of allowed failed attempts.                                       |
| `String`           | `devicePublicKeyBase64` | Base64 encoded device public key                                                                   |
| `Long`             | `version`               | Activation version                                                                                 |
| `Object`           | `additionalData`        | The activation's custom attributes set through a private API in a free JSON structure              |
| `String`           | `parentActivationId`    | The parent activation ID. Mandatory when `transferType` is present.                                |
| `String`           | `transferType`          | The activation transfer type (`SPAWN`, or `MOVE`). Mandatory when `parentActivationId` is present. |


### Method 'blockActivation'

Block activation with given ID. Activations can be blocked in ACTIVE state only. After successfully calling this method, activation is in BLOCKED state.

#### Request

REST endpoint: `POST /rest/v4/activation/block`

`BlockActivationRequest`

| Type     | Name             | Description                                                                                       |
|----------|------------------|---------------------------------------------------------------------------------------------------|
| `String` | `activationId`   | An identifier of an activation                                                                    |
| `String` | `reason`         | Reason why activation is being blocked (default: NOT_SPECIFIED)                                   |
| `String` | `externalUserId` | User ID of user who blocked the activation. Use null value if activation owner caused the change. |

#### Response

`BlockActivationResponse`

| Type               | Name               | Description                                                |
|--------------------|--------------------|------------------------------------------------------------|
| `String`           | `activationId`     | An identifier of an activation                             |
| `ActivationStatus` | `activationStatus` | An activation status                                       |
| `String`           | `blockedReason`    | Reason why activation was blocked (default: NOT_SPECIFIED) |

### Method 'unblockActivation'

Unblock activation with given ID. Activations can be unblocked in BLOCKED state only. After successfully calling this method, activation is in ACTIVE state and failed attempt counter is set to 0.

#### Request

REST endpoint: `POST /rest/v4/activation/unblock`

`UnblockActivationRequest`

| Type     | Name             | Description                                                                                         |
|----------|------------------|-----------------------------------------------------------------------------------------------------|
| `String` | `activationId`   | An identifier of an activation                                                                      |
| `String` | `externalUserId` | User ID of user who unblocked the activation. Use null value if activation owner caused the change. |

#### Response

`UnblockActivationResponse`

| Type               | Name               | Description                    |
|--------------------|--------------------|--------------------------------|
| `String`           | `activationId`     | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status           |

### Method 'lookupActivations'

Lookup activations using query parameters.

#### Request

REST endpoint: `POST /rest/v4/activation/lookup`

`LookupActivationsRequest`

| Type       | Name                      | Description                                                                                                                                                    |
|------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`   | `userIds`                 | User IDs to use in query, at least one user ID needs to be specified                                                                                           |
| `String[]` | `applicationIds`          | Application IDs to use in the query, do not specify value for all applications                                                                                 |
| `String`   | `timestampLastUsedBefore` | Filter activations by timestamp when the activation was last used (timestampLastUsed < timestampLastUsedBefore), if not specified, a current timestamp is used |
| `String`   | `timestampLastUsedAfter`  | Filter activations by timestamp when the activation was last used (timestampLastUsed >= timestampLastUsedAfter), if not specified, the epoch start is used     |
| `String`   | `activationStatus`        | Filter activations by their status, do not specify value for any status                                                                                        |
| `String[]` | `activationFlags`         | Filter activations by activation flags                                                                                                                         |

#### Response

`LookupActivationsResponse`

| `Activation[]` | `activations` | A collection of activations for given query parameters |

`LookupActivationsResponse.Activation`

| Type               | Name                  | Description                                                                           |
|--------------------|-----------------------|---------------------------------------------------------------------------------------|
| `String`           | `activationId`        | An identifier of an activation                                                        |
| `ActivationStatus` | `activationStatus`    | An activation status                                                                  |
| `String`           | `blockedReason`       | Reason why activation was blocked (default: NOT_SPECIFIED)                            |
| `String`           | `activationName`      | An activation name                                                                    |
| `String`           | `extras`              | Any custom attributes set through SDK                                                 |
| `String`           | `platform`            | User device platform, e.g. `ios`, `android`, `hw` and `unknown`                       |
| `String`           | `deviceInfo`          | Information about user device, e.g. `iPhone12,3`                                      |
| `String[]`         | `activationFlags`     | Activation flags                                                                      |
| `DateTime`         | `timestampCreated`    | A timestamp when the activation was created                                           |
| `DateTime`         | `timestampLastUsed`   | A timestamp when the activation was last used                                         |
| `DateTime`         | `timestampLastChange` | A timestamp of last activation status change                                          |
| `String`           | `userId`              | An identifier of a user                                                               |
| `String`           | `applicationId`       | An identifier of an application                                                       |
| `Long`             | `version`             | Activation version                                                                    |
| `Object`           | `additionalData`      | The activation's custom attributes set through a private API in a free JSON structure |

### Method 'updateStatusForActivations'

Update status for activations identified using their identifiers.

#### Request

REST endpoint: `POST /rest/v4/activation/status/update`

`UpdateStatusForActivationsRequest`

| Type               | Name               | Description                                                 |
|--------------------|--------------------|-------------------------------------------------------------|
| `String[]`         | `activationIds`    | Identifiers of activations whose status needs to be updated |
| `ActivationStatus` | `activationStatus` | Activation status to use when updating the activations      |

#### Response

`UpdateStatusForActivationsResponse`

| Type      | Name      | Description                                                                                                                                                     |
|-----------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `boolean` | `updated` | Whether status update succeeded for all provided activations, either all activation statuses are updated or none of the statuses is updated in case of an error |

## DSA Signature Verification

Methods related to DSA signature verification.

### Method 'signAsymmetric'

Sign data using available asymmetric signature algorithms.

#### Request

REST endpoint: `POST /rest/v4/dsa/sign`

`SignAsymmetricRequest`

| Type     | Name           | Description                                       |
|----------|----------------|---------------------------------------------------|
| `String` | `activationId` | An identifier of an activation                    |
| `String` | `data`         | Base64 encoded data for the signature calculation |

#### Response

`SignAsymmetricResponse`

| Type     | Name             | Description                                          |
|----------|------------------|------------------------------------------------------|
| `String` | `signatureEcdsa` | ECDSA signature calculated using server private key  |
| `String` | `signatureMldsa` | ML-DSA signature calculated using server private key |

### Method 'verifyAsymmetricSignature'

Verify signature correctness for given activation, data and signature type.

#### Request

REST endpoint: `POST /rest/v4/dsa/verify`

`VerifyAsymmetricSignatureRequest`

| Type                        | Name              | Description                                        |
|-----------------------------|-------------------|----------------------------------------------------|
| `String`                    | `activationId`    | An identifier of an activation                     |
| `String`                    | `data`            | Base64 encoded data for the signature verification |
| `String`                    | `signature`       | Base64 encoded signature to be verified            |
| `AsymmetricSignatureType`   | `signatureType`   | Signature type (default: `ECDSA` or `MLDSA`)       |
| `AsymmetricSignatureFormat` | `signatureFormat` | Signature format (default: `DER` or `JOSE`)        |

#### Response

`VerifyAsymmetricSignatureResponse`

| Type      | Name             | Description                                                                         |
|-----------|------------------|-------------------------------------------------------------------------------------|
| `boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |

## JWT Signature Verification

Methods related to JWT signature verification.

### Method 'signJwt'

Sign data using JWT signature algorithm.

#### Request

REST endpoint: `POST /rest/v4/jwt/sign`

`SignJwtRequest`

| Type                      | Name              | Description                                             |
|---------------------------|-------------------|---------------------------------------------------------|
| `String`                  | `activationId`    | An identifier of an activation                          |
| `String`                  | `data`            | Base64URL encoded data for the signature calculation    |
| `JwtSignatureFormat`      | `signatureFormat` | Signature format (default: `JWS_COMPACT` or `JWS_JSON`) |
| `AsymmetricSignatureType` | `signatureType`   | Signature type: `ECDSA` or `MLDSA`                      |

#### Response

`SignJwtResponse`

| Type                 | Name              | Description                                    |
|----------------------|-------------------|------------------------------------------------|
| `String`             | `signedData`      | JWT data and signature                         |
| `JwtSignatureFormat` | `signatureFormat` | Signature format (`JWS_COMPACT` or `JWS_JSON`) |

### Method 'verifyJwtSignature'

Verify JWT signature.

#### Request

REST endpoint: `POST /rest/v4/jwt/verify`

`VerifyJwtSignatureRequest`

| Type                 | Name              | Description                                    |
|----------------------|-------------------|------------------------------------------------|
| `String`             | `activationId`    | An identifier of an activation                 |
| `String`             | `signedData`      | JWT data and signature                         |
| `JwtSignatureFormat` | `signatureFormat` | Signature format (`JWS_COMPACT` or `JWS_JSON`) |

#### Response

`VerifyJwtSignatureResponse`

| Type      | Name             | Description                                                                         |
|-----------|------------------|-------------------------------------------------------------------------------------|
| `boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |

## Offline Authentication

Methods related to offline authentication code validation.

### Method 'createNonPersonalizedOfflineAuthPayload'

Create a data payload used as a challenge for non-personalized off-line authentication.

#### Request

REST endpoint: `POST /rest/v4/auth/offline/non-personalized/create`

`CreateNonPersonalizedOfflineAuthPayloadRequest`

| Type     | Name            | Description                                                                                                                                                                                   |
|----------|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String` | `applicationId` | An identifier of an application                                                                                                                                                               |
| `String` | `data`          | Data for the signature, for normalized value see the [Offline Signatures QR code](https://github.com/wultra/powerauth-webflow/blob/develop/docs/Off-line-Signatures-QR-Code.md) documentation |

#### Response

`CreateNonPersonalizedOfflineAuthPayloadResponse`

| Type     | Name          | Description                                                                                                              |
|----------|---------------|--------------------------------------------------------------------------------------------------------------------------|
| `String` | `offlineData` | Data for QR code in format: `{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}`                    |
| `String` | `nonce`       | Random cryptographic nonce, 16B encoded in Base64, same nonce as in `offlineData` (available separately for easy access) |

### Method 'createPersonalizedOfflineAuthPayload'

Create a data payload used as a challenge for personalized off-line authentication.

#### Request

REST endpoint: `POST /rest/v4/auth/offline/personalized/create`

`CreatePersonalizedOfflineAuthPayloadRequest`

| Type      | Name                        | Description                                                                                                                                                                                   |
|-----------|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`  | `activationId`              | An identifier of an activation                                                                                                                                                                |
| `String`  | `data`                      | Data for the signature, for normalized value see the [Offline Signatures QR code](https://github.com/wultra/powerauth-webflow/blob/develop/docs/Off-line-Signatures-QR-Code.md) documentation |
| `String`  | `nonce`                     | Optional nonce (16 bytes base64 encoded into 24 characters), otherwise it will be generated by PowerAuth server. Needed to be set when proximity check is enabled.                            |
| `Object`  | `proximityCheck`            | Optional parameters for proximity TOTP.                                                                                                                                                       |
| `String`  | `proximityCheck.seed`       | Seed for TOTP, base64 encoded.                                                                                                                                                                |
| `Integer` | `proximityCheck.stepLength` | Length of the TOTP step in seconds.                                                                                                                                                           |

#### Response

`CreatePersonalizedOfflineAuthPayloadResponse`

| Type     | Name          | Description                                                                                                              |
|----------|---------------|--------------------------------------------------------------------------------------------------------------------------|
| `String` | `offlineData` | Data for QR code in format: `{DATA}\n{NONCE}\n{KEY_MAC_PERSONALIZED_DATA}{SIGNATURE}`                                    |
| `String` | `nonce`       | Random cryptographic nonce, 16B encoded in Base64, same nonce as in `offlineData` (available separately for easy access) |


### Method 'verifyOfflineAuthentication'

Verify offline authentication code for provided data.

#### Request

REST endpoint: `POST /rest/v4/auth/offline/verify`

`VerifyOfflineAuthenticationRequest`

| Type         | Name                        | Description                                                                     |
|--------------|-----------------------------|---------------------------------------------------------------------------------|
| `String`     | `activationId`              | An identifier of an activation                                                  |
| `String`     | `data`                      | Base64 encoded normalized data for the authentication                           |
| `String`     | `authenticationCode`        | Authentication code value                                                       |
| `BigInteger` | `componentLength`           | Authentication component length                                                 |
| `boolean`    | `allowBiometry`             | Whether biometry is allowed in offline mode                                     |
| `Object`     | `proximityCheck`            | Optional parameters for proximity TOTP.                                         |
| `String`     | `proximityCheck.seed`       | Seed for TOTP, base64 encoded.                                                  |
| `Integer`    | `proximityCheck.stepLength` | Length of the TOTP step in seconds.                                             |
| `Integer`    | `proximityCheck.stepCount`  | Count how many backward steps should be validated. Zero means current one only. |

#### Response

`VerifyOfflineAuthenticationResponse`

| Type                     | Name                     | Description                                                                                   |
|--------------------------|--------------------------|-----------------------------------------------------------------------------------------------|
| `boolean`                | `authenticationValid`    | Indicates if the authentication code was correctly validated or if it was invalid (incorrect) |
| `ActivationStatus`       | `activationStatus`       | An activation status                                                                          |
| `String`                 | `blockedReason`          | Reason why activation was blocked (default: NOT_SPECIFIED)                                    |
| `String`                 | `activationId`           | An identifier of an activation                                                                |
| `String`                 | `userId`                 | An identifier of a user                                                                       |
| `String`                 | `applicationId`          | An identifier of the application                                                              |
| `AuthenticationCodeType` | `authenticationCodeType` | Type of the authentication code that was used for the computation of the authentication code. |
| `Integer`                | `remainingAttempts`      | How many attempts are left for authentication using this activation                           |
| `String[]`               | `applicationRoles`       | Roles assigned to the application                                                             |
| `String[]`               | `activationFlags`        | Activation flags for the activation                                                           |

## Token-Based Authentication

### Method 'createToken'

Create a new token for the simple token-based authentication.

#### Request

REST endpoint: `POST /rest/v4/token/create`

`CreateTokenRequest`

| Type                     | Name                     | Description                                                                     |
|--------------------------|--------------------------|---------------------------------------------------------------------------------|
| `String`                 | `activationId`           | An identifier of an activation.                                                 |
| `String`                 | `applicationKey`         | A key (identifier) of an application, associated with given application version |
| `String`                 | `temporaryKeyId`         | Temporary key identifier for AEAD                                               |
| `String`                 | `encryptedData`          | Base64 encoded encrypted data for AEAD                                          |
| `String`                 | `nonce`                  | Base64 encoded nonce for IV derivation for AEAD                                 |
| `AuthenticationCodeType` | `authenticationCodeType` | Type of the authentication code (factors) used for token creation.              |
| `String`                 | `protocolVersion`        | Cryptography protocol version                                                   |
| `Long`                   | `timestamp`              | Unix timestamp in milliseconds for AEAD                                         |

AEAD request should contain following data (an empty JSON object):
```json
{}
```

#### Response

`CreateTokenResponse`

| Type     | Name            | Description                             |
|----------|-----------------|-----------------------------------------|
| `String` | `encryptedData` | Base64 encoded encrypted data for AEAD  |
| `Long`   | `timestamp`     | Unix timestamp in milliseconds for AEAD |

AEAD response contains following data (example):
```json
{
   "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb",  
   "tokenSecret": "VqAXEhziiT27lxoqREjtcQ=="
}
```

### Method 'validateToken'

Validate token digest used for the simple token-based authentication.

#### Request

REST endpoint: `POST /rest/v4/token/validate`

`ValidateTokenRequest`

| Type     | Name              | Description                                            |
|----------|-------------------|--------------------------------------------------------|
| `String` | `tokenId`         | An identifier of the token.                            |
| `String` | `tokenDigest`     | Digest computed during the token based authentication. |
| `String` | `nonce`           | Cryptographic nonce. Random 16B, Base64 encoded.       |
| `String` | `protocolVersion` | Cryptography protocol version                          |
| `Long`   | `timestamp`       | Token digest timestamp, Unix timestamp format.         |

#### Response

`ValidateTokenResponse`

| Type                     | Name                     | Description                                                                              |
|--------------------------|--------------------------|------------------------------------------------------------------------------------------|
| `boolean`                | `tokenValid`             | Information about the validation result - if true, token digest was valid.               |
| `String`                 | `activationId`           | An identifier of an activation                                                           |
| `ActivationStatus`       | `activationStatus`       | An activation status at the moment of a token verification                               |
| `String`                 | `blockedReason`          | Reason why activation was blocked in case activation is blocked (default: NOT_SPECIFIED) |
| `String`                 | `userId`                 | An identifier of a user                                                                  |
| `String`                 | `applicationId`          | An identifier of the application                                                         |
| `AuthenticationCodeType` | `authenticationCodeType` | Type of the authentication code that was used for creating the token.                    |
| `String[]`               | `applicationRoles`       | Roles assigned to the application                                                        |
| `String[]`               | `activationFlags`        | Activation flags for the activation                                                      |

### Method 'removeToken'

Remove token with given ID.

#### Request

REST endpoint: `POST /rest/v4/token/remove`

`RemoveTokenRequest`

| Type     | Name           | Description                      |
|----------|----------------|----------------------------------|
| `String` | `tokenId`      | An identifier of the token.      |
| `String` | `activationId` | An identifier of the activation. |

#### Response

`RemoveTokenResponse`

| Type      | Name      | Description                                                                                |
|-----------|-----------|--------------------------------------------------------------------------------------------|
| `boolean` | `removed` | True in case token was removed, false in case token with given ID was already not present. |

## Vault unlocking

Methods related to secure vault.

### Method 'vaultUnlock'

Get the encrypted vault unlock key upon successful authentication using PowerAuth authentication code.

#### Request

REST endpoint: `POST /rest/v4/vault/unlock`

`VaultUnlockRequest`

| Type                     | Name                     | Description                                                                     |
|--------------------------|--------------------------|---------------------------------------------------------------------------------|
| `String`                 | `activationId`           | An identifier of an activation                                                  |
| `String`                 | `applicationKey`         | A key (identifier) of an application, associated with given application version |
| `String`                 | `requestData`            | Base64 encoded data for the authentication                                      |
| `String`                 | `authenticationCode`     | PowerAuth authentication code                                                   |
| `AuthenticationCodeType` | `authenticationCodeType` | PowerAuth authentication code type                                              |
| `String`                 | `authenticationVersion`  | PowerAuth cryptography protocol version                                         |
| `String`                 | `temporaryKeyId`         | Temporary key identifier for AEAD                                               |
| `String`                 | `encryptedData`          | Base64 encoded encrypted data for AEAD                                          |
| `String`                 | `nonce`                  | Base64 encoded nonce for IV derivation for AEAD                                 |
| `Long`                   | `timestamp`              | Unix timestamp in milliseconds for AEAD                                         |

AEAD request should contain following data:
```json
{
    "keyIdentifier": "...",
    "reason": "..."
}
```

Following key identifiers are supported:
- `KEK_DEVICE_PRIVATE` - key encryption key for the device private key
- `KDK_APP_VAULT_KNOWLEDGE` - key encryption key for vault used after 2FA with a knowledge factor
- `KDK_APP_VAULT_2FA` - key encryption key for vault used after any 2FA authentication

You can provide following reasons for a vault unlocking:

- `ADD_BIOMETRY` - call was used to enable biometric authentication.
- `FETCH_ENCRYPTION_KEY` - call was used to fetch a generic data encryption key.
- `SIGN_WITH_DEVICE_PRIVATE_KEY` - call was used to unlock device private key used for ECDSA signatures.
- `NOT_SPECIFIED` - no reason was specified.


#### Response

`VaultUnlockResponse`

| Type      | Name                  | Description                                                                                   |
|-----------|-----------------------|-----------------------------------------------------------------------------------------------|
| `String`  | `encryptedData`       | Base64 encoded encrypted data for AEAD                                                        |
| `boolean` | `authenticationValid` | Indicates if the authentication code was correctly validated or if it was invalid (incorrect) |
| `Long`    | `timestamp`           | Unix timestamp in milliseconds for AEAD                                                       |

AEAD response contains following data (example):
```json
{
    "vaultEncryptionKey": "..."
}
```

## Audit Log

Methods related to auditing.

### Method 'getAuditLog'

Get the audit log for given user, application and date range. In case no application ID is provided, event log for all applications is returned.

#### Request

REST endpoint: `POST /rest/v4/audit/list`

`SignatureAuditRequest`

| Type       | Name            | Description                           |
|------------|-----------------|---------------------------------------|
| `String`   | `userId`        | An identifier of a user               |
| `String`   | `applicationId` | An identifier of an application       |
| `DateTime` | `timestampFrom` | Timestamp from which to fetch the log |
| `DateTime` | `timestampTo`   | Timestamp to which to fetch the log   |

#### Response

`SignatureAuditResponse`

| Type     | Name    | Description                        |
|----------|---------|------------------------------------|
| `Item[]` | `items` | Collection of signature audit logs |

`SignatureAuditResponse.Item`

| Type               | Name                | Description                                                    |
|--------------------|---------------------|----------------------------------------------------------------|
| `Long`             | `id`                | Record ID                                                      |
| `String`           | `userId`            | An identifier of a user                                        |
| `String`           | `applicationId`     | An identifier of an application                                |
| `String`           | `activationId`      | An identifier of an activation                                 |
| `Long`             | `activationCounter` | A counter value at the moment of a signature verification      |
| `String`           | `activationCtrData` | Base64 encoded hash based counter data                         |
| `ActivationStatus` | `activationStatus`  | An activation status at the moment of a signature verification |
| `KeyValueMap`      | `additionalInfo`    | Key-value map with additional information                      |
| `String`           | `dataBase64`        | A base64 encoded data sent with the signature                  |
| `String`           | `signatureVersion`  | Requested signature version                                    |
| `String`           | `signatureType`     | Requested signature type                                       |
| `String`           | `signature`         | Submitted value of a signature                                 |
| `String`           | `note`              | Extra info about the result of the signature verification      |
| `boolean`          | `valid`             | Flag indicating if the provided signature was valid            |
| `long`             | `version`           | Activation version                                             |
| `DateTime`         | `timestampCreated`  | Timestamp when the record was created                          |

## Activation history

Get activation status change log.

### Method 'getActivationHistory'

Get the status change log for given activation and date range.

#### Request

REST endpoint: `POST /rest/v4/activation/history`

`ActivationHistoryRequest`

| Type       | Name            | Description                               |
|------------|-----------------|-------------------------------------------|
| `String`   | `activationId`  | Activation ID                             |
| `DateTime` | `timestampFrom` | Timestamp from which to fetch the changes |
| `DateTime` | `timestampTo`   | Timestamp to which to fetch the changes   |

#### Response

`ActivationHistoryResponse`

| Type     | Name    | Description                          |
|----------|---------|--------------------------------------|
| `Item[]` | `items` | Collection of activation change logs |

`ActivationHistoryResponse.Item`

| Type               | Name               | Description                                                                                            |
|--------------------|--------------------|--------------------------------------------------------------------------------------------------------|
| `Long`             | `id`               | Change ID                                                                                              |
| `String`           | `activationId`     | An identifier of an activation                                                                         |
| `ActivationStatus` | `activationStatus` | Activation status at this moment                                                                       |
| `String`           | `eventReason`      | Reason why this activation history record was created (default: null)                                  |
| `String`           | `externalUserId`   | User ID of user who modified the activation. Null value is used if activation owner caused the change. |
| `String`           | `activationName`   | Activation name.                                                                                       |
| `DateTime`         | `timestampCreated` | Timestamp when the record was created                                                                  |
| `long`             | `version`          | Activation version                                                                                     |

## Integration management

Methods used for managing integration credentials for PowerAuth Server.

### Method 'createIntegration'

Create a new integration with given name, automatically generate credentials for the integration.

#### Request

REST endpoint: `POST /rest/v4/integration/create`

`CreateIntegrationRequest`

| Type     | Name   | Description           |
|----------|--------|-----------------------|
| `String` | `name` | New integration name. |

#### Response

`CreateIntegrationResponse`

| Type     | Name           | Description                                            |
|----------|----------------|--------------------------------------------------------|
| `String` | `id`           | Integration identifier (UUID4).                        |
| `String` | `name`         | A name of the integration.                             |
| `String` | `clientToken`  | An integration client token (serves as a "username").  |
| `String` | `clientSecret` | An integration client secret (serves as a "password"). |

### Method 'getIntegrationList'

Get the list of all integrations that are configured on the server instance.

#### Request

REST endpoint: `POST /rest/v4/integration/list`

`GetIntegrationListRequest`

- _no attributes_

#### Response

`GetIntegrationListResponse`

| Type     | Name    | Description                        |
|----------|---------|------------------------------------|
| `Item[]` | `items` | Collection of integration records. |

`GetIntegrationListResponse.Item`

| Type     | Name           | Description                                            |
|----------|----------------|--------------------------------------------------------|
| `String` | `id`           | Integration identifier (UUID4).                        |
| `String` | `name`         | A name of the integration.                             |
| `String` | `clientToken`  | An integration client token (serves as a "username").  |
| `String` | `clientSecret` | An integration client secret (serves as a "password"). |

### Method 'removeIntegration'

Remove integration with given ID.

#### Request

REST endpoint: `POST /rest/v4/integration/remove`

`RemoveIntegrationRequest`

| Type     | Name | Description                         |
|----------|------|-------------------------------------|
| `String` | `id` | ID of an integration to be removed. |

#### Response

`RemoveIntegrationResponse`

| Type      | Name      | Description                                           |
|-----------|-----------|-------------------------------------------------------|
| `String`  | `id`      | ID of an integration to be removed.                   |
| `boolean` | `removed` | Flag specifying if an integration was removed or not. |

### Method 'createCallbackUrl'

Create a callback URL with given parameters.

#### Request

REST endpoint: `POST /rest/v4/application/callback/create`

`CreateCallbackUrlRequest`

| Type                        | Name              | Description                                                                                                                |
|-----------------------------|-------------------|----------------------------------------------------------------------------------------------------------------------------|
| `String`                    | `applicationId`   | Associated application ID.                                                                                                 |
| `String`                    | `name`            | Callback URL name, for visual identification.                                                                              |
| `CallbackUrlType`           | `type`            | Type of the callback. Either `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`.                                      |
| `String`                    | `callbackUrl`     | Callback URL that should be notified about activation status updates.                                                      |
| `List<String>`              | `attributes`      | Attributes which should be sent with the callback. See possible attributes bellow.                                         |
| `HttpAuthenticationPrivate` | `authentication`  | Callback HTTP request authentication configuration.                                                                        |
| `Duration`                  | `retentionPeriod` | Duration in ISO 8601 duration format after which a completed callback event is automatically removed from database.        |
| `Duration`                  | `initialBackoff`  | Initial delay in ISO 8601 duration format before retry attempt following a callback event failure, if retries are enabled. |
| `Integer`                   | `maxAttempts`     | Maximum number of attempts to send a callback event.                                                                       |

When creating a callback URL of type `ACTIVATION_STATUS_CHANGE`, following `attributes` can be used:

- `userId`
- `activationName`
- `deviceInfo`
- `platform`
- `protocol`
- `activationFlags`
- `activationStatus`
- `blockedReason`
- `applicationId`

When creating a callback URL of type `OPERATION_STATUS_CHANGE`, following `attributes` can be used:

- `userId`
- `applications`
- `operationType`
- `parameters`
- `additionalData`
- `activationFlag`
- `status`
- `data`
- `failureCount`
- `maxFailureCount`
- `authenticationCodeType`
- `externalId`
- `timestampCreated`
- `timestampExpires`
- `timestampFinalized`

The `authentication` parameter contains a JSON-based configuration for client TLS certificate and HTTP basic authentication:
```json
{
  "certificate": {
    "enabled": false,
    "useCustomKeyStore": false,
    "keyStoreLocation": "[keystore resource location]",
    "keyStoreContent": "[keystore content encoded in Base64]",
    "keyStorePassword": "[keystore password]",
    "keyAlias": "[key alias]",
    "keyPassword": "[key password]",
    "useCustomTrustStore": false,
    "trustStoreLocation": "[truststore resource location]",
    "trustStoreContent": "[truststore content encoded in Base64]",
    "trustStorePassword": "[truststore password]"
  },
  "httpBasic": {
    "enabled": false,
    "username": "[HTTP basic authentication username]",
    "password": "[HTTP basic authentication password]"
  },
  "oauth2": {
    "enabled": false,
    "clientId": "[OAuth2 client ID]",
    "clientSecret": "[OAuth2 client secret]",
    "tokenUri": "[OAuth2 token URI]",
    "scope": "[OAuth2 scope]"
  }
}
```

#### Response

`CreateCallbackUrlResponse`

| Type                       | Name              | Description                                                                                                                |
|----------------------------|-------------------|----------------------------------------------------------------------------------------------------------------------------|
| `String`                   | `id`              | Callback URL identifier (UUID4).                                                                                           |
| `String`                   | `applicationId`   | Associated application ID.                                                                                                 |
| `String`                   | `name`            | Callback URL name, for visual identification.                                                                              |
| `CallbackUrlType`          | `type`            | Type of the callback. Either `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`.                                      |
| `String`                   | `callbackUrl`     | Callback URL that should be notified about activation status updates.                                                      |
| `List<String>`             | `attributes`      | Attributes which should be sent with the callback.                                                                         |
| `HttpAuthenticationPublic` | `authentication`  | Callback HTTP request authentication configuration.                                                                        |
| `Duration`                 | `retentionPeriod` | Duration in ISO 8601 duration format after which a completed callback event is automatically removed from database.        |
| `Duration`                 | `initialBackoff`  | Initial delay in ISO 8601 duration format before retry attempt following a callback event failure, if retries are enabled. |
| `Integer`                  | `maxAttempts`     | Maximum number of attempts to send a callback event.                                                                       |

### Method 'updateCallbackUrl'

Update a callback URL with given parameters.

#### Request

REST endpoint: `POST /rest/v4/application/callback/update`

`UpdateCallbackUrlRequest`

| Type                        | Name              | Description                                                                                                                |
|-----------------------------|-------------------|----------------------------------------------------------------------------------------------------------------------------|
| `String`                    | `id`              | Callback URL identifier (UUID4).                                                                                           |
| `String`                    | `applicationId`   | Associated application ID.                                                                                                 |
| `CallbackUrlType`           | `type`            | Type of the callback. Either `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`.                                      |
| `String`                    | `name`            | Callback URL name, for visual identification.                                                                              |
| `String`                    | `callbackUrl`     | Callback URL that should be notified about activation status updates.                                                      |
| `List<String>`              | `attributes`      | Attributes which should be sent with the callback. See possible attributes bellow.                                         |
| `HttpAuthenticationPrivate` | `authentication`  | Callback HTTP request authentication configuration.                                                                        |
| `Duration`                  | `retentionPeriod` | Duration in ISO 8601 duration format after which a completed callback event is automatically removed from database.        |
| `Duration`                  | `initialBackoff`  | Initial delay in ISO 8601 duration format before retry attempt following a callback event failure, if retries are enabled. |
| `Integer`                   | `maxAttempts`     | Maximum number of attempts to send a callback event.                                                                       |

When configuring a callback URL of type `ACTIVATION_STATUS_CHANGE`, following `attributes` can be used:

- `userId`
- `activationName`
- `deviceInfo`
- `platform`
- `protocol`
- `activationFlags`
- `activationStatus`
- `blockedReason`
- `applicationId`

When configuring a callback URL of type `OPERATION_STATUS_CHANGE`, following `attributes` can be used:

- `userId`
- `applications`
- `operationType`
- `parameters`
- `additionalData`
- `activationFlag`
- `status`
- `data`
- `failureCount`
- `maxFailureCount`
- `authenticationCodeType`
- `externalId`
- `timestampCreated`
- `timestampExpires`
- `timestampFinalized`

The `authentication` parameter contains a JSON-based configuration for client TLS certificate and HTTP basic authentication:
```json
{
  "certificate": {
    "enabled": false,
    "useCustomKeyStore": false,
    "keyStoreLocation": "[keystore resource location]",
    "keyStoreContent": "[keystore content encoded in Base64]",
    "keyStorePassword": "[keystore password]",
    "keyAlias": "[key alias]",
    "keyPassword": "[key password]",
    "useCustomTrustStore": false,
    "trustStoreLocation": "[truststore resource location]",
    "trustStoreContent": "[truststore content encoded in Base64]",
    "trustStorePassword": "[truststore password]"
  },
  "httpBasic": {
    "enabled": false,
    "username": "[HTTP basic authentication username]",
    "password": "[HTTP basic authentication password]"
  },
  "oauth2": {
    "enabled": false,
    "clientId": "[OAuth2 client ID]",
    "clientSecret": "[OAuth2 client secret]",
    "tokenUri": "[OAuth2 token URI]",
    "scope": "[OAuth2 scope]"
  }
}
```

In case you do not want to modify the already set `keyStoreContent` or `trustStoreContent`, send a `null` value in request. For removing the existing `keyStoreContent` or `trustStoreContent` use an empty string.


#### Response

`UpdateCallbackUrlResponse`

| Type                       | Name              | Description                                                                                                                |
|----------------------------|-------------------|----------------------------------------------------------------------------------------------------------------------------|
| `String`                   | `id`              | Callback URL identifier (UUID4).                                                                                           |
| `String`                   | `applicationId`   | Associated application ID.                                                                                                 |
| `String`                   | `name`            | Callback URL name, for visual identification.                                                                              |
| `CallbackUrlType`          | `type`            | Type of the callback. Either `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`.                                      |
| `String`                   | `callbackUrl`     | Callback URL that should be notified about activation status updates.                                                      |
| `List<String>`             | `attributes`      | Attributes which should be sent with the callback.                                                                         |
| `HttpAuthenticationPublic` | `authentication`  | Callback HTTP request authentication configuration.                                                                        |
| `Duration`                 | `retentionPeriod` | Duration in ISO 8601 duration format after which a completed callback event is automatically removed from database.        |
| `Duration`                 | `initialBackoff`  | Initial delay in ISO 8601 duration format before retry attempt following a callback event failure, if retries are enabled. |
| `Integer`                  | `maxAttempts`     | Maximum number of attempts to send a callback event.                                                                       |

### Method 'getCallbackUrlList'

Get the list of all callbacks for given application.

#### Request

REST endpoint: `POST /rest/v4/application/callback/list`

`GetCallbackUrlListRequest`

| Type     | Name            | Description                                      |
|----------|-----------------|--------------------------------------------------|
| `String` | `applicationId` | Application ID for which to fetch callback URLs. |

#### Response

`GetCallbackUrlListResponse`

| Type                | Name              | Description        |
|---------------------|-------------------|--------------------|
| `CallbackUrlList[]` | `callbackUrlList` | Callback URL list. |

`GetCallbackUrlListResponse.CallbackUrlList`

| Type                       | Name              | Description                                                                                                                |
|----------------------------|-------------------|----------------------------------------------------------------------------------------------------------------------------|
| `String`                   | `id`              | Callback URL identifier (UUID4).                                                                                           |
| `String`                   | `applicationId`   | Associated application ID.                                                                                                 |
| `String`                   | `name`            | Callback URL name, for visual identification.                                                                              |
| `CallbackUrlType`          | `type`            | Type of the callback. Either `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`.                                      |
| `String`                   | `callbackUrl`     | Callback URL that should be notified about activation status updates.                                                      |
| `List<String>`             | `attributes`      | Attributes which should be sent with the callback.                                                                         |
| `HttpAuthenticationPublic` | `authentication`  | Callback HTTP request authentication configuration.                                                                        |
| `Duration`                 | `retentionPeriod` | Duration in ISO 8601 duration format after which a completed callback event is automatically removed from database.        |
| `Duration`                 | `initialBackoff`  | Initial delay in ISO 8601 duration format before retry attempt following a callback event failure, if retries are enabled. |
| `Integer`                  | `maxAttempts`     | Maximum number of attempts to send a callback event.                                                                       |

### Method 'removeCallbackUrl'

Remove callback URL with given ID.

#### Request

REST endpoint: `POST /rest/v4/application/callback/remove`

`RemoveCallbackUrlRequest`

| Type     | Name | Description                           |
|----------|------|---------------------------------------|
| `String` | `id` | ID of the callback URL to be removed. |

#### Response

`RemoveCallbackUrlResponse`

| Type      | Name      | Description                                             |
|-----------|-----------|---------------------------------------------------------|
| `String`  | `id`      | ID of the callback URL.                                 |
| `boolean` | `removed` | Flag specifying if the callback URL was removed or not. |

## End-To-End Encryption

### Method 'extractEncryptor'

Extract the encryptor data for request/response encryption and decryption on intermediate server.

#### Request

REST endpoint: `POST /rest/v4/encryptor`

`ExtractEncryptorRequest`

| Type                 | Name              | Description                                                                                              |
|----------------------|-------------------|----------------------------------------------------------------------------------------------------------|
| `String`             | `activationId`    | A UUID4 identifier of an activation (used only in activation scope, use null value in application scope) |
| `String`             | `applicationKey`  | A key (identifier) of an application, associated with given application version                          |
| `String`             | `temporaryKeyId`  | Temporary key identifier for AEAD                                                                        |
| `String`             | `nonce`           | Base64 encoded nonce for IV derivation for AEAD                                                          |
| `String`             | `protocolVersion` | Cryptography protocol version                                                                            |
| `Long`               | `timestamp`       | Unix timestamp in milliseconds for AEAD                                                                  |
| `ActivationStatus[]` | `allowedStates`   | Activation states which are allowed when obtaining encryptor in activation scope                         |

#### Response

`ExtractEncryptorResponse`

| Type     | Name          | Description                        |
|----------|---------------|------------------------------------|
| `String` | `secretKey`   | Base64 encoded secret key for AEAD |
| `String` | `sharedInfo2` | The sharedInfo2 parameter for AEAD |

## Activation versioning

### Method 'startUpgrade'

Upgrade activation to the most recent version supported by the server.

Upgrade is performed between major activation versions, upgrade from version `3` to version `4`. 

#### Request

REST endpoint: `POST /rest/v4/upgrade/start`

`StartUpgradeRequest`

| Type     | Name              | Description                                                                                              |
|----------|-------------------|----------------------------------------------------------------------------------------------------------|
| `String` | `activationId`    | A UUID4 identifier of an activation (used only in activation scope, use null value in application scope) |
| `String` | `applicationKey`  | A key (identifier) of an application, associated with given application version                          |
| `String` | `temporaryKeyId`  | Temporary key identifier for AEAD                                                                        |
| `String` | `encryptedData`   | Base64 encoded encrypted data for AEAD                                                                   |
| `String` | `nonce`           | Base64 encoded nonce for IV derivation for AEAD                                                          |
| `String` | `protocolVersion` | Cryptography protocol version                                                                            |
| `Long`   | `timestamp`       | Unix timestamp in milliseconds for AEAD                                                                  |

#### Response

`StartUpgradeResponse`

| Type     | Name            | Description                             |
|----------|-----------------|-----------------------------------------|
| `String` | `encryptedData` | Base64 encoded encrypted data for AEAD  |
| `Long`   | `timestamp`     | Unix timestamp in milliseconds for AEAD |

### Method 'commitUpgrade'

Commit activation upgrade.

#### Request

REST endpoint: `POST /rest/v4/upgrade/commit`

`CommitUpgradeRequest`

| Type     | Name             | Description                                                                                              |
|----------|------------------|----------------------------------------------------------------------------------------------------------|
| `String` | `activationId`   | A UUID4 identifier of an activation (used only in activation scope, use null value in application scope) |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version                          |

#### Response

`CommitUpgradeResponse`

| Type      | Name        | Description                                         |
|-----------|-------------|-----------------------------------------------------|
| `boolean` | `committed` | Flag specifying if activation upgrade was committed |

## Activation Flags

### Method `listActivationFlags`

List flags for an activation.

#### Request

REST endpoint: `POST /rest/v4/activation/flags/list`

`ListActivationFlagsRequest`

| Type     | Name           | Description                         |
|----------|----------------|-------------------------------------|
| `String` | `activationId` | A UUID4 identifier of an activation |

#### Response

`ListActivationFlagsResponse`

| Type       | Name              | Description                            |
|------------|-------------------|----------------------------------------|
| `String`   | `activationId`    | The UUID4 identifier of the activation |
| `String[]` | `activationFlags` | Activation flags for the activation    |

### Method `addActivationFlags`

Add activation flags to an activation. Duplicate flags are ignored.

#### Request

REST endpoint: `POST /rest/v4/activation/flags/create`

`AddActivationFlagsRequest`

| Type       | Name              | Description                                    |
|------------|-------------------|------------------------------------------------|
| `String`   | `activationId`    | A UUID4 identifier of an activation            |
| `String[]` | `activationFlags` | Activation flags to be added to the activation |

#### Response

`AddActivationFlagsResponse`

| Type       | Name              | Description                                            |
|------------|-------------------|--------------------------------------------------------|
| `String`   | `activationId`    | The UUID4 identifier of the activation                 |
| `String[]` | `activationFlags` | Activation flags for the activation after the addition |

### Method `updateActivationFlags`

Update activation flags to an activation. Existing flags are removed.

#### Request

REST endpoint: `POST /rest/v4/activation/flags/update`

`UpdateActivationFlagsRequest`

| Type       | Name              | Description                         |
|------------|-------------------|-------------------------------------|
| `String`   | `activationId`    | A UUID4 identifier of an activation |
| `String[]` | `activationFlags` | Activation flags for the update     |

#### Response

`UpdateActivationFlagsResponse`

| Type       | Name              | Description                                          |
|------------|-------------------|------------------------------------------------------|
| `String`   | `activationId`    | The UUID4 identifier of the activation               |
| `String[]` | `activationFlags` | Activation flags for the activation after the update |

### Method `removeActivationFlags`

Remove activation flags for an activation.

#### Request

REST endpoint: `POST /rest/v4/activation/flags/remove`

`RemoveActivationFlagsRequest`

| Type       | Name              | Description                                        |
|------------|-------------------|----------------------------------------------------|
| `String`   | `activationId`    | A UUID4 identifier of an activation                |
| `String[]` | `activationFlags` | Activation flags to be removed from the activation |

#### Response

`RemoveActivationFlagsResponse`

| Type       | Name              | Description                                           |
|------------|-------------------|-------------------------------------------------------|
| `String`   | `activationId`    | The UUID4 identifier of the activation                |
| `String[]` | `activationFlags` | Activation flags for the activation after the removal |

## Application Roles

### Method `listApplicationRoles`

List roles for an application.

#### Request

REST endpoint: `POST /rest/v4/application/roles/list`

`ListApplicationRolesRequest`

| Type     | Name            | Description                     |
|----------|-----------------|---------------------------------|
| `String` | `applicationId` | An identifier of an application |

#### Response

`ListApplicationRolesResponse`

| Type       | Name               | Description                                   |
|------------|--------------------|-----------------------------------------------|
| `String`   | `applicationId`    | The identifier of the application             |
| `String[]` | `applicationRoles` | Application roles assigned to the application |

### Method `addApplicationRoles`

Add application roles to an application. Duplicate roles are ignored.

#### Request

REST endpoint: `POST /rest/v4/application/roles/create`

`AddApplicationRolesRequest`

| Type       | Name               | Description                                      |
|------------|--------------------|--------------------------------------------------|
| `String`   | `applicationId`    | An identifier of an application                  |
| `String[]` | `applicationRoles` | Application roles to be added to the application |

#### Response

`AddApplicationRolesResponse`

| Type       | Name               | Description                                                      |
|------------|--------------------|------------------------------------------------------------------|
| `String`   | `applicationId`    | The identifier of the application                                |
| `String[]` | `applicationRoles` | Application roles assigned to the application after the addition |

### Method `updateApplicationRoles`

Update application roles assigned to an application. Existing roles are removed.

#### Request

REST endpoint: `POST /rest/v4/application/roles/update`

`UpdateApplicationRolesRequest`

| Type       | Name               | Description                                         |
|------------|--------------------|-----------------------------------------------------|
| `String`   | `applicationId`    | An identifier of an application                     |
| `String[]` | `applicationRoles` | Application roles to be assigned to the application |

#### Response

`UpdateApplicationRolesResponse`

| Type       | Name               | Description                                                    |
|------------|--------------------|----------------------------------------------------------------|
| `String`   | `applicationId`    | The identifier of the application                              |
| `String[]` | `applicationRoles` | Application roles assigned to the application after the update |

### Method `removeApplicationRoles`

Remove application roles from an application.

#### Request

REST endpoint: `POST /rest/v4/application/roles/remove`

`RemoveApplicationRolesRequest`

| Type       | Name               | Description                                          |
|------------|--------------------|------------------------------------------------------|
| `String`   | `applicationId`    | An identifier of an application                      |
| `String[]` | `applicationRoles` | Application roles to be removed from the application |

#### Response

`RemoveApplicationRolesResponse`

| Type       | Name               | Description                                                     |
|------------|--------------------|-----------------------------------------------------------------|
| `String`   | `applicationId`    | An identifier of an application                                 |
| `String[]` | `applicationRoles` | Application roles assigned to the application after the removal |

## Operations

### Method 'createOperation'

Create a new operation based on the operation template.

#### Request

REST endpoint: `POST /rest/v4/operation/create`

`OperationCreateRequest`

| Type                  | Name                    | Description                                                                                                         |
|-----------------------|-------------------------|---------------------------------------------------------------------------------------------------------------------|
| `String`              | `userId`                | The identifier of the user (optional for non-personalized operations)                                               |
| `List<String>`        | `applications`          | List of associated applications                                                                                     |
| `String`              | `activationFlag`        | Activation flag associated with the operation                                                                       |
| `String`              | `templateName`          | Name of the template used for creating the operation                                                                |
| `Date`                | `timestampExpires`      | Timestamp of when the operation will expire, overrides expiration period from operation template                    |
| `String`              | `externalId`            | External identifier of the operation, i.e., ID from transaction system                                              |
| `Map<String, String>` | `parameters`            | Parameters of the operation, will be filled to the operation data                                                   |
| `Map<String, Object>` | `additionalData`        | Operation context, such as the IP address of the caller                                                             |
| `boolean`             | `proximityCheckEnabled` | Whether proximity check should be used, overrides configuration from operation template                             |
| `String`              | `activationId`          | Activation ID. It is possible to specify a single device (otherwise all user's activations are taken into account). |

#### Response

`OperationDetailResponse`

| Type                           | Name                      | Description                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------|
| `String`                       | `id`                      | The operation ID                                                                 |
| `String`                       | `userId`                  | The identifier of the user                                                       |
| `List<String>`                 | `applications`            | List of associated applications                                                  |
| `String`                       | `externalId`              | External identifier of the operation, i.e., ID from transaction system           |
| `String`                       | `activationFlag`          | Activation flag associated with the operation                                    |
| `String`                       | `operationType`           | Type of the operation created based on the template                              |
| `String`                       | `templateName`            | Template name used when creating this operation                                  |
| `String`                       | `data`                    | Operation data                                                                   |
| `Map<String, String>`          | `parameters`              | Parameters of the operation, will be filled to the operation data                |
| `Map<String, Object>`          | `additionalData`          | Operation context, such as the IP address of the caller                          |
| `OperationStatus`              | `status`                  | Status of the operation                                                          |
| `String`                       | `statusReason`            | Optional details why the status has changed in machine-readable format           |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                             |
| `Long`                         | `failureCount`            | The current number of the failed approval attempts                               |
| `Long`                         | `maxFailureCount`         | The maximum allowed number of the failed approval attempts                       |
| `Date`                         | `timestampCreated`        | Timestamp of when the operation was created                                      |
| `Date`                         | `timestampExpires`        | Timestamp of when the operation will expires / expired                           |
| `Date`                         | `timestampFinalized`      | Timestamp of when the operation was switched to a terminating status             |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| `String`                       | `proximityOtp`            | TOTP for proximity check (if enabled) valid for the current time step.           |
| `String`                       | `activationId`            | Activation Id of the activation scoped for the operation                         |

### Method 'operationDetail'

Get the operation detail.

#### Request

REST endpoint: `POST /rest/v4/operation/detail`

`OperationDetailRequest`

| Type     | Name          | Description                     |
|----------|---------------|---------------------------------|
| `String` | `operationId` | The identifier of the operation |

#### Response

`OperationDetailResponse`

| Type                           | Name                      | Description                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------|
| `String`                       | `id`                      | The operation ID                                                                 |
| `String`                       | `userId`                  | The identifier of the user                                                       |
| `List<String>`                 | `applications`            | List of associated applications                                                  |
| `String`                       | `externalId`              | External identifier of the operation, i.e., ID from transaction system           |
| `String`                       | `activationFlag`          | Activation flag associated with the operation                                    |
| `String`                       | `operationType`           | Type of the operation created based on the template                              |
| `String`                       | `templateName`            | Template name used when creating this operation                                  |
| `String`                       | `data`                    | Operation data                                                                   |
| `Map<String, String>`          | `parameters`              | Parameters of the operation, will be filled to the operation data                |
| `Map<String, Object>`          | `additionalData`          | Operation context, such as the IP address of the caller                          |
| `OperationStatus`              | `status`                  | Status of the operation                                                          |
| `String`                       | `statusReason`            | Optional details why the status has changed in machine-readable format           |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                             |
| `Long`                         | `failureCount`            | The current number of the failed approval attempts                               |
| `Long`                         | `maxFailureCount`         | The maximum allowed number of the failed approval attempts                       |
| `Date`                         | `timestampCreated`        | Timestamp of when the operation was created                                      |
| `Date`                         | `timestampExpires`        | Timestamp of when the operation will expires / expired                           |
| `Date`                         | `timestampFinalized`      | Timestamp of when the operation was switched to a terminating status             |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| `String`                       | `proximityOtp`            | TOTP for proximity check (if enabled) valid for the current time step.           |
| `String`                       | `activationId`            | Activation Id of the activation scoped for the operation                         |

### Method 'operationClaim'

Claim the operation for a user.

#### Request

REST endpoint: `POST /rest/v4/operation/claim`

`OperationClaimRequest`

| Type     | Name          | Description                                            |
|----------|---------------|--------------------------------------------------------|
| `String` | `operationId` | The identifier of the operation                        |
| `String` | `userId`      | User identifier of the user, used for operation claim. |

#### Response

`OperationDetailResponse`

| Type                           | Name                      | Description                                                                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `String`                       | `id`                      | The operation ID                                                                                                                 |
| `String`                       | `userId`                  | The identifier of the user                                                                                                       |
| `List<String>`                 | `applications`            | List of associated applications                                                                                                  |
| `String`                       | `externalId`              | External identifier of the operation, i.e., ID from transaction system                                                           |
| `String`                       | `activationFlag`          | Activation flag associated with the operation                                                                                    |
| `String`                       | `operationType`           | Type of the operation created based on the template                                                                              |
| `String`                       | `templateName`            | Template name used when creating this operation                                                                                  |
| `String`                       | `data`                    | Operation data                                                                                                                   |
| `Map<String, String>`          | `parameters`              | Parameters of the operation, will be filled to the operation data                                                                |
| `Map<String, Object>`          | `additionalData`          | Operation context, such as the IP address of the caller                                                                          |
| `OperationStatus`              | `status`                  | Status of the operation                                                                                                          |
| `String`                       | `statusReason`            | Optional details why the status changed. The value should be sent in the form of a computer-readable code, not a free-form text. |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                                                                             |
| `Long`                         | `failureCount`            | The current number of the failed approval attempts                                                                               |
| `Long`                         | `maxFailureCount`         | The maximum allowed number of the failed approval attempts                                                                       |
| `Date`                         | `timestampCreated`        | Timestamp of when the operation was created                                                                                      |
| `Date`                         | `timestampExpires`        | Timestamp of when the operation will expires / expired                                                                           |
| `Date`                         | `timestampFinalized`      | Timestamp of when the operation was switched to a terminating status                                                             |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`.                                                 |
| `String`                       | `proximityOtp`            | TOTP for proximity check (if enabled) valid for the current time step.                                                           |
| `String`                       | `activationId`            | Activation Id of the activation scoped for the operation                                                                         |

### Method 'findPendingOperationsForUser'

Get the list of pending operations for a user.

#### Request

REST endpoint: `POST /rest/v4/operation/list/pending`

`OperationListForUserRequest`

| Type      | Name            | Description                                                                                                                                                                     |
|-----------|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`  | `userId`        | The identifier of the user                                                                                                                                                      |
| `String`  | `applicationId` | The identifier of the application                                                                                                                                               |
| `String`  | `activationId`  | Optional. An identifier of activation when the list is requested on a particular device                                                                                         |
| `Integer` | `pageNumber`    | Optional. The number of the page to fetch in the paginated results. Starts from 0, where 0 refers to the first page. If not provided, defaults to 0.                            |
| `Integer` | `pageSize`      | Optional. The number of records per page in the paginated results. This determines the total number of records shown in each page of results. If not provided, defaults to 500. |


#### Response

`OperationListResponse`

A collection of records with the following structure:

| Type                           | Name                      | Description                                                                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `String`                       | `id`                      | The operation ID                                                                                                                 |
| `String`                       | `userId`                  | The identifier of the user                                                                                                       |
| `List<String>`                 | `applications`            | List of associated applications                                                                                                  |
| `String`                       | `externalId`              | External identifier of the operation, i.e., ID from transaction system                                                           |
| `String`                       | `activationFlag`          | Activation flag associated with the operation                                                                                    |
| `String`                       | `operationType`           | Type of the operation created based on the template                                                                              |
| `String`                       | `templateName`            | Template name used when creating this operation                                                                                  |
| `String`                       | `data`                    | Operation data                                                                                                                   |
| `Map<String, String>`          | `parameters`              | Parameters of the operation, will be filled to the operation data                                                                |
| `Map<String, Object>`          | `additionalData`          | Operation context, such as the IP address of the caller                                                                          |
| `OperationStatus`              | `status`                  | Status of the operation                                                                                                          |
| `String`                       | `statusReason`            | Optional details why the status changed. The value should be sent in the form of a computer-readable code, not a free-form text. |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                                                                             |
| `Long`                         | `failureCount`            | The current number of the failed approval attempts                                                                               |
| `Long`                         | `maxFailureCount`         | The maximum allowed number of the failed approval attempts                                                                       |
| `Date`                         | `timestampCreated`        | Timestamp of when the operation was created                                                                                      |
| `Date`                         | `timestampExpires`        | Timestamp of when the operation will expires / expired                                                                           |
| `Date`                         | `timestampFinalized`      | Timestamp of when the operation was switched to a terminating status                                                             |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`.                                                 |
| `String`                       | `proximityOtp`            | TOTP for proximity check (if enabled) valid for the current time step.                                                           |
| `String`                       | `activationId`            | Activation Id of the activation scoped for the operation                                                                         |

### Method 'findAllOperationsForUser'

Get the list of all operations for a user.

#### Request

REST endpoint: `POST /rest/v4/operation/list`

`OperationListForUserRequest`

| Type      | Name            | Description                                                                                                                                                                     |
|-----------|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`  | `userId`        | The identifier of the user                                                                                                                                                      |
| `String`  | `applicationId` | The identifier of the application                                                                                                                                               |
| `String`  | `activationId`  | Optional. An identifier of activation when the list is requested on a particular device                                                                                         |
| `Integer` | `pageNumber`    | Optional. The number of the page to fetch in the paginated results. Starts from 0, where 0 refers to the first page. If not provided, defaults to 0.                            |
| `Integer` | `pageSize`      | Optional. The number of records per page in the paginated results. This determines the total number of records shown in each page of results. If not provided, defaults to 500. |


#### Response

`OperationListResponse`

A collection of records with the following structure:

| Type                           | Name                      | Description                                                                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `String`                       | `id`                      | The operation ID                                                                                                                 |
| `String`                       | `userId`                  | The identifier of the user                                                                                                       |
| `List<String>`                 | `applications`            | List of associated applications                                                                                                  |
| `String`                       | `externalId`              | External identifier of the operation, i.e., ID from transaction system                                                           |
| `String`                       | `activationFlag`          | Activation flag associated with the operation                                                                                    |
| `String`                       | `operationType`           | Type of the operation created based on the template                                                                              |
| `String`                       | `templateName`            | Template name used when creating this operation                                                                                  |
| `String`                       | `data`                    | Operation data                                                                                                                   |
| `Map<String, String>`          | `parameters`              | Parameters of the operation, will be filled to the operation data                                                                |
| `Map<String, Object>`          | `additionalData`          | Operation context, such as the IP address of the caller                                                                          |
| `OperationStatus`              | `status`                  | Status of the operation                                                                                                          |
| `String`                       | `statusReason`            | Optional details why the status changed. The value should be sent in the form of a computer-readable code, not a free-form text. |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                                                                             |
| `Long`                         | `failureCount`            | The current number of the failed approval attempts                                                                               |
| `Long`                         | `maxFailureCount`         | The maximum allowed number of the failed approval attempts                                                                       |
| `Date`                         | `timestampCreated`        | Timestamp of when the operation was created                                                                                      |
| `Date`                         | `timestampExpires`        | Timestamp of when the operation will expires / expired                                                                           |
| `Date`                         | `timestampFinalized`      | Timestamp of when the operation was switched to a terminating status                                                             |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`.                                                 |
| `String`                       | `proximityOtp`            | TOTP for proximity check (if enabled) valid for the current time step.                                                           |
| `String`                       | `activationId`            | Activation Id of the activation scoped for the operation                                                                         |

### Method 'findAllOperationsByExternalID'

Get the list of operations by external ID.

#### Request

REST endpoint: `POST /rest/v4/operation/list/external`

`OperationExtIdRequest`

| Type      | Name            | Description                                                                                                                                                                     |
|-----------|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`  | `externalId`    | The external identifier of the operation                                                                                                                                        |
| `String`  | `applicationId` | The identifier of the application                                                                                                                                               |
| `Integer` | `pageNumber`    | Optional. The number of the page to fetch in the paginated results. Starts from 0, where 0 refers to the first page. If not provided, defaults to 0.                            |
| `Integer` | `pageSize`      | Optional. The number of records per page in the paginated results. This determines the total number of records shown in each page of results. If not provided, defaults to 500. |


#### Response

`OperationListResponse`

A collection of records with the following structure:

### Method 'findAllOperationsForUser'

Get the list of all operations for a user.

#### Request

REST endpoint: `POST /rest/v4/operation/list`

`OperationListForUserRequest`

| Type      | Name            | Description                                                                                                                                                                     |
|-----------|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `String`  | `userId`        | The identifier of the user                                                                                                                                                      |
| `String`  | `applicationId` | The identifier of the application                                                                                                                                               |
| `String`  | `activationId`  | Optional. An identifier of activation when the list is requested on a particular device                                                                                         |
| `Integer` | `pageNumber`    | Optional. The number of the page to fetch in the paginated results. Starts from 0, where 0 refers to the first page. If not provided, defaults to 0.                            |
| `Integer` | `pageSize`      | Optional. The number of records per page in the paginated results. This determines the total number of records shown in each page of results. If not provided, defaults to 500. |


#### Response

`OperationListResponse`

A collection of records with the following structure:

| Type                           | Name                      | Description                                                                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `String`                       | `id`                      | The operation ID                                                                                                                 |
| `String`                       | `userId`                  | The identifier of the user                                                                                                       |
| `List<String>`                 | `applications`            | List of associated applications                                                                                                  |
| `String`                       | `externalId`              | External identifier of the operation, i.e., ID from transaction system                                                           |
| `String`                       | `activationFlag`          | Activation flag associated with the operation                                                                                    |
| `String`                       | `operationType`           | Type of the operation created based on the template                                                                              |
| `String`                       | `templateName`            | Template name used when creating this operation                                                                                  |
| `String`                       | `data`                    | Operation data                                                                                                                   |
| `Map<String, String>`          | `parameters`              | Parameters of the operation, will be filled to the operation data                                                                |
| `Map<String, Object>`          | `additionalData`          | Operation context, such as the IP address of the caller                                                                          |
| `OperationStatus`              | `status`                  | Status of the operation                                                                                                          |
| `String`                       | `statusReason`            | Optional details why the status changed. The value should be sent in the form of a computer-readable code, not a free-form text. |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                                                                             |
| `Long`                         | `failureCount`            | The current number of the failed approval attempts                                                                               |
| `Long`                         | `maxFailureCount`         | The maximum allowed number of the failed approval attempts                                                                       |
| `Date`                         | `timestampCreated`        | Timestamp of when the operation was created                                                                                      |
| `Date`                         | `timestampExpires`        | Timestamp of when the operation will expires / expired                                                                           |
| `Date`                         | `timestampFinalized`      | Timestamp of when the operation was switched to a terminating status                                                             |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`.                                                 |
| `String`                       | `proximityOtp`            | TOTP for proximity check (if enabled) valid for the current time step.                                                           |
| `String`                       | `activationId`            | Activation Id of the activation scoped for the operation                                                                         |

### Method 'cancelOperation'

Cancel an operation.

#### Request

REST endpoint: `POST /rest/v4/operation/cancel`

`OperationCancelRequest`

| Type     | Name           | Description                                                                                                                      |
|----------|----------------|----------------------------------------------------------------------------------------------------------------------------------|
| `String` | `operationId`  | The identifier of the operation                                                                                                  |
| `String` | `statusReason` | Optional details why the status changed. The value should be sent in the form of a computer-readable code, not a free-form text. |

#### Response

`OperationDetailResponse`

| Type                           | Name                      | Description                                                                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `String`                       | `id`                      | The operation ID                                                                                                                 |
| `String`                       | `userId`                  | The identifier of the user                                                                                                       |
| `List<String>`                 | `applications`            | List of associated applications                                                                                                  |
| `String`                       | `externalId`              | External identifier of the operation, i.e., ID from transaction system                                                           |
| `String`                       | `activationFlag`          | Activation flag associated with the operation                                                                                    |
| `String`                       | `operationType`           | Type of the operation created based on the template                                                                              |
| `String`                       | `templateName`            | Template name used when creating this operation                                                                                  |
| `String`                       | `data`                    | Operation data                                                                                                                   |
| `Map<String, String>`          | `parameters`              | Parameters of the operation, will be filled to the operation data                                                                |
| `Map<String, Object>`          | `additionalData`          | Operation context, such as the IP address of the caller                                                                          |
| `OperationStatus`              | `status`                  | Status of the operation                                                                                                          |
| `String`                       | `statusReason`            | Optional details why the status changed. The value should be sent in the form of a computer-readable code, not a free-form text. |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                                                                             |
| `Long`                         | `failureCount`            | The current number of the failed approval attempts                                                                               |
| `Long`                         | `maxFailureCount`         | The maximum allowed number of the failed approval attempts                                                                       |
| `Date`                         | `timestampCreated`        | Timestamp of when the operation was created                                                                                      |
| `Date`                         | `timestampExpires`        | Timestamp of when the operation will expires / expired                                                                           |
| `Date`                         | `timestampFinalized`      | Timestamp of when the operation was switched to a terminating status                                                             |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`.                                                 |
| `String`                       | `proximityOtp`            | TOTP for proximity check (if enabled) valid for the current time step.                                                           |
| `String`                       | `activationId`            | Activation Id of the activation scoped for the operation                                                                         |

### Method 'approveOperation'

Approve an operation.

#### Request

REST endpoint: `POST /rest/v4/operation/approve`

`OperationApproveRequest`

| Type                     | Name                     | Description                                                      |
|--------------------------|--------------------------|------------------------------------------------------------------|
| `String`                 | `operationId`            | The identifier of the operation                                  |
| `String`                 | `userId`                 | The identifier of the user who attempts to approve the operation |
| `String`                 | `applicationId`          | The identifier of the application                                |
| `String`                 | `data`                   | Operation data that the user attempts to approve                 |
| `AuthenticationCodeType` | `authenticationCodeType` | Authentication code type used when approving the operation       |
| `Map<String, String>`    | `additionalData`         | Operation context, such as the IP address of the caller          |

#### Response

`OperationUserActionResponse`

| Type                      | Name        | Description                   |
|---------------------------|-------------|-------------------------------|
| `UserActionResult`        | `result`    | The result of the user action |
| `OperationDetailResponse` | `operation` | Operation detail              |

### Method 'failApproveOperation'

Fail approval of an operation to increment the failed attempt counter by one.

#### Request

REST endpoint: `POST /rest/v4/operation/approve/fail`

`OperationFailApprovalRequest`

| Type     | Name          | Description                     |
|----------|---------------|---------------------------------|
| `String` | `operationId` | The identifier of the operation |

#### Response

`OperationUserActionResponse`

| Type                      | Name        | Description                   |
|---------------------------|-------------|-------------------------------|
| `UserActionResult`        | `result`    | The result of the user action |
| `OperationDetailResponse` | `operation` | Operation detail              |

### Method 'rejectOperation'

Reject an operation.

#### Request

REST endpoint: `POST /rest/v4/operation/reject`

`OperationRejectRequest`

| Type                  | Name             | Description                                                      |
|-----------------------|------------------|------------------------------------------------------------------|
| `String`              | `operationId`    | The identifier of the operation                                  |
| `String`              | `userId`         | The identifier of the user who attempts to approve the operation |
| `String`              | `applicationId`  | The identifier of the application                                |
| `Map<String, Object>` | `additionalData` | Operation context, such as the IP address of the caller          |

#### Response

`OperationUserActionResponse`

| Type                      | Name        | Description                   |
|---------------------------|-------------|-------------------------------|
| `UserActionResult`        | `result`    | The result of the user action |
| `OperationDetailResponse` | `operation` | Operation detail              |


## Operation Templates

### Method 'createOperationTemplate'

Create an operation template.

#### Request

REST endpoint: `POST /rest/v4/operation/template/create`

`OperationTemplateCreateRequest`

| Type                           | Name                      | Description                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------|
| `String`                       | `templateName`            | The name of the operation template                                               |
| `String`                       | `operationType`           | The type of the operation that is created based on the template                  |
| `String`                       | `dataTemplate`            | Template for the operation data                                                  |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed types of authentication code                                             |
| `Long`                         | `maxFailureCount`         | How many failed attempts should be allowed for the operation                     |
| `Long`                         | `expiration`              | Operation expiration period in seconds                                           |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| `boolean`                      | `proximityCheckEnabled`   | Whether proximity check is enabled and TOTP seed should be generated.            |

#### Response

`OperationTemplateDetailResponse`

|   | Type                           | Name                      | Description                                                                      |
|:--|--------------------------------|---------------------------|----------------------------------------------------------------------------------|
|   | `Long`                         | `id`                      | Operation template ID                                                            |
|   | `String`                       | `templateName`            | The name of the operation template                                               |
|   | `String`                       | `operationType`           | The type of the operation that is created based on the template                  |
|   | `String`                       | `dataTemplate`            | Template for the operation data                                                  |
|   | `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed authentication code types                                                |
|   | `Long`                         | `maxFailureCount`         | How many failed attempts should be allowed for the operation                     |
|   | `Long`                         | `expiration`              | Operation expiration period in seconds                                           |
|   | `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
|   | `boolean`                      | `proximityCheckEnabled`   | Whether proximity check is enabled and TOTP seed should be generated.            |
  
### Method 'getAllTemplates'

Get all operation templates.

#### Request

REST endpoint: `POST /rest/v4/operation/template/list`

_Empty request body_

#### Response

`OperationTemplateListResponse`

Collection of items with the following structure:

| Type                           | Name                      | Description                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------|
| `Long`                         | `id`                      | Operation template ID                                                            |
| `String`                       | `templateName`            | The name of the operation template                                               |
| `String`                       | `operationType`           | The type of the operation that is created based on the template                  |
| `String`                       | `dataTemplate`            | Template for the operation data                                                  |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed authentication code types                                                |
| `Long`                         | `maxFailureCount`         | How many failed attempts should be allowed for the operation                     |
| `Long`                         | `expiration`              | Operation expiration period in seconds                                           |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| `boolean`                      | `proximityCheckEnabled`   | Whether proximity check is enabled and TOTP seed should be generated.            |

### Method 'getTemplateDetail'

Get an operation template detail.

#### Request

REST endpoint: `POST /rest/v4/operation/template/detail`

`OperationTemplateDetailRequest`

| Type   | Name | Description           |
|--------|------|-----------------------|
| `Long` | `id` | Operation template ID |

#### Response

`OperationTemplateDetailResponse`

| Type                           | Name                      | Description                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------|
| `Long`                         | `id`                      | Operation template ID                                                            |
| `String`                       | `templateName`            | The name of the operation template                                               |
| `String`                       | `operationType`           | The type of the operation that is created based on the template                  |
| `String`                       | `dataTemplate`            | Template for the operation data                                                  |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed authentication code types                                                |
| `Long`                         | `maxFailureCount`         | How many failed attempts should be allowed for the operation                     |
| `Long`                         | `expiration`              | Operation expiration period in seconds                                           |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| `boolean`                      | `proximityCheckEnabled`   | Whether proximity check is enabled and TOTP seed should be generated.            |

### Method 'updateOperationTemplate'

Update an operation template.

#### Request

REST endpoint: `POST /rest/v4/operation/template/update`

`OperationTemplateUpdateRequest`

| Type                           | Name                      | Description                                                                      |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------|
| `Long`                         | `id`                      | Operation template ID                                                            |
| `String`                       | `operationType`           | The type of the operation that is created based on the template                  |
| `String`                       | `dataTemplate`            | Template for the operation data                                                  |
| `List<AuthenticationCodeType>` | `authenticationCodeTypes` | Allowed authentication code types                                                |
| `Long`                         | `maxFailureCount`         | How many failed attempts should be allowed for the operation                     |
| `Long`                         | `expiration`              | Operation expiration period in seconds                                           |
| `String`                       | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| `boolean`                      | `proximityCheckEnabled`   | Whether proximity check is enabled and TOTP seed should be generated.            |

#### Response

`OperationTemplateDetailResponse`

| Type                            | Name                      | Description                                                                      |
|---------------------------------|---------------------------|----------------------------------------------------------------------------------|
| `Long`                          | `id`                      | Operation template ID                                                            |
| `String`                        | `templateName`            | The name of the operation template                                               |
| `String`                        | `operationType`           | The type of the operation that is created based on the template                  |
| `String`                        | `dataTemplate`            | Template for the operation data                                                  |
| `List<AuthenticationCodeTypes>` | `authenticationCodeTypes` | Allowed authentication code types                                                |
| `Long`                          | `maxFailureCount`         | How many failed attempts should be allowed for the operation                     |
| `Long`                          | `expiration`              | Operation expiration period in seconds                                           |
| `String`                        | `riskFlags`               | Risk flags for offline QR code. Uppercase letters without separator, e.g. `XFC`. |
| `boolean`                       | `proximityCheckEnabled`   | Whether proximity check is enabled and TOTP seed should be generated.            |

### Method 'removeOperationTemplate'

Remove an operation template.

#### Request

REST endpoint: `POST /rest/v4/operation/template/remove`

`OperationTemplateDeleteRequest`

| Type   | Name | Description           |
|--------|------|-----------------------|
| `Long` | `id` | Operation template ID |

#### Response

_empty response_

## Dynamic Factor Keys

### Method 'changePassword'

Change the password-related dynamic factor key.

#### Request

REST endpoint: `POST /rest/v4/password/change`

`ChangePasswordRequest`

| Type     | Name              | Description                             |
|----------|-------------------|-----------------------------------------|
| `String` | `activationId`    | A UUID4 identifier of an activation     |
| `String` | `applicationKey`  | A key (identifier) of an application    |
| `String` | `temporaryKeyId`  | Temporary key identifier for AEAD       |
| `String` | `nonce`           | Base64 encoded nonce for AEAD           |
| `String` | `encryptedData`   | Base64 encoded encrypted payload        |
| `String` | `protocolVersion` | Cryptography protocol version           |
| `Long`   | `timestamp`       | Unix timestamp in milliseconds for AEAD |

#### Response

`ChangePasswordResponse`

| Type     | Name            | Description                               |
|----------|-----------------|-------------------------------------------|
| `String` | `encryptedData` | Base64 encoded encrypted response payload |
| `Long`   | `timestamp`     | Unix timestamp in milliseconds for AEAD   |

### Method 'addBiometry'

Set up the biometry-related dynamic factor key.

#### Request

REST endpoint: `POST /rest/v4/biometry/add`

`AddBiometryRequest`

| Type     | Name              | Description                             |
|----------|-------------------|-----------------------------------------|
| `String` | `activationId`    | A UUID4 identifier of an activation     |
| `String` | `applicationKey`  | A key (identifier) of an application    |
| `String` | `temporaryKeyId`  | Temporary key identifier for AEAD       |
| `String` | `nonce`           | Base64 encoded nonce for AEAD           |
| `String` | `encryptedData`   | Base64 encoded encrypted payload        |
| `String` | `protocolVersion` | Cryptography protocol version           |
| `Long`   | `timestamp`       | Unix timestamp in milliseconds for AEAD |

#### Response

`AddBiometryResponse`

| Type     | Name            | Description                               |
|----------|-----------------|-------------------------------------------|
| `String` | `encryptedData` | Base64 encoded encrypted response payload |
| `Long`   | `timestamp`     | Unix timestamp in milliseconds for AEAD   |

### Method 'removeBiometry'

Remove the biometry-related dynamic factor key.

#### Request

REST endpoint: `POST /rest/v4/biometry/remove`

`RemoveBiometryRequest`

| Type     | Name           | Description                         |
|----------|----------------|-------------------------------------|
| `String` | `activationId` | A UUID4 identifier of an activation |

#### Response

_Empty response_


## Temporary Keys

### Method 'createTemporaryKey'

Create temporary key pair.

#### Request

REST endpoint: `POST /rest/v4/keystore/create`

`TemporaryPublicKeyRequest`

| Type                  | Name                      | Description                                                                  |
|-----------------------|---------------------------|------------------------------------------------------------------------------|
| `String`              | `jwt`                     | Signed JWT payload (HS384) with `TemporaryPublicKeyRequestClaims` structure. |

`TemporaryPublicKeyRequestClaims`

| Type     | Name             | Description      |
|----------|------------------|------------------|
| `String` | `applicationKey` | Application key  |
| `String` | `activationId`   | Activation ID    |
| `String` | `challenge`      | Random challenge |

#### Response

`TemporaryPublicKeyResponse`

| Type                  | Name                      | Description                                                                   |
|-----------------------|---------------------------|-------------------------------------------------------------------------------|
| `String`              | `jwt`                     | Signed JWT payload (ES384) with `TemporaryPublicKeyResponseClaims` structure. |

`TemporaryPublicKeyResponseClaims`

| Type     | Name             | Description                    |
|----------|------------------|--------------------------------|
| `String` | `applicationKey` | Application key                |
| `String` | `activationId`   | Activation ID                  |
| `String` | `challenge`      | Random challenge               |
| `String` | `keyId`          | Unique key pair ID             |
| `String` | `publicKey`      | Public key (encoded as Base64) |
| `Date`   | `expiration`     | Expiration timestamp.          |


### Method 'removeTemporaryKey'

Remove the temporary key pair.

#### Request

REST endpoint: `POST /rest/v4/keystore/remove`

`RemoveTemporaryPublicKeyRequest`

| Type     | Name | Description               |
|----------|------|---------------------------|
| `String` | `id` | Key pair ID to be removed |


#### Response

`RemoveTemporaryPublicKeyResponse`

| Type      | Name      | Description                                 |
|-----------|-----------|---------------------------------------------|
| `String`  | `id`      | Key pair ID to be removed                   |
| `boolean` | `removed` | Boolean indicating if the value was removed |


## Telemetry

### Method `report`

Generate a telemetry report.

#### Request

REST endpoint: `POST /rest/v4/telemetry/report`

`TelemetryReportRequest`

| Type                  | Name         | Description                   |
|-----------------------|--------------|-------------------------------|
| `String`              | `name`       | Telemetry report name         |
| `Map<String, Object>` | `parameters` | Telemetry report parameters   |

#### Response

`TelemetryReportResponse`

| Type                  | Name         | Description                    |
|-----------------------|--------------|--------------------------------|
| `String`              | `name`       | Telemetry report name          |
| `Map<String, Object>` | `reportData` | Telemetry report response data |

## Used enums

This chapter lists all enums used by PowerAuth Server services.

- `ActivationStatus` - Represents the status of activation, one of the following values:
    - CREATED
    - PENDING_COMMIT
    - ACTIVE
    - BLOCKED
    - REMOVED

- `ActivationOtpValidation` - Represents mode of validation of additional OTP (*deprecated*):
    - NONE
    - ON_KEY_EXCHANGE
    - ON_COMMIT

- `CommitPhase` - Specifies when activation is committed:
    - ON_COMMIT (default) - activation is committed in the `PENDING_COMMIT` state
    - ON_KEY_EXCHANGE - activation is committed during key exchange

- `AuthenticationCodeType` - Represents the type of the authentication code, one of the following values:
    - POSSESSION
    - POSSESSION_KNOWLEDGE
    - POSSESSION_BIOMETRY

- `OperationStatus` - Represents the possible operation status
    - PENDING
    - CANCELED
    - EXPIRED
    - APPROVED
    - REJECTED
    - FAILED

- `UserActionResult` - Represents the result of the user action when approving operation.
    - APPROVED
    - APPROVAL_FAILED
    - REJECTED
    - REJECT_FAILED
    - OPERATION_FAILED

## Used complex types

This chapter lists complex types used by PowerAuth Server services.

- `KeyValueMap` - Represents a map for storing key-value entries:
    - entry - list of entries (0..n)
        - key - String-based key
        - value - String-based value
