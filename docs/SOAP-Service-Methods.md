---
layout: page
title: SOAP Service Methods
---

This is a reference documentation of the methods published by the PowerAuth Server SOAP service. It reflects the SOAP service methods as they are defined in the [WSDL file](https://github.com/lime-company/powerauth-server/blob/master/powerauth-java-client-spring/src/main/resources/soap/wsdl/service.wsdl).

Following methods are published using the service:

- System Status
    - [getSystemStatus](#method-getsystemstatus)
    - [getErrorCodeList](#method-geterrorcodelist)
- Application Management
    - [getApplicationList](#method-getapplicationlist)
    - [getApplicationDetail](#method-getapplicationdetail)
    - [createApplication](#method-createapplication)
    - [createApplicationVersion](#method-createapplicationversion)
    - [unsupportApplicationVersion](#method-unsupportapplicationversion)
    - [supportApplicationVersion](#method-supportapplicationversion)
- Activation Management
    - [getActivationListForUser](#method-getactivationlistforuser)
    - [initActivation](#method-initactivation)
    - [prepareActivation](#method-prepareactivation)
    - [createActivation](#method-createactivation)
    - [commitActivation](#method-commitactivation)
    - [getActivationStatus](#method-getactivationstatus)
    - [removeActivation](#method-removeactivation)
    - [blockActivation](#method-blockactivation)
    - [unblockActivation](#method-unblockactivation)
- Signature Verification
    - [verifySignature](#method-verifysignature)
    - [verifyECDSASignature](#method-verifyecdsasignature)
- Offline Signatures
    - [createPersonalizedOfflineSignaturePayload](#method-createpersonalizedofflinesignaturepayload)
    - [createNonPersonalizedOfflineSignaturePayload](#method-createnonpersonalizedofflinesignaturepayload)
    - [verifyOfflineSignature](#method-verifyofflinesignature)
- Token Based Authentication
    - [createToken](#method-createtoken)
    - [validateToken](#method-validatetoken)
    - [removeToken](#method-removetoken)
- Vault Unlocking
    - [vaultUnlock](#method-vaultunlock)
- Signature Audit Log
    - [getSignatureAuditLog](#method-getsignatureauditlog)
- Activation History
    - [getActivationHistory](#method-getactivationhistory)
- Integration Management
    - [createIntegration](#method-createintegration)
    - [getIntegrationList](#method-getintegrationlist)
    - [removeIntegration](#method-removeintegration)
- Callback URL Management
    - [createCallbackUrl](#method-createcallbackurl)
    - [getCallbackUrlList](#method-getcallbckurllist)
    - [removeCallbackUrl](#method-removecallbackurl)
- End-To-End Encryption
    - [getNonPersonalizedEncryptionKey](#method-getnonpersonalizedencryptionkey)
    - [getPersonalizedEncryptionKey](#method-getpersonalizedencryptionkey)

## System status

Methods used for getting the PowerAuth Server system status.

### Method 'getSystemStatus'

Get the server status information.

#### Request

`GetSystemStatusRequest`

- _no attributes_

#### Response

`GetSystemStatusResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `status` | A constant value "OK". |
| `String` | `applicationName` | A name of the application, the default value is `powerauth`. The value may be overriden by setting`powerauth.service.applicationName` property.
| `String` | `applicationDisplayName` | A human readable name of the application, default value is "PowerAuth Server". The value may be overriden by setting `powerauth.service.applicationDisplayName` property. |
| `String` | `applicationEnvironment` | An identifier of the environment, by default, the value is empty. The value may be overriden by setting `powerauth.service.applicationEnvironment` property. |
| `String` | `version` | Version of PowerAuth server. |
| `String` | `buildTime` | Timestamp when the powerauth-server.war file was built. |
| `DateTime` | `timestamp` | A current system timestamp. |

### Method 'getErrorCodeList'

Get the list of all error codes that PowerAuth Server can return.

#### Request

`GetErrorCodeListRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `language` | Language code (ISO). |

#### Response

`GetErrorCodeListResponse`

| Type | Name | Description |
|------|------|-------------|
| `Error[]` | `errors` | A collection of errors. |

`GetErrorCodeListResponse.Error`

| Type | Name | Description |
|------|------|-------------|
| `String` | `code` | A code of the error. |
| `String` | `value` | A localized message for the error code. |

## Application management

Methods related to the management of applications and application versions.

### Method 'getApplicationList'

Get list of all applications that are present in this PowerAuth Server instance.

#### Request

`GetApplicationListRequest`

- _no attributes_

#### Response

`GetApplicationListResponse`

| Type | Name | Description |
|------|------|-------------|
| `Application[]` | `applications` | A collection of application objects |

`GetApplicationListRequest.Application`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | An application ID |
| `String` | `applicationName` | Application name |

### Method 'getApplicationDetail'

Get detail of application with given ID, including the list of versions.

#### Request

`GetApplicationDetailRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |

#### Response

`GetApplicationDetailResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationName` | An application name |
| `String` | `masterPublicKey` | Base64 encoded master public key |
| `Version[]` | `versions` | Collection of application versions |

`GetApplicationDetailResponse.Version`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `String` | `applicationVersionName` | An application version name, for example "1.0.3" |
| `String` | `applicationKey` | An application key associated with this version |
| `String` | `applicationSecret` | An application secret associated with this version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

### Method 'createApplication'

Create a new application with given name.

#### Request

`CreateApplicationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationName` | An application name |

#### Response

`CreateApplicationResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationName` | An application name |

### Method 'createApplicationVersion'

Create a new application version with given name for a specified application.

#### Request

`CreateApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationVersionName` | An application version name |

#### Response

`CreateApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `String` | `applicationVersionName` | An application version name |
| `String` | `applicationKey` | An application key associated with this version |
| `String` | `applicationSecret` | An application secret associated with this version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

### Method 'unsupportApplicationVersion'

Mark application version with given ID as "unsupported". Signatures constructed using application key and application secret associated with this versions will be rejected as invalid.

#### Request

`UnsupportApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |

#### Response

`UnsupportApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

### Method 'supportApplicationVersion'

Mark application version with given ID as "supported". Signatures constructed using application key and application secret associated with this versions will be evaluated the standard way.

#### Request

`SupportApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |

#### Response

`SupportApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

## Activation management

Methods related to activation management.

### Method 'getActivationListForUser'

Get the list of all activations for given user and application ID. If no application ID is provided, return list of all activations for given user.

#### Request

`GetActivationListForUserRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |

#### Response

`GetActivationListForUserResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Activation[]` | `activations` | A collection of activations for given user |

`GetActivationListForUserResponse.Activation`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `String` | `activationName` | An activation name |
| `String` | `extras` | Any custom attributes |
| `DateTime` | `timestampCreated` | A timestamp when the activation was created |
| `DateTime` | `timestampLastUsed` | A timestamp when the activation was last used |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier fo an application |
| `String` | `applicationName` | An application name |

### Method 'initActivation'

Create (initialize) a new application for given user and application. After calling this method, a new activation record is created in CREATED state.

#### Request

`InitActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `DateTime` | `timestampActivationExpire` | Timestamp after when the activation cannot be completed anymore |
| `Long` | `maxFailureCount` | How many failures are allowed for this activation |

#### Response

`InitActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A long UUID4 identifier of an activation |
| `String` | `activationIdShort` | A short (5+5 characters from Base32) identifier of an activation |
| `String` | `activationOTP` | An activation OTP (5+5 characters from Base32) |
| `String` | `activationSignature` | A signature of the activation data using Master Server Private Key |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |

### Method 'prepareActivation'

Assure a key exchange between PowerAuth Client and PowerAuth Server and prepare the activation with given ID to be committed. Only activations in CREATED state can be prepared. After successfully calling this method, activation is in OTP_USED state.

#### Request

`PrepareActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationIdShort` | A short (5+5 characters from Base32) identifier of an activation |
| `String` | `activationName` | A visual identifier of the activation |
| `String` | `extras` | Any extra parameter object |
| `String` | `activationNonce` | A base64 encoded activation nonce |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key |
| `String` | `encryptedDevicePublicKey` | A base64 encoded encrypted device public key |
| `String` | `applicationKey` | An application key |
| `String` | `applicationSignature` | An application signature |

#### Response

`PrepareActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A long UUID4 identifier of an activation |
| `String` | `activationNonce` | A base64 encoded activation nonce |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key |
| `String` | `encryptedServerPublicKey` | A base64 encoded encrypted server public key |
| `String` | `encryptedServerPublicKeySignature` | A base64 encoded signature of the activation data using Master Server Private Key |

### Method 'createActivation'

Create an activation for given user and application, with provided maximum number of failed attempts and expiration timestamp, including a key exchange between PowerAuth Client and PowerAuth Server. Prepare the activation to be committed later. After successfully calling this method, activation is in OTP_USED state.

#### Request

`CreateActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | User ID |
| `Long` | `applicationId` | Application ID |
| `DateTime` | `timestampActivationExpire` | Timestamp after when the activation cannot be completed anymore |
| `Long` | `maxFailureCount` | How many failures are allowed for this activation |
| `String` | `identity` | An identity identifier string for this activation |
| `String` | `activationName` | A visual identifier of the activation |
| `String` | `extras` | Any extra parameter object |
| `String` | `activationNonce` | A base64 encoded activation nonce |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key |
| `String` | `encryptedDevicePublicKey` | A base64 encoded encrypted device public key |
| `String` | `applicationKey` | An application key |
| `String` | `applicationSignature` | An application signature |

#### Response

`CreateActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A long UUID4 identifier of an activation |
| `String` | `activationNonce` | A base64 encoded activation nonce |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key |
| `String` | `encryptedServerPublicKey` | A base64 encoded encrypted server public key |
| `String` | `encryptedServerPublicKeySignature` | A base64 encoded signature of the activation data using Master Server Private Key |

### Method 'commitActivation'

Commit activation with given ID. Only non-expired activations in OTP_USED state can be committed. After successful commit, activation is in ACTIVE state.

#### Request

`CommitActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`CommitActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `Boolean` | `activated` | Flag indicating if the activation was committed |

### Method 'getActivationStatus'

Get status information and all important details for activation with given ID.

#### Request

`GetActivationStatusRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`GetActivationStatusResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `String` | `activationName` | An activation name |
| `String` | `userId` | An identifier of a user |
| `String` | `extras` | Any custom attributes |
| `Long` | `applicationId` | An identifier fo an application |
| `String` | `encryptedStatusBlob` | An encrypted blob with status information |
| `DateTime` | `timestampCreated` | A timestamp when the activation was created |
| `DateTime` | `timestampLastUsed` | A timestamp when the activation was last used |
| `String` | `activationIdShort` | A short (5+5 characters from Base32) identifier of an activation |
| `String` | `activationOTP` | An activation OTP (5+5 characters from Base32) |
| `String` | `activationSignature` | A signature of the activation data using Master Server Private Key |

### Method 'removeActivation'

Remove activation with given ID. This operation is irreversible. Activations can be removed in any state. After successfully calling this method, activation is in REMOVED state.

#### Request

`RemoveActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`RemoveActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `Boolean` | `removed` | Flag indicating if the activation was removed |

### Method 'blockActivation'

Block activation with given ID. Activations can be blocked in ACTIVE state only. After successfully calling this method, activation is in BLOCKED state.

#### Request

`BlockActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `reason` | Reason why activation is being blocked (default: NOT_SPECIFIED) |

#### Response

`BlockActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |

### Method 'unblockActivation'

Unblock activation with given ID. Activations can be unblocked in BLOCKED state only. After successfully calling this method, activation is in ACTIVE state and failed attempt counter is set to 0.

#### Request

`UnblockActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`UnblockActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |

## Signature verification

Methods related to signature verification.

### Method 'verifySignature'

Verify signature correctness for given activation, application key, data and signature type.

#### Request

`VerifySignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `applicationKey` | An key (identifier) of an application, associated with given application version |
| `String` | `data` | Base64 encoded data for the signature |
| `String` | `signature` | PowerAuth signature |
| `SignatureType` | `signatureType` | PowerAuth signature type |

#### Response

`VerifySignatureResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of the application |
| `SignatureType` | `signatureType` | Type of the signature that was used for the computation of the signature. |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `Integer` | `remainingAttempts` | How many attempts are left for authentication using this activation |
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |

### Method 'verifyECDSASignature'

Verify asymmetric ECDSA signature correctness for given activation and data.

#### Request

`VerifyECDSASignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `data` | Base64 encoded data for the signature |
| `String` | `signature` | Base64 encoded ECDSA signature |

#### Response

`VerifyECDSASignatureResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `signatureValid` | Indicates if the ECDSA signature was correctly validated or if it was invalid (incorrect) |

### Method 'createPersonalizedOfflineSignaturePayload'

Create a data payload used as a challenge for personalized off-line signatures.

#### Request

`CreatePersonalizedOfflineSignaturePayloadRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `data` | Data for the signature, for normalized value see the [Offline Signatures QR code](https://github.com/lime-company/powerauth-webflow/wiki/Off-line-Signatures-QR-Code) documentation |

#### Response

`CreatePersonalizedOfflineSignaturePayloadResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `offlineData` | Data for QR code in format: `{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}` |
| `String` | `nonce` | Random cryptographic nonce, 16B encoded in Base64, same nonce as in `offlineData` (available separately for easy access) |

### Method 'createNonPersonalizedOfflineSignaturePayload'

Create a data payload used as a challenge for non-personalized off-line signatures.

#### Request

`CreateNonPersonalizedOfflineSignaturePayloadRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationId` | An identifier of an application |
| `String` | `data` | Data for the signature, for normalized value see the [Offline Signatures QR code](https://github.com/lime-company/powerauth-webflow/wiki/Off-line-Signatures-QR-Code) documentation |

#### Response

`CreateNonPersonalizedOfflineSignaturePayloadResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `offlineData` | Data for QR code in format: `{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}` |
| `String` | `nonce` | Random cryptographic nonce, 16B encoded in Base64, same nonce as in `offlineData` (available separately for easy access) |

### Method 'verifyOfflineSignature'

Verify off-line signature of provided data.

#### Request

`VerifyOfflineSignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `data` | Base64 encoded data for the signature, normalized data for signatures. |
| `String` | `signature` | Actual signature value. |
| `SignatureType` | `signatureType` | Type of the signature |

#### Response

`VerifyOfflineSignatureResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of the application |
| `SignatureType` | `signatureType` | Type of the signature that was used for the computation of the signature. |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `Integer` | `remainingAttempts` | How many attempts are left for authentication using this activation |
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |

### Method 'createToken'

Create a new token for the simple token-based authentication.

#### Request

`CreateTokenRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation. |
| `SignatureType` | `signatureType` | Type of the signature (factors) used for token creation. |
| `String` | `ephemeralPublicKey` | Ephemeral public key used for request/response encryption. Base64 encoded bytes of the encoded public key. |

#### Response

`CreateTokenResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `mac` | Data MAC value, Base64 encoded. |
| `String` | `encryptedData` | Encrypted data, Base64 encoded bytes. |

### Method 'validateToken'

Validate token digest used for the simple token-based authentication.

#### Request

`ValidateTokenRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `tokenId` | An identifier of the token. |
| `String` | `tokenDigest` | Digest computed during the token based authentication. |
| `String` | `nonce` | Cryptographic nonce. Random 16B, Base64 encoded. |
| `Long` | `timestamp` | Token digest timestamp, Unix timestamp format. |

#### Response

`ValidateTokenResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `tokenValid` | Information about the validation result - if true, token digest was valid. |
| `String`  | `activationId` | An identifier of an activation |
| `String`  | `userId` | An identifier of a user |
| `Long`    | `applicationId` | An identifier of the application |
| `SignatureType` | `signatureType` | Type of the signature that was used for the computation of the signature.  |

### Method 'removeToken'

Remove token with given ID.

#### Request

`RemoveTokenRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `tokenId` | An identifier of the token. |

#### Response

`RemoveTokenResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `removed` | True in case token was removed, false in case token with given ID was already not present. |

## Vault unlocking

Methods related to secure vault.

### Method 'vaultUnlock'

Get the encrypted vault unlock key upon successful authentication using PowerAuth Signature.

#### Request

`VaultUnlockRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `applicationKey` | An key (identifier) of an application, associated with given application version |
| `String` | `data` | Base64 encoded data for the signature |
| `String` | `signature` | PowerAuth signature |
| `SignatureType` | `signatureType` | PowerAuth signature type |
| `String` | `reason` | Reason why vault is being unlocked (default: NOT_SPECIFIED) |

#### Response

`VaultUnlockResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `Integer` | `remainingAttempts` | How many attempts are left for authentication using this activation |
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |
| `String` | `encryptedVaultEncryptionKey` | Encrypted key for vault unlocking |

## Signature audit

Methods related to signature auditing.

### Method 'getSignatureAuditLog'

Get the signature audit log for given user, application and date range. In case no application ID is provided, event log for all applications is returned.

#### Request

`SignatureAuditRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `DateTime` | `timestampFrom` | Timestamp from which to fetch the log |
| `DateTime` | `timestampTo` | Timestamp to which to fetch the log |

#### Response

`SignatureAuditResponse`

| Type | Name | Description |
|------|------|-------------|
| `Item[]` | `items` | Collection of signature audit logs |

`SignatureAuditResponse.Item`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | Record ID |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `String` | `activationId` | An identifier of an activation |
| `Long` | `activationCounter` | A counter value at the moment of a signature verification |
| `ActivationStatus` | `activationStatus` | An activation status at the moment of a signature verification |
| `KeyValueMap` | `additionalInfo` | Key-value map with additional information |
| `String` | `dataBase64` | A base64 encoded data sent with the signature |
| `SignatureType` | `signatureType` | Requested signature type |
| `String` | `signature` | Submitted value of a signature |
| `String` | `note` | Extra info about the result of the signature verification |
| `Boolean` | `valid` | Flag indicating if the provided signature was valid |
| `DateTime` | `timestampCreated` | Timestamp when the record was created |

## Activation history

Get activation status change log.

### Method 'getActivationHistory'

Get the status change log for given activation and date range.

#### Request

`ActivationHistoryRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | Activation ID |
| `DateTime` | `timestampFrom` | Timestamp from which to fetch the changes |
| `DateTime` | `timestampTo` | Timestamp to which to fetch the changes |

#### Response

`ActivationHistoryResponse`

| Type | Name | Description |
|------|------|-------------|
| `Item[]` | `items` | Collection of activation change logs |

`ActivationHistoryResponse.Item`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | Change ID |
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status at the moment of a signature verification |
| `DateTime` | `timestampCreated` | Timestamp when the record was created |

## Integration management

Methods used for managing integration credentials for PowerAuth Server.

### Method 'createIntegration'

Create a new integration with given name, automatically generate credentials for the integration.

#### Request

`CreateIntegrationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `name` | New integration name. |

#### Response

`CreateIntegrationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Integration identifier (UUID4). |
| `String` | `name` | A name of the integration. |
| `String` | `clientToken` | An integration client token (serves as a "username"). |
| `String` | `clientSecret` | An integration client secret (serves as a "password"). |

### Method 'getIntegrationList'

Get the list of all integrations that are configured on the server instance.

#### Request

`GetIntegrationListRequest`

- _no attributes_

#### Response

`GetIntegrationListResponse`

| Type | Name | Description |
|------|------|-------------|
| `Item[]` | `items` | Collection of integration records. |

`GetIntegrationListResponse.Item`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Integration identifier (UUID4). |
| `String` | `name` | A name of the integration. |
| `String` | `clientToken` | An integration client token (serves as a "username"). |
| `String` | `clientSecret` | An integration client secret (serves as a "password"). |

### Method 'removeIntegration'

Remove integration with given ID.

#### Request

`RemoveIntegrationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an integration to be removed. |

#### Response

`RemoveIntegrationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an integration to be removed. |
| `Boolean` | `removed` | Flag specifying if an integration was removed or not. |

### Method 'createCallbackUrl'

Creates a callback URL with given parameters.

#### Request

`CreateCallbackUrlRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | Associated application ID. |
| `String` | `name` | Callback URL name, for visual identification. |
| `String` | `callbackUrl` | Callback URL that should be notified about activation status updates. |

#### Response

`CreateCallbackUrlResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Callback URL identifier (UUID4). |
| `Long` | `applicationId` | Associated application ID. |
| `String` | `name` | Callback URL name, for visual identification. |
| `String` | `callbackUrl` | Callback URL that should be notified about activation status updates. |

### Method 'getCallbackUrlList'

Get the list of all callbacks for given application.

#### Request

`GetCallbackUrlListRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | Application ID for which to fetch callback URLs. |

#### Response

`GetCallbackUrlListResponse`

| Type | Name | Description |
|------|------|-------------|
| `CallbackUrlList[]` | `callbackUrlList` | Callback URL list. |

`GetCallbackUrlListResponse.CallbackUrlList`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Callback URL identifier (UUID4). |
| `Long` | `applicationId` | Associated application ID. |
| `String` | `name` | Callback URL name, for visual identification. |
| `String` | `callbackUrl` | Callback URL that should be notified about activation status updates. |

### Method 'removeCallbackUrl'

Remove callback URL with given ID.

#### Request

`RemoveCallbackUrlRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an callback URL to be removed. |

#### Response

`RemoveCallbackUrlResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an callback URL to be removed. |
| `Boolean` | `removed` | Flag specifying if a callback URL was removed or not. |

## End-To-End Encryption

Methods used for establishing a context for end-to-end encryption.

### Method 'getNonPersonalizedEncryptionKey'

Establishes a context required for performing a non-personalized (application specific) end-to-end encryption.

#### Request

`GetNonPersonalizedEncryptionKeyRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationKey` | Application version identification  |
| `String` | `sessionIndex` | Random session index used to generate session based key, in case `null` is provided, `encryptionKeyIndex` will be autogenerated in response. |
| `String` | `ephemeralPublicKey` | Ephemeral public key used for deriving a shared secret. |

#### Response

`GetNonPersonalizedEncryptionKeyResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationKey` | Application version identification  |
| `Long` | `applicationId` | Application ID associated with provided version  |
| `String` | `encryptionKeyIndex` | Session index used to generate session based key. |
| `String` | `encryptionKey` | Derived key used as a base for ad-hoc key derivation. |
| `String` | `ephemeralPublicKey` | Ephemeral public key used for deriving a shared secret. |

### Method 'getPersonalizedEncryptionKey'

Establishes a context required for performing a personalized (activation specific) end-to-end encryption.

#### Request

`GetPersonalizedEncryptionKeyRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | Activation ID  |
| `String` | `sessionIndex` | Random session index used to generate session based key, in case `null` is provided, `encryptionKeyIndex` will be autogenerated in response. |

#### Response

`GetPersonalizedEncryptionKeyResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | Activation ID  |
| `String` | `encryptionKeyIndex` | Session index used to generate session based key. |
| `String` | `encryptionKey` | Derived key used as a base for ad-hoc key derivation. |

## Used enums

This chapter lists all enums used by PowerAuth Server SOAP service.

- `ActivationStatus` - Represents the status of activation, one of the following values:
    - CREATED
    - OTP_USED
    - ACTIVE
    - BLOCKED
    - REMOVED

- `SignatureType` - Represents the type of the signature, one of the following values:
    - POSSESSION
    - KNOWLEDGE
    - BIOMETRY
    - POSSESSION_KNOWLEDGE
    - POSSESSION_BIOMETRY
    - POSSESSION_KNOWLEDGE_BIOMETRY

## Used complex types

This chapter lists complex types used by PowerAuth Server SOAP service.

- `KeyValueMap` - Represents a map for storing key-value entries:
    - entry - list of entries (0..n)
        - key - String-based key
        - value - String-based value

## Documentation template

When adding documentation for a new method, use this template:

### Method 'methodName'

Lorem ipsum description.

#### Request

`RequestObject`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | Lorem ipsum |

#### Response

`ResponseObject`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | Lorem ipsum |
