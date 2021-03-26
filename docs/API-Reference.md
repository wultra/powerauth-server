# PowerAuth Server API Reference

<!-- template api -->

This is a reference documentation of the methods published by the PowerAuth Server RESTful service.

## Swagger Documentation

The REST service methods can be browsed using Swagger on deployed PowerAuth instance:

- [http://localhost:8080/powerauth-java-server/swagger-ui.html](http://localhost:8080/powerauth-java-server/swagger-ui.html)

## Actuator Service

PowerAuth Server Supports the standard Spring actuator service. It is available on [http://localhost:8080/powerauth-java-server/actuator](http://localhost:8080/powerauth-java-server/actuator)

## Used enums

This chapter lists all enums used by PowerAuth Server SOAP service.

- `ActivationStatus` - Represents the status of activation, one of the following values:
    - CREATED
    - PENDING_COMMIT
    - ACTIVE
    - BLOCKED
    - REMOVED

- `ActivationOtpValidation` - Represents mode of validation of additional OTP:
    - NONE
    - ON_KEY_EXCHANGE
    - ON_COMMIT

- `SignatureType` - Represents the type of the signature, one of the following values:
    - POSSESSION
    - KNOWLEDGE
    - BIOMETRY
    - POSSESSION_KNOWLEDGE
    - POSSESSION_BIOMETRY
    - POSSESSION_KNOWLEDGE_BIOMETRY

- `RecoveryCodeStatus` - Represent status of the recovery code, one of the following values:
    - CREATED
    - ACTIVE
    - BLOCKED
    - REVOKED

- `RecoveryPukStatus` - Represents status of the recovery PUK, one of the following values:
    - VALID
    - USED
    - INVALID

## Used complex types

This chapter lists complex types used by PowerAuth Server SOAP service.

- `KeyValueMap` - Represents a map for storing key-value entries:
    - entry - list of entries (0..n)
        - key - String-based key
        - value - String-based value

## System Status

Methods used for getting the PowerAuth Server system status.

<!-- begin api GET /rest/v3/status -->
### Get System Status

<!-- begin remove -->
REST endpoint: `POST /rest/v3/status`
<!-- end -->

Get the server status information.

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "status": "OK",
    "applicationName": "powerauth-server",
    "applicationDisplayName": "PowerAuth Server",
    "applicationEnvironment": "uat",
    "version": "1.0.0",
    "buildTime": "2021-01-11T16:56:14.154+00:00",
    "timestamp": "2021-03-26T17:27:31.218+00:00"
  }
}
```

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
<!-- end -->

<!-- begin api GET /rest/v3/errors -->
### Get Error List Codes

Get the list of error codes that API may return.

<!-- begin remove -->
REST endpoint: `GET /rest/v3/errors`
<!-- end -->

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "errors": [
      {
        "code": "ERR0000",
        "value": "Unknown error occurred."
      },
      {
        "code": "ERR0001",
        "value": "No user ID was set."
      }
  ]}
}
```

`GetErrorCodeListResponse`

| Type | Name | Description |
|------|------|-------------|
| `Error[]` | `errors` | A collection of errors. |

`GetErrorCodeListResponse.Error`

| Type | Name | Description |
|------|------|-------------|
| `String` | `code` | A code of the error. |
| `String` | `value` | A localized message for the error code. |
<!-- end -->

## Application management

Methods related to the management of applications and application versions.

<!-- begin api GET /rest/v3/applications -->
### Get Application List

<!-- begin remove -->
REST endpoint: `GET /rest/v3/applications`
<!-- end -->

Get list of all applications that are present in this PowerAuth Server instance.

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "applications": [
      {
        "id": 1,
        "applicationName": "test1-mobile",
        "applicationRoles": []
      },
      {
        "id": 2,
        "applicationName": "test2-mobile",
        "applicationRoles": []
      }
  ]}
}
```

`GetApplicationListResponse`

| Type | Name | Description |
|------|------|-------------|
| `Application[]` | `applications` | A collection of application objects |

`GetApplicationListRequest.Application`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | An application ID |
| `String` | `applicationName` | Application name |
| `String[]` | `applicationRoles` | Roles assigned to the application |
<!-- end -->

<!-- begin api GET /rest/v3/applications/detail/{id} -->
### Get Application Detail

<!-- begin remove -->
REST endpoint: `GET /rest/v3/applications/detail/{id}`
<!-- end -->

Get detail of application with given ID or name, including the list of versions.

`GetApplicationDetailRequest`

_//TODO: Add endpoint for detail by the name_

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationName` | An application name (required if applicationId not specified) |

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "applicationId": 3,
    "applicationName": "demo",
    "applicationRoles": [],
    "masterPublicKey": "BGyETh1n9W20nHaxj9n2Fm72N/0/i7gKcBSyL4nCqLAqsD/tkrzPA3dibvmYXGL2NPTusUhFISu2a03PtLijtFs=",
    "versions": [
      {
        "applicationVersionId": 1,
        "applicationVersionName": "default",
        "applicationKey": "QdGi0mefDLSauL2tiQwSOw==",
        "applicationSecret": "Ec1RlAr6B3Il6wEg9OQLXA==",
        "supported": true
      }
    ]
  }
}
```

`GetApplicationDetailResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationName` | An application name |
| `String[]` | `applicationRoles` | Roles assigned to the application |
| `String` | `masterPublicKey` | Base64 encoded master public key |
| `Version[]` | `versions` | Collection of application versions |

`GetApplicationDetailResponse.Version`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `String` | `applicationVersionName` | An application version name, for example "1.0.3" |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `applicationSecret` | An application secret associated with this version |
| `Boolean` | `supported` | Flag indicating if this application is supported |
<!-- end -->

<!-- begin api GET /rest/v3/application/detail/${id}/versions -->
### Lookup Application By Version Key

<!-- begin remove -->
REST endpoint: `GET /rest/v3/application/detail/{id}/versions`
<!-- end -->

Find application using application key.

#### Request

#### Query Params

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "applicationId": 3
  }
}
```

`LookupApplicationByAppKeyResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
<!-- end -->

<!-- begin api POST /rest/v3/applications -->
### Create Application

<!-- begin remove -->
REST endpoint: `POST /rest/v3/applications`
<!-- end -->

Create a new application with given name.

#### Request

```json
{
	"requestObject": {
		"applicationName": "api-experiment"
	}
}
```

`CreateApplicationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationName` | An application name |

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "applicationId": 1,
    "applicationName": "api-experiment",
    "applicationRoles": []
  }
}
```

`CreateApplicationResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationName` | An application name |
| `String[]` | `applicationRoles` | Roles assigned to the application |
<!-- end -->

<!-- begin api POST /rest/v3/applications/detail/{id}/versions -->
### Create Application Version

<!-- begin remove -->
REST endpoint: `POST /rest/v3/applications/detail/{id}/versions`
<!-- end -->

Create a new application version with given name for a specified application.

#### Request

_// TODO: Rename the parameter_

```json
{
	"requestObject": {
		"applicationVersionName": "1.0.0"
	}
}

```

`CreateApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationVersionName` | An application version name |

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "applicationVersionId": 830,
    "applicationVersionName": "1.0.0",
    "applicationKey": "xb9pA2hdtpNZ3sVIOmsWKA==",
    "applicationSecret": "MKjUCHqJ1HzQDsm6vt6n8w==",
    "supported": true
  }
}
```

`CreateApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `String` | `applicationVersionName` | An application version name |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `applicationSecret` | An application secret associated with this version |
| `Boolean` | `supported` | Flag indicating if this application is supported |
<!-- end -->

<!-- begin api POST /rest/v3/application/version/{id}/unsupport -->
### Unsupport Application Version

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/version/{id}/unsupport`
<!-- end -->

Mark application version with given ID as "unsupported". Signatures constructed using application key and application secret associated with this versions will be rejected as invalid.

#### Request

```json
{
	"requestObject": {
		"applicationVersionId": 830
	}
}
```

`UnsupportApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "applicationVersionId": 830,
    "supported": false
  }
}
```

`UnsupportApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `Boolean` | `supported` | Flag indicating if this application is supported |
<!-- end -->

<!-- begin api POST /rest/v3/application/version/{id}/support -->
### Support Application Version

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/version/support`
<!-- end -->

Mark application version with given ID as "supported". Signatures constructed using application key and application secret associated with this versions will be evaluated the standard way.

#### Request

```json
{
	"requestObject": {
		"applicationVersionId": 830
	}
}
```

`SupportApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "applicationVersionId": 830,
    "supported": true
  }
}
```

`SupportApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `Boolean` | `supported` | Flag indicating if this application is supported |
<!-- end -->

## Activation management

Methods related to activation management.

<!-- begin api POST /rest/v3/activation/init -->
### Initialize Activation

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/init`
<!-- end -->

Create (initialize) a new activation for given user and application. If both `activationOtpValidation` and `activationOtp` optional parameters are set, then the same value of activation OTP must be later provided for the confirmation.

After calling this method, a new activation record is created in CREATED state.

#### Request

#### Minimal Request

```json
{
	"requestObject": {
		"userId": "petr",
		"applicationId": 3
	}
}
```

#### Full Request

_//TODO: Prepare example_

`InitActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `DateTime` | `timestampActivationExpire` | Timestamp after when the activation cannot be completed anymore |
| `Long` | `maxFailureCount` | How many failures are allowed for this activation |
| `ActivationOtpValidation` | `activationOtpValidation` | Optional activation OTP validation mode |
| `String` | `activationOtp` | Optional activation OTP |

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "activationId": "e892e226-40a2-452e-9958-ec91ac6629a9",
    "activationCode": "5FI5W-IUDWO-BUTQA-7WSMA",
    "activationSignature": "MEUCIQDFWeNwQrA2uG8WcsVKWS1YBksYRR+6TNohBv79VzAIuAIgDcITfZWloV1pRP6l2qA+y8cpzpCcR5L52c8FW+LmV+c=",
    "userId": "petr",
    "applicationId": 3
  }
}
```

`InitActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String` | `activationCode` | Activation code which uses 4x5 characters in Base32 encoding separated by a "-" character |
| `String` | `activationSignature` | A signature of the activation data using Master Server Private Key |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
<!-- end -->

<!-- begin api POST /rest/v3/activation/prepare -->
### Prepare Activation

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/prepare`
<!-- end -->

Assure a key exchange between PowerAuth Client and PowerAuth Server and prepare the activation with given ID to be committed. Only activations in CREATED state can be prepared.

If optional `activationOtp` value is present in ECIES payload, then the value must match the OTP stored in activation's record and OTP validation mode must be ON_KEY_EXCHANGE.

After successfully calling this method, activation is in PENDING_COMMIT or ACTIVE state, depending on the presence of an activation OTP in ECIES payload:

| Situation | State after `prepareActivation` |
|-----------|---------------------------------|
| OTP is not required and is not provided             | `PENDING_COMMIT` |
| OTP is required and is valid                        | `ACTIVE`         |
| OTP is required, but is not valid                   | `CREATED`        |
| OTP is required, but is not valid, no attempts left | `REMOVED`        |

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`PrepareActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationCode` | Activation code which uses 4x5 characters in Base32 encoding separated by a "-" character |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key for ECIES |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` | Base64 encoded mac of key and data for ECIES |
| `String` | `nonce` | Base64 encoded nonce for IV derivation for ECIES |

ECIES request should contain following data (as JSON):
 - `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
 - `devicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC`  (base64-encoded).
 - `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.
 - `platform` - User device platform, e.g. `ios`, `android`, `hw` and `unknown`.
 - `deviceInfo` - Information about user device, e.g. `iPhone12,3`.
 - `activationOtp` - Optional activation OTP for confirmation. The value must be provided in case that activation was initialized with `ActivationOtpValidation` set to `ON_KEY_EXCHANGE`.

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`PrepareActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String` | `userId` | User ID |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |
| `ActivationStatus` | `activationStatus` | An activation status |

ECIES response contains following data (as JSON):
 - `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
 - `serverPublicKey` - Public key `KEY_SERVER_PUBLIC` of the server (base64-encoded).
 - `ctrData` - Initial value for hash-based counter (base64-encoded).
 - `activationRecovery` - Information about activation recovery which is sent only in case activation recovery is enabled.
    - `recoveryCode` - Recovery code which uses 4x5 characters in Base32 encoding separated by a "-" character.
    - `puk` - Recovery PUK with unique PUK used as secret for the recovery code.
<!-- end -->

<!-- begin api POST /rest/v3/activation/create -->
### Create New Activation

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/create`
<!-- end -->

Create an activation for given user and application, with provided maximum number of failed attempts and expiration timestamp, including a key exchange between PowerAuth Client and PowerAuth Server. Prepare the activation to be committed later.

If optional `activationOtp` value is set, then the activation's OTP validation mode is set to `ON_COMMIT`. The same OTP value must be later provided in [CommitActivation](#method-commitactivation) method, to complete the activation.

After successfully calling this method, activation is in PENDING_COMMIT state.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`CreateActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | User ID |
| `DateTime` | `timestampActivationExpire` | Timestamp after when the activation cannot be completed anymore |
| `Long` | `maxFailureCount` | How many failures are allowed for this activation |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key for ECIES |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |
| `String` | `nonce` | Base64 encoded nonce for IV derivation for ECIES |
| `String` | `activationOtp` | Optional activation OTP |

ECIES request should contain following data (as JSON):
 - `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
 - `devicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC`  (base64-encoded).
 - `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.
 - `platform` - User device platform, e.g. `ios`, `android`, `hw` and `unknown`.
 - `deviceInfo` - Information about user device, e.g. `iPhone12,3`.

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CreateActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |

ECIES response contains following data (as JSON):
 - `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
 - `serverPublicKey` - Public key `KEY_SERVER_PUBLIC` of the server (base64-encoded).
 - `ctrData` - Initial value for hash-based counter (base64-encoded).
 - `activationRecovery` - - `activationRecovery` - Information about activation recovery which is sent only in case activation recovery is enabled.
   - `recoveryCode` - Recovery code which uses 4x5 characters in Base32 encoding separated by a "-" character.
   - `puk` - Recovery PUK with unique PUK used as secret for the recovery code.
<!-- end -->

<!-- begin api PUT /rest/v3/activation/{id}/otp -->
### Update Activation OTP

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/{id}/otp`
<!-- end -->

Update activation OTP for activation with given ID. Only non-expired activations in PENDING_COMMIT state, with OTP validation set to NONE or ON_COMMIT, can be altered.

After successful, activation OTP is updated and the OTP validation is set to ON_COMMIT.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {
        "activationOtp": "122272",
        "externalUserId": "joe-doe"
    }
}
```

`UpdateActivationOtpRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | An identifier of an activation |
| `String` | `externalUserId` | User ID of user who changes the activation. Use null value if activation owner caused the change. |
| `String` | `activationOtp` | A new value of activation OTP |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`UpdateActivationOtpResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `boolean` | `updated` | Flag indicating that OTP has been updated |
<!-- end -->

<!-- begin api POST /rest/v3/activation/{id}/commit -->
### Commit Activation

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/{id}/commit`
<!-- end -->

Commit activation with given ID. Only non-expired activations in PENDING_COMMIT state can be committed.

If optional `activationOtp` value is set, then the value must match the OTP stored in activation's record and OTP validation mode must be `ON_COMMIT`.

After successful commit, activation is in ACTIVE state.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {
        "activationOtp": "122272",
        "externalUserId": "joe-doe"
    }
}
```

`CommitActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | An identifier of an activation |
| `String` | `externalUserId` | User ID of user who committed the activation. Use null value if activation owner caused the change. |
| `String` | `activationOtp` | An optional activation OTP for confirmation. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {
        "acticationId": "121212-1...1-233322"
    }
}
```

`CommitActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `Boolean` | `activated` | Flag indicating if the activation was committed |
<!-- end -->

<!-- begin api GET /rest/v3/activation/{id} -->
### Get Activation Detail

<!-- begin remove -->
REST endpoint: `GET /rest/v3/activation/status`
<!-- end -->

Get status information and all important details for activation with given ID.

#### Request

`GetActivationStatusRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | An identifier of an activation |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {
        "acticationId": "121212-1...1-233322"
    }
}
```

`GetActivationStatusResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `ActivationOtpValidation` | `activationOtpValidation` | An activation OTP validation mode |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `String` | `activationName` | An activation name |
| `String` | `userId` | An identifier of a user |
| `String` | `extras` | Any custom attributes |
| `String` | `platform` | User device platform, e.g. `ios`, `android`, `hw` and `unknown` |
| `String` | `deviceInfo` | Information about user device, e.g. `iPhone12,3` |
| `String[]` | `activationFlags` | Activation flags |
| `Long` | `applicationId` | An identifier fo an application |
| `DateTime` | `timestampCreated` | A timestamp when the activation was created |
| `DateTime` | `timestampLastUsed` | A timestamp when the activation was last used |
| `DateTime` | `timestampLastChange` | A timestamp of last activation status change |
| `String` | `encryptedStatusBlob` | An encrypted blob with status information |
| `String` | `activationCode` | Activation code which uses 4x5 characters in Base32 encoding separated by a "-" character |
| `String` | `activationSignature` | A signature of the activation data using Master Server Private Key |
| `String` | `devicePublicKeyFingerprint` | Numeric fingerprint of device public key, used during activation for key verification |
| `Long` | `version` | Activation version |
<!-- end -->

<!-- begin api POST /rest/v3/activation/{id}/remove -->
### Remove Activation

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/remove`
<!-- end -->

Remove activation with given ID. This operation is irreversible. Activations can be removed in any state. After successfully calling this method, activation is in REMOVED state.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`RemoveActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | An identifier of an activation |
| `String` | `externalUserId` | User ID of user who removed the activation. Use null value if activation owner caused the change. |
| `Boolean` | `revokeRecoveryCodes` | An optional flag that indicates if recovery codes, that were created in the scope of the removed activation, should be also revoked. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RemoveActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `Boolean` | `removed` | Flag indicating if the activation was removed |
<!-- end -->

<!-- begin api GET /rest/v3/activation/list -->
### Get Activations List

<!-- begin remove -->
REST endpoint: `GET /rest/v3/activation/list`
<!-- end -->

Get the list of all activations for given user and application ID. If no application ID is provided, return list of all activations for given user.

#### Request

`GetActivationListForUserRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

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
| `String` | `platform` | User device platform, e.g. `ios`, `android`, `hw` and `unknown` |
| `String` | `deviceInfo` | Information about user device, e.g. `iPhone12,3` |
| `String[]` | `activationFlags` | Activation flags |
| `DateTime` | `timestampCreated` | A timestamp when the activation was created |
| `DateTime` | `timestampLastUsed` | A timestamp when the activation was last used |
| `DateTime` | `timestampLastChange` | A timestamp of last activation status change |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier fo an application |
| `String` | `applicationName` | An application name |
| `Long` | `version` | Activation version |
<!-- end -->

<!-- begin api POST /rest/v3/activation/{id}/block -->
### Block Activation

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/block`
<!-- end -->

Block activation with given ID. Activations can be blocked in ACTIVE state only. After successfully calling this method, activation is in BLOCKED state.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`BlockActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `reason` | Reason why activation is being blocked (default: NOT_SPECIFIED) |
| `String` | `externalUserId` | User ID of user who blocked the activation. Use null value if activation owner caused the change. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`BlockActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
<!-- end -->

<!-- begin api POST /rest/v3/activation/{id}/unblock -->
### Unblock Activation

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/unblock`
<!-- end -->

Unblock activation with given ID. Activations can be unblocked in BLOCKED state only. After successfully calling this method, activation is in ACTIVE state and failed attempt counter is set to 0.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`UnblockActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `externalUserId` | User ID of user who unblocked the activation. Use null value if activation owner caused the change. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```


`UnblockActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
<!-- end -->

<!-- begin api POST /rest/v3/activation/lookup -->
### Lookup Activations

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/lookup`
<!-- end -->

Lookup activations using query parameters.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`LookupActivationsRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userIds` | User IDs to use in query, at least one user ID needs to be specified |
| `String` | `applicationIds` | Application IDs to use in the query, do not specify value for all applications |
| `String` | `timestampLastUsedBefore` | Filter activations by timestamp when the activation was last used (timestampLastUsed < timestampLastUsedBefore), if not specified, a current timestamp is used |
| `String` | `timestampLastUsedAfter` | Filter activations by timestamp when the activation was last used (timestampLastUsed >= timestampLastUsedAfter), if not specified, the epoch start is used |
| `String` | `activationStatus` | Filter activations by their status, do not specify value for any status |
| `String[]` | `activationFlags` | Filter activations by activation flags |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`LookupActivationsResponse`

| `Activation[]` | `activations` | A collection of activations for given query parameters |

`LookupActivationsResponse.Activation`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `String` | `activationName` | An activation name |
| `String` | `extras` | Any custom attributes |
| `String` | `platform` | User device platform, e.g. `ios`, `android`, `hw` and `unknown` |
| `String` | `deviceInfo` | Information about user device, e.g. `iPhone12,3` |
| `String[]` | `activationFlags` | Activation flags |
| `DateTime` | `timestampCreated` | A timestamp when the activation was created |
| `DateTime` | `timestampLastUsed` | A timestamp when the activation was last used |
| `DateTime` | `timestampLastChange` | A timestamp of last activation status change |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier fo an application |
| `String` | `applicationName` | An application name |
| `Long` | `version` | Activation version |
<!-- end -->

<!-- begin api POST /rest/v3/activation/status/update -->
### Update Status for Activations

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/status/update`
<!-- end -->

Update status for activations identified using their identifiers.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`UpdateStatusForActivationsRequest`

| Type | Name | Description |
|------|------|-------------|
| `String[]` | `activationIds` | Identifiers of activations whose status needs to be updated |
| `ActivationStatus` | `activationStatus` | Activation status to use when updating the activations |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```


`UpdateStatusForActivationsResponse`

| Type | Name | Description |
|------|------|-------------|
| `boolean` | `updated` | Whether status update succeeded for all provided activations, either all activation statuses are updated or none of the statuses is updated in case of an error |
<!-- end -->

## Signature verification

Methods related to signature verification.

<!-- begin api POST /rest/v3/signature/verify -->
### Verify Signature

<!-- begin remove -->
REST endpoint: `POST /rest/v3/signature/verify`
<!-- end -->

Verify signature correctness for given activation, application key, data and signature type.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`VerifySignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `data` | Base64 encoded data for the signature |
| `String` | `signature` | PowerAuth signature |
| `SignatureType` | `signatureType` | PowerAuth signature type |
| `Long` | `forcedSignatureVersion` | Forced signature version used during activation upgrade |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`VerifySignatureResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `String` | `activationId` | An identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of the application |
| `SignatureType` | `signatureType` | Type of the signature that was used for the computation of the signature. |
| `Integer` | `remainingAttempts` | How many attempts are left for authentication using this activation |
<!-- end -->

<!-- begin api POST /rest/v3/verify/ecdsa  -->
### Verify ECDSA Signature

<!-- begin remove -->
REST endpoint: `POST /rest/v3/verify/ecdsa`
<!-- end -->

Verify asymmetric ECDSA signature correctness for given activation and data.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`VerifyECDSASignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `data` | Base64 encoded data for the signature |
| `String` | `signature` | Base64 encoded ECDSA signature |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`VerifyECDSASignatureResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `signatureValid` | Indicates if the ECDSA signature was correctly validated or if it was invalid (incorrect) |
<!-- end -->

<!-- begin api POST /rest/v3/signature/offline/personalized -->
### Create Personalized Offline Signature Payload

<!-- begin remove -->
REST endpoint: `POST /rest/v3/signature/offline/personalized`
<!-- end -->

Create a data payload used as a challenge for personalized off-line signatures.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`CreatePersonalizedOfflineSignaturePayloadRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `data` | Data for the signature, for normalized value see the [Offline Signatures QR code](https://github.com/wultra/powerauth-webflow/blob/develop/docs/Off-line-Signatures-QR-Code.md) documentation |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CreatePersonalizedOfflineSignaturePayloadResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `offlineData` | Data for QR code in format: `{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}` |
| `String` | `nonce` | Random cryptographic nonce, 16B encoded in Base64, same nonce as in `offlineData` (available separately for easy access) |
<!-- end -->

<!-- begin api POST /rest/v3/signature/offline/non-personalized -->
### Create Non-Personalized Offline Signature Payload

<!-- begin remove -->
REST endpoint: `POST /rest/v3/signature/offline/non-personalized`
<!-- end -->

Create a data payload used as a challenge for non-personalized off-line signatures.

#### Request

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CreateNonPersonalizedOfflineSignaturePayloadRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationId` | An identifier of an application |
| `String` | `data` | Data for the signature, for normalized value see the [Offline Signatures QR code](https://github.com/wultra/powerauth-webflow/blob/develop/docs/Off-line-Signatures-QR-Code.md) documentation |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CreateNonPersonalizedOfflineSignaturePayloadResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `offlineData` | Data for QR code in format: `{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}` |
| `String` | `nonce` | Random cryptographic nonce, 16B encoded in Base64, same nonce as in `offlineData` (available separately for easy access) |
<!-- end -->

<!-- begin api POST /rest/v3/signature/offline/verify -->
### Verify Offline Signature

<!-- begin remove -->
REST endpoint: `POST /rest/v3/signature/offline/verify`
<!-- end -->

Verify off-line signature of provided data.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`VerifyOfflineSignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `data` | Base64 encoded data for the signature, normalized data for signatures |
| `String` | `signature` | Actual signature value |
| `boolean` | `biometryAllowed` | Whether biometry is allowed in offline mode |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`VerifyOfflineSignatureResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `blockedReason` | Reason why activation was blocked (default: NOT_SPECIFIED) |
| `String` | `activationId` | An identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of the application |
| `SignatureType` | `signatureType` | Type of the signature that was used for the computation of the signature. |
| `Integer` | `remainingAttempts` | How many attempts are left for authentication using this activation |
<!-- end -->

## Token Based Authentication

<!-- begin api POST /rest/v3/token/create -->
### Create Token

<!-- begin remove -->
REST endpoint: `POST /rest/v3/token/create`
<!-- end -->

Create a new token for the simple token-based authentication.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```
`CreateTokenRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation. |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key for ECIES |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |
| `String` | `nonce` | Base64 encoded nonce for IV derivation for ECIES |
| `SignatureType` | `signatureType` | Type of the signature (factors) used for token creation. |

ECIES request should contain following data (an empty JSON object):
```json
{}
```

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```
`CreateTokenResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |

ECIES response contains following data (example):

```json
{
   "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb",  
   "tokenSecret": "VqAXEhziiT27lxoqREjtcQ=="
}
```
<!-- end -->

<!-- begin api POST /rest/v3/token/validate -->
### Validate Token

<!-- begin remove -->
REST endpoint: `POST /rest/v3/token/validate`
<!-- end -->

Validate token digest used for the simple token-based authentication.

#### Request


_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`ValidateTokenRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `tokenId` | An identifier of the token. |
| `String` | `tokenDigest` | Digest computed during the token based authentication. |
| `String` | `nonce` | Cryptographic nonce. Random 16B, Base64 encoded. |
| `Long` | `timestamp` | Token digest timestamp, Unix timestamp format. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`ValidateTokenResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `tokenValid` | Information about the validation result - if true, token digest was valid. |
| `String`  | `activationId` | An identifier of an activation |
| `String`  | `userId` | An identifier of a user |
| `Long`    | `applicationId` | An identifier of the application |
| `SignatureType` | `signatureType` | Type of the signature that was used for the computation of the signature.  |
<!-- end -->

<!-- begin api POST /rest/v3/token/remove -->
### Method 'removeToken'

<!-- begin remove -->
REST endpoint: `POST /rest/v3/token/remove`
<!-- end -->

Remove token with given ID.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`RemoveTokenRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `tokenId` | An identifier of the token. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RemoveTokenResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `removed` | True in case token was removed, false in case token with given ID was already not present. |
<!-- end -->

## Vault unlocking

Methods related to secure vault.

<!-- begin api POST /rest/v3/vault/unlock -->
### Unlock Vault

<!-- begin remove -->
REST endpoint: `POST /rest/v3/vault/unlock`
<!-- end -->

Get the encrypted vault unlock key upon successful authentication using PowerAuth Signature.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`VaultUnlockRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `signedData` | Base64 encoded data for the signature |
| `String` | `signature` | PowerAuth signature |
| `SignatureType` | `signatureType` | PowerAuth signature type |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key for ECIES |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |
| `String` | `nonce` | Base64 encoded nonce for IV derivation for ECIES |

ECIES request should contain following data:

```json
{
    "reason": "..."
}
```

You can provide following reasons for a vault unlocking:

- `ADD_BIOMETRY` - call was used to enable biometric authentication.
- `FETCH_ENCRYPTION_KEY` - call was used to fetch a generic data encryption key.
- `SIGN_WITH_DEVICE_PRIVATE_KEY` - call was used to unlock device private key used for ECDSA signatures.
- `NOT_SPECIFIED` - no reason was specified.


#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`VaultUnlockResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |

ECIES response contains following data (example):

```json
{
    "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
    "encryptedVaultEncryptionKey": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```
<!-- end -->

## Signature audit

Methods related to signature auditing.

<!-- begin api GET /rest/v3/signature/list -->
### Get Signature List

<!-- begin remove -->
REST endpoint: `POST /rest/v3/signature/list`
<!-- end -->

Get the signature audit log for given user, application and date range. In case no application ID is provided, event log for all applications is returned.

#### Request

`SignatureAuditRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `DateTime` | `timestampFrom` | Timestamp from which to fetch the log |
| `DateTime` | `timestampTo` | Timestamp to which to fetch the log |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

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
| `String` | `activationCtrData` | Base64 encoded hash based counter data |
| `ActivationStatus` | `activationStatus` | An activation status at the moment of a signature verification |
| `KeyValueMap` | `additionalInfo` | Key-value map with additional information |
| `String` | `dataBase64` | A base64 encoded data sent with the signature |
| `String` | `signatureVersion` | Requested signature version |
| `SignatureType` | `signatureType` | Requested signature type |
| `String` | `signature` | Submitted value of a signature |
| `String` | `note` | Extra info about the result of the signature verification |
| `Boolean` | `valid` | Flag indicating if the provided signature was valid |
| `DateTime` | `timestampCreated` | Timestamp when the record was created |
<!-- end -->

## Activation history

Get activation status change log.

<!-- begin api GET /rest/v3/activation/{id}/history -->
### Get Activation History

<!-- begin remove -->
REST endpoint: `GET /rest/v3/activation/{id}/history`
<!-- end -->

Get the status change log for given activation and date range.

#### Request

`ActivationHistoryRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Activation ID |
| `DateTime` | `timestampFrom` | Timestamp from which to fetch the changes |
| `DateTime` | `timestampTo` | Timestamp to which to fetch the changes |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

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
| `String` | `eventReason` | Reason why this activation history record was created (default: null) |
| `String` | `externalUserId` | User ID of user who modified the activation. Null value is used if activation owner caused the change. |
| `DateTime` | `timestampCreated` | Timestamp when the record was created |
<!-- end -->

## Integration management

Methods used for managing integration credentials for PowerAuth Server.

<!-- begin api POST /rest/v3/integration -->
### Create Integration

<!-- begin remove -->
REST endpoint: `POST /rest/v3/integration`
<!-- end -->

Create a new integration with given name, automatically generate credentials for the integration.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`CreateIntegrationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `name` | New integration name. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CreateIntegrationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Integration identifier (UUID4). |
| `String` | `name` | A name of the integration. |
| `String` | `clientToken` | An integration client token (serves as a "username"). |
| `String` | `clientSecret` | An integration client secret (serves as a "password"). |
<!-- end -->

<!-- begin api GET /rest/v3/integration -->
### Get Integration List

<!-- begin remove -->
REST endpoint: `GET /rest/v3/integration`
<!-- end -->

Get the list of all integrations that are configured on the server instance.

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

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
<!-- end -->

<!-- begin api POST /rest/v3/integration/{id}/remove -->
### Remove Integration

<!-- begin remove -->
REST endpoint: `POST /rest/v3/integration/remove`
<!-- end -->

Remove integration with given ID.

#### Request

`RemoveIntegrationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an integration to be removed. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RemoveIntegrationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an integration to be removed. |
| `Boolean` | `removed` | Flag specifying if an integration was removed or not. |
<!-- end -->

<!-- begin api POST /rest/v3/application/callback -->
### Create Callback URL

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/detail/{id}/callback/create`
<!-- end -->

Create a callback URL with given parameters.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`CreateCallbackUrlRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | Associated application ID. |
| `String` | `name` | Callback URL name, for visual identification. |
| `String` | `callbackUrl` | Callback URL that should be notified about activation status updates. |
| `List<String>` | `attributes` | Attributes which should be sent with the callback. |

The `attributes` list can contain following values:

- `activationId`
- `userId`
- `activationName`
- `deviceInfo`
- `platform`
- `activationFlags`
- `activationStatus`
- `blockedReason`
- `applicationId`

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CreateCallbackUrlResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Callback URL identifier (UUID4). |
| `Long` | `applicationId` | Associated application ID. |
| `String` | `name` | Callback URL name, for visual identification. |
| `String` | `callbackUrl` | Callback URL that should be notified about activation status updates. |
| `List<String>` | `attributes` | Attributes which should be sent with the callback. |
<!-- end -->

<!-- begin api PUT /rest/v3/application/detail/{id}/callback/update -->
### Update Callback URL

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/detail/{id}/callback/update`
<!-- end -->

Update a callback URL with given parameters.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`UpdateCallbackUrlRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | Associated application ID. |
| `String` | `name` | Callback URL name, for visual identification. |
| `String` | `callbackUrl` | Callback URL that should be notified about activation status updates. |
| `List<String>` | `attributes` | Attributes which should be sent with the callback. |

The `attributes` list can contain following values:

- `activationId`
- `userId`
- `activationName`
- `deviceInfo`
- `platform`
- `activationFlags`
- `activationStatus`
- `blockedReason`
- `applicationId`

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`UpdateCallbackUrlResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | Callback URL identifier (UUID4). |
| `Long` | `applicationId` | Associated application ID. |
| `String` | `name` | Callback URL name, for visual identification. |
| `String` | `callbackUrl` | Callback URL that should be notified about activation status updates. |
| `List<String>` | `attributes` | Attributes which should be sent with the callback. |
<!-- end -->

<!-- begin api GET /rest/v3/application/callback -->
### Get Callback URL List

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/detail/{id}/callback`
<!-- end -->

Get the list of all callbacks for given application.

#### Request

`GetCallbackUrlListRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | Application ID for which to fetch callback URLs. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

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
| `List<String>` | `attributes` | Attributes which should be sent with the callback. |
<!-- end -->

<!-- begin api POST /rest/v3/application/callback/remove -->
### Remove Callback URL

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/callback/{id}remove`
<!-- end -->

Remove callback URL with given ID.

#### Request

`RemoveCallbackUrlRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an callback URL to be removed. |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RemoveCallbackUrlResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | ID of an callback URL to be removed. |
| `Boolean` | `removed` | Flag specifying if a callback URL was removed or not. |
<!-- end -->

## End-To-End Encryption

<!-- begin api POST /rest/v3/ecies/decryptor -->
### Get ECIES Decryptor

<!-- begin remove -->
REST endpoint: `POST /rest/v3/ecies/decryptor`
<!-- end -->

Get ECIES decryptor data for request/response decryption on intermediate server.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`GetEciesDecryptorRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation (used only in activation scope, use null value in application scope) |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key for ECIES |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`GetEciesDecryptorResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `secretKey` | Base64 encoded secret key for ECIES |
| `String` | `sharedInfo2` | The sharedInfo2 parameter for ECIES |
<!-- end -->

## Activation Versioning

<!-- begin api POST /rest/v3/upgrade/start -->
### Start Activation Upgrade

<!-- begin remove -->
REST endpoint: `POST /rest/v3/upgrade/start`
<!-- end -->

Upgrade activation to the most recent version supported by the server.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`StartUpgradeRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation (used only in activation scope, use null value in application scope) |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key for ECIES |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |
| `String` | `nonce` | Base64 encoded nonce for IV derivation for ECIES |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`StartUpgradeResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` |  Base64 encoded mac of key and data for ECIES |
<!-- end -->

<!-- begin api POST /rest/v3/upgrade/commit -->
### Commit Activation Upgrade

<!-- begin remove -->
REST endpoint: `POST /rest/v3/upgrade/commit`
<!-- end -->

Commit activation upgrade.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`CommitUpgradeRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation (used only in activation scope, use null value in application scope) |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CommitUpgradeResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `committed` | Flag specifying if activation upgrade was committed |
<!-- end -->

## Activation Recovery

<!-- begin api POST /rest/v3/recovery/create -->
### Create Recovery Code

<!-- begin remove -->
REST endpoint: `POST /rest/v3/recovery/create`
<!-- end -->

Create a recovery code for user.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`CreateRecoveryCodeRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationId` | An identifier of an application |
| `String` | `userId` | An identifier of a user |
| `Long` | `pukCount` | Number of PUKs to generate |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`CreateRecoveryCodeResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `nonce` | A base64 encoded nonce used when generating recovery code |
| `String` | `userId` | An identifier of a user |
| `Long` | `recoveryCodeId` | Recovery code entity identifier |
| `String` | `recoveryCodeMasked` | Recovery code with partial masking to avoid leaking recovery code |
| `RecoveryCodeStatus` | `status` | Recovery code status |
| `Puk[]` | `puks` | Recovery code PUKs |

`CreateRecoveryCodeResponse.Puk`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `pukIndex` | Index of the PUK, counting starts by 1 |
| `Long` | `pukDerivationIndex` | Derivation index used when generating PUK |
| `RecoveryPukStatus` | `status` | Recovery PUK status |
<!-- end -->

<!-- begin api POST /rest/v3/recovery/confirm -->
### Confirm Recovery Code

<!-- begin remove -->
REST endpoint: `POST /rest/v3/recovery/confirm`
<!-- end -->

Confirm a recovery code received using recovery postcard.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`ConfirmRecoveryCodeRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `String` | `ephemeralPublicKey` | Base64 encoded ephemeral public key for ECIES |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` | Base64 encoded mac of key and data for ECIES |
| `String` | `nonce` | Base64 encoded nonce for IV derivation for ECIES |

ECIES request should contain following data (as JSON):
 - `recoveryCode` - Recovery code which should be confirmed in this request.

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`ConfirmRecoveryCodeResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` | Base64 encoded mac of key and data for ECIES |

ECIES response contains following data (as JSON):
 - `alreadyConfirmed` - Boolean flag which describes whether recovery code was already confirmed before this request.
 <!-- end -->

<!-- begin api POST /rest/v3/recovery/lookup -->
### Lookup Recovery Codes

<!-- begin remove -->
REST endpoint: `POST /rest/v3/recovery/lookup`
<!-- end -->

Lookup recovery codes.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`LookupRecoveryCodesRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String` | `applicationId` | An identifier of an application |
| `RecoveryCodeStatus` | `recoveryCodeStatus` | Recovery code status |
| `RecoveryPukStatus` | `recoveryPukStatus` | Recovery PUK status |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`LookupRecoveryCodesResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `recoveryCodeId` | Recovery code entity identifiers |
| `String` | `recoveryCodeMasked` | Recovery code with partial masking to avoid leaking recovery code |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `String` | `activationId` | A UUID4 identifier of an activation |
| `RecoveryCodeStatus` | `status` | Recovery code status |
| `Puk[]` | `puks` | Recovery code PUKs |

`LookupRecoveryCodesResponse.Puk`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `pukIndex` | Index of the PUK, counting starts by 1 |
| `RecoveryPukStatus` | `status` | Recovery PUK status |
<!-- end -->

<!-- begin api POST /rest/v3/recovery/revoke -->
### Revoke Recovery Codes

<!-- begin remove -->
REST endpoint: `POST /rest/v3/recovery/revoke`
<!-- end -->

Revoke recovery codes.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`RevokeRecoveryCodesRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long[]` | `recoveryCodeIds` | Recovery code entity identifiers |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RevokeRecoveryCodesResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `revoked` | True if at least one recovery code was revoked |
<!-- end -->

<!-- begin api POST /rest/v3/activation/recovery/create -->
### Activation Via Recovery Code

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/recovery/create`
<!-- end -->

Create an activation using recovery code. After successfully calling this method, activation is in PENDING_COMMIT state.

If optional `activationOtp` value is set, then the activation's OTP validation mode is set to `ON_COMMIT`. The same OTP value must be later provided in [CommitActivation](#method-commitactivation) method, to complete the activation.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`RecoveryCodeActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `recoveryCode` | Recovery code |
| `String` | `puk` | Recovery PUK |
| `String` | `applicationKey` | A key (identifier) of an application, associated with given application version |
| `Long` | `maxFailureCount` | Maximum number of failures when using the recovery code |
| `String` | `ephemeralPublicKey` | Base64 encoded encrypted data for ECIES |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` | Base64 encoded mac of key and data for ECIES |
| `String` | `nonce` | Base64 encoded nonce for IV derivation for ECIES |
| `String` | `activationOtp` | Optional activation OTP |

ECIES request should contain following data (as JSON):
 - `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
 - `devicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC`  (base64-encoded).
 - `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.
 - `platform` - User device platform, e.g. `ios`, `android`, `hw` and `unknown`.
 - `deviceInfo` - Information about user device, e.g. `iPhone12,3`.

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RevokeRecoveryCodesResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `String` | `encryptedData` | Base64 encoded encrypted data for ECIES |
| `String` | `mac` | Base64 encoded mac of key and data for ECIES |

ECIES response contains following data (as JSON):
 - `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
 - `serverPublicKey` - Public key `KEY_SERVER_PUBLIC` of the server (base64-encoded).
 - `ctrData` - Initial value for hash-based counter (base64-encoded).
 - `activationRecovery` - Information about activation recovery.
    - `recoveryCode` - Recovery code which uses 4x5 characters in Base32 encoding separated by a "-" character.
    - `puk` - Recovery PUK with unique PUK used as secret for the recovery code.

In case the PUK is invalid and there are still valid PUKs left to try, the error response contains the `currentRecoveryPukIndex`
value in the SOAP fault detail. This value contains information about which PUK should the user re-write next.
<!-- end -->

<!-- begin api GET /rest/v3/recovery/config/detail/{id} -->
### Get Recovery Code Configuration

<!-- begin remove -->
REST endpoint: `GET /rest/v3/recovery/config/detail/{id}`
<!-- end -->

Get configuration of activation recovery.

#### Request

`GetRecoveryConfigRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`GetRecoveryConfigResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `Boolean` | `activationRecoveryEnabled` | Whether activation recovery is enabled |
| `Boolean` | `recoveryPostcardEnabled` | Whether recovery postcard is enabled |
| `Boolean` | `allowMultipleRecoveryCodes` | Whether multiple recovery codes per user are allowed |
| `String` | `postcardPublicKey` | Base64 encoded recovery postcard public key for PowerAuth server |
| `String` | `remotePostcardPublicKey` | Base64 encoded recovery postcard public key for recovery postcard printing center |
<!-- end -->

<!-- begin api PUT /rest/v3/recovery/config/update -->
### Update Recovery Code Configuration

<!-- begin remove -->
REST endpoint: `POST /rest/v3/recovery/config/update`
<!-- end -->

Update configuration of activation recovery.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`UpdateRecoveryConfigRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `Boolean` | `activationRecoveryEnabled` | Whether activation recovery is enabled |
| `Boolean` | `recoveryPostcardEnabled` | Whether recovery postcard is enabled |
| `Boolean` | `allowMultipleRecoveryCodes` | Whether multiple recovery codes per user are allowed |
| `String` | `remotePostcardPublicKey` | Base64 encoded recovery postcard public key |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`UpdateRecoveryConfigResponse`

| Type | Name | Description |
|------|------|-------------|
| `Boolean` | `updated` | Whether recovery configuration was updated |   
<!-- end -->

## Activation Flags

<!-- begin api GET /rest/v3/activation/{id}/flags/list -->
### Get Activation Flags

<!-- begin remove -->
REST endpoint: `GET /rest/v3/activation/flags/list`
<!-- end -->

List flags for an activation.

#### Request

`ListActivationFlagsRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `id` | A UUID4 identifier of an activation |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```


`ListActivationFlagsResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | The UUID4 identifier of the activation |
| `String[]` | `activationFlags` | Activation flags for the activation |
<!-- end -->

<!-- begin api POST /rest/v3/activation/flags/create -->
### Add Activation Flags

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/flags/create`
<!-- end -->

Add activation flags to an activation. Duplicate flags are ignored.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`AddActivationFlagsRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String[]` | `activationFlags` | Activation flags to be added to the activation |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`AddActivationFlagsResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | The UUID4 identifier of the activation |
| `String[]` | `activationFlags` | Activation flags for the activation after the addition |
<!-- end -->

<!-- begin api POST /rest/v3/activation/flags/update -->
### Update Activation Flags

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/flags/update`
<!-- end -->

Update activation flags to an activation. Existing flags are removed.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`UpdateActivationFlagsRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String[]` | `activationFlags` | Activation flags for the update |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`UpdateActivationFlagsResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | The UUID4 identifier of the activation |
| `String[]` | `activationFlags` | Activation flags for the activation after the update |
<!-- end -->

<!-- begin api POST /rest/v3/activation/flags/remove -->
### Remove Activation Flags

<!-- begin remove -->
REST endpoint: `POST /rest/v3/activation/flags/remove`
<!-- end -->

Remove activation flags for an activation.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`RemoveActivationFlagsRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A UUID4 identifier of an activation |
| `String[]` | `activationFlags` | Activation flags to be removed from the activation |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RemoveActivationFlagsResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | The UUID4 identifier of the activation |
| `String[]` | `activationFlags` | Activation flags for the activation after the removal |
<!-- end -->

## Application Roles

<!-- begin api GET /rest/v3/application/roles/list -->
### List Application Roles

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/{id}/roles/list`
<!-- end -->

List roles for an application.

#### Request

`ListApplicationRolesRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | An identifier of an application |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`ListApplicationRolesResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | The identifier of the application |
| `String[]` | `applicationRoles` | Application roles assigned to the application |
<!-- end -->

<!-- begin api PUT /rest/v3/application/roles/create -->
### Add Application Roles

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/roles/create`
<!-- end -->

Add application roles to an application. Duplicate roles are ignored.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`AddApplicationRolesRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String[]` | `applicationRoles` | Application roles to be added to the application |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`AddApplicationRolesResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | The identifier of the application |
| `String[]` | `applicationRoles` | Application roles assigned to the application after the addition |
<!-- end -->

<!-- begin api POST /rest/v3/application/roles/update -->
### Update Application Roles

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/roles/update`
<!-- end -->

Update application roles assigned to an application. Existing roles are removed.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`UpdateApplicationRolesRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String[]` | `applicationRoles` | Application roles to be assigned to the application |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`UpdateApplicationRolesResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | The identifier of the application |
| `String[]` | `applicationRoles` | Application roles assigned to the application after the update |
<!-- end -->

<!-- begin api POST /rest/v3/application/roles/remove -->
### Remove Application Roles

<!-- begin remove -->
REST endpoint: `POST /rest/v3/application/roles/remove`
<!-- end -->

Remove application roles from an activation.

#### Request

_//TODO: Prepare example_
```json
{
    "requestObject": {

    }
}
```

`RemoveApplicationRolesRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationId` | An identifier of an application |
| `String[]` | `applicationRoles` | Application roles to be removed from the application |

#### Response 200

_//TODO: Prepare example_
```json
{
    "responseObject": {

    }
}
```

`RemoveApplicationRolesResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationId` | An identifier of an application |
| `String[]` | `applicationRoles` | Application roles assigned to the application after the removal |
<!-- end -->
