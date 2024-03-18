# FIDO2 API

<!-- TEMPLATE api -->

FIDO2 REST API enables integration of WebAuthN standard into PowerAuth for FIDO2 authenticators. Registration and authentication ceremonies are supported by this REST API.

## Possible Error Codes

The API may return one of the following error codes:

| HTTP  | Error Code             | Description                                                                       |
|-------|------------------------|-----------------------------------------------------------------------------------|
| `400` | `ERROR_FIDO2_AUTH`     | Error related failed FIDO2 assertions.                                            |
| `400` | `ERROR_FIDO2_REQUEST`  | Error related failed FIDO2 request processing.                                    |
| `400` | `ERROR_HTTP_REQUEST`   | Request did not pass validation (mandatory property missing, null/invalid value). |
| `401` | `ERROR_UNAUTHORIZED`   | Returned in the case authentication fails (invalid application credentials).      |
| `404` | `ERROR_NOT_FOUND`      | Returned in the case URL is not present (calling wrong API).                      |

## Registration Services

<!-- begin api POST /fido2/registrations/list -->
### Get FIDO2 Authenticators for User

Request a list of FIDO2 authenticators.

<!-- begin box info -->
FIDO2 assertions are backed by PowerAuth activations.
<!-- end -->

#### Request

```json
{
  "requestObject": {
    "userId": "string",
    "applicationId": "string"
  }
}
```

##### Request Params

| Attribute                                                       | Type     | Description                                                  |
|-----------------------------------------------------------------|----------|--------------------------------------------------------------|
| `userId`<span class="required" title="Required">*</span>        | `String` | User for which the authenticators should be returned.        |
| `applicationId`<span class="required" title="Required">*</span> | `String` | Application for which the authenticators should be returned. |

#### Response 200

List of authenticators for provided user and application.

```json
{
  "status": "string",
  "responseObject": {
    "authenticators": [
      {
        "userId": "string",
        "activationId": "string",
        "applicationId": "string",
        "activationName": "string",
        "credentialId": "string",
        "activationStatus": "CREATED",
        "extras": {
          "additionalProp1": {},
          "additionalProp2": {},
          "additionalProp3": {}
        },
        "platform": "string",
        "deviceInfo": "string",
        "blockedReason": "string",
        "failedAttempts": 0,
        "maxFailedAttempts": 0,
        "applicationRoles": [
          "string"
        ],
        "activationFlags": [
          "string"
        ],
        "publicKeyBytes": "string"
      }
    ]
  }
}
```

##### Response Params

| Attribute           | Type       | Description                                                 |
|---------------------|------------|-------------------------------------------------------------|
| `userId`            | `String`   | User ID associated with the authenticator.                  |
| `activationId`      | `String`   | Activation ID.                                              |
| `applicationId`     | `String`   | Application associated with the authenticator.              |
| `activationName`    | `String`   | Activation name.                                            |
| `credentialId`      | `String`   | Credential ID (FIDO2 Authenticator ID).                     |
| `activationStatus`  | `String`   | The activation status.                                      |
| `extras`            | `String`   | Associated authenticator data.                              |
| `platform`          | `String`   | Type of FIDO2 authenticator (`platform`, `cross-platform`). |
| `deviceInfo`        | `String`   | Authenticator model info (vendor, type).                    |
| `blockedReason`     | `String`   | If blocked, the value contains reason for blocking.         |
| `failedAttempts`    | `String`   | How many approvals failed.                                  |
| `maxFailedAttempts` | `String`   | Maximum allowed count of approval failures.                 |
| `applicationRoles`  | `String[]` | Application roles.                                          |
| `activationFlags`   | `String[]` | Activation flags.                                           |
| `publicKeyBytes`    | `String`   | Authenticator public key, encoded as Base64.                |

<!-- end -->

<!-- begin api POST /fido2/registrations/challenge -->
### Create a FIDO2 Registration Challenge

Request a challenge for new FIDO2 authenticator registration.

<!-- begin box info -->
FIDO2 assertions are backed by PowerAuth activations.
<!-- end -->

#### Request

```json
{
  "requestObject": {
    "userId": "string",
    "applicationId": "string"
  }
}
```

##### Request Params

| Attribute                                                       | Type     | Description                                             |
|-----------------------------------------------------------------|----------|---------------------------------------------------------|
| `userId`<span class="required" title="Required">*</span>        | `String` | User for which the challenge should be prepared.        |
| `applicationId`<span class="required" title="Required">*</span> | `String` | Application for which the challenge should be prepared. |

#### Response 200

Challenge for new FIDO2 authenticator registration.

```json
{
  "status": "string",
  "responseObject": {
    "activationId": "string",
    "applicationId": "string",
    "challenge": "string",
    "userId": "string"
  }
}
```

##### Response Params

| Attribute           | Type       | Description                                                 |
|---------------------|------------|-------------------------------------------------------------|
| `userId`            | `String`   | User ID associated with the authenticator.                  |
| `activationId`      | `String`   | Activation ID.                                              |
| `applicationId`     | `String`   | Application associated with the authenticator.              |
| `challenge`         | `String`   | FIDO2 registration challenge.                               |

<!-- end -->

<!-- begin api POST /fido2/registrations -->
### Register FIDO2 Authenticator

Register a new FIDO2 authenticator.

<!-- begin box info -->
FIDO2 assertions are backed by PowerAuth activations.
<!-- end -->

#### Request

```json
{
  "requestObject": {
    "applicationId": "string",
    "activationName": "string",
    "expectedChallenge": "string",
    "authenticatorParameters": {
      "id": "string",
      "type": "string",
      "authenticatorAttachment": "string",
      "response": "...",
      "relyingPartyId": "string",
      "allowedOrigins": [
        "string"
      ],
      "allowedTopOrigins": [
        "string"
      ],
      "requiresUserVerification": true
    }
  }
}
```

##### Request Params

| Attribute                                                        | Type                      | Description                                                                       |
|------------------------------------------------------------------|---------------------------|-----------------------------------------------------------------------------------|
| `applicationId`<span class="required" title="Required">*</span>  | `String`                  | Application for which the challenge should be prepared.                           |
| `activationName`<span class="required" title="Required">*</span> | `String`                  | Name of the activation.                                                           |
| `expectedChallenge`                                              | `String`                  | Expected challenge value. If present, it is checked against the actual challenge. |
| `authenticatorParameters`                                        | `AuthenticatorParameters` | Parameters of the registered authenticator.                                       |

##### `AuthenticatorParameters` Object

| Attribute                                                                 | Type     | Description                                                                   |
|---------------------------------------------------------------------------|----------|-------------------------------------------------------------------------------|
| `credentialId`<span class="required" title="Required">*</span>                      | `String` | Credential ID.                                                                |
| `type`<span class="required" title="Required">*</span>                    | `String` | Credential type (`public-key`).                                               |
| `authenticatorAttachment`<span class="required" title="Required">*</span> | `String` | Information about authenticator attachment.                                   |
| `response`<span class="required" title="Required">*</span>                | `String` | Authenticator response (value provided by authenticator, encoded as Base64).  |
| `relyingPartyId`                                                          | `String` | Identification of relying party, typically the domain, i.e., `example.com`.   |
| `allowedOrigins`                                                          | `String` | Collection of origins that should be allowed to provide the assertion.        |
| `allowedTopOrigins`                                                       | `String` | Collection of top origins that should be allowed to provide the assertion.    |
| `requiresUserVerification`                                                | `String` | Information if user verification flag must be present (if user was verified). |


#### Response 200

A new FIDO2 authenticator registration.

```json
{
  "status": "string",
  "responseObject": {
    "userId": "string",
    "activationId": "string",
    "applicationId": "string",
    "activationName": "string",
    "credentialId": "string",
    "activationStatus": "CREATED",
    "extras": {
      "additionalProp1": {},
      "additionalProp2": {},
      "additionalProp3": {}
    },
    "platform": "string",
    "deviceInfo": "string",
    "blockedReason": "string",
    "failedAttempts": 0,
    "maxFailedAttempts": 0,
    "applicationRoles": [
      "string"
    ],
    "activationFlags": [
      "string"
    ],
    "publicKeyBytes": "string"
  }
}
```

##### Response Params

| Attribute           | Type       | Description                                                 |
|---------------------|------------|-------------------------------------------------------------|
| `userId`            | `String`   | User ID associated with the authenticator.                  |
| `activationId`      | `String`   | Activation ID.                                              |
| `applicationId`     | `String`   | Application associated with the authenticator.              |
| `activationName`    | `String`   | Activation name.                                            |
| `credentialId`      | `String`   | Credential ID (FIDO2 Authenticator ID).                     |
| `activationStatus`  | `String`   | The activation status.                                      |
| `extras`            | `String`   | Associated authenticator data.                              |
| `platform`          | `String`   | Type of FIDO2 authenticator (`platform`, `cross-platform`). |
| `deviceInfo`        | `String`   | Authenticator model info (vendor, type).                    |
| `blockedReason`     | `String`   | If blocked, the value contains reason for blocking.         |
| `failedAttempts`    | `String`   | How many approvals failed.                                  |
| `maxFailedAttempts` | `String`   | Maximum allowed count of approval failures.                 |
| `applicationRoles`  | `String[]` | Application roles.                                          |
| `activationFlags`   | `String[]` | Activation flags.                                           |
| `publicKeyBytes`    | `String`   | Authenticator public key, encoded as Base64.                |

<!-- end -->

## Assertion Services

<!-- begin api POST /fido2/assertions/challenge -->
### Create a FIDO2 Assertion Challenge

Request a new FIDO2 assertion challenge.

<!-- begin box info -->
FIDO2 assertions are backed by PowerAuth operations. This means you can use templates and template parameters.
<!-- end -->

#### Request

```json
{
  "requestObject": {
    "applicationIds": [
      "string"
    ],
    "userId": "string",
    "externalId": "string",
    "templateName": "string",
    "parameters": {
      "additionalProp1": "string",
      "additionalProp2": "string",
      "additionalProp3": "string"
    }
  }
}
```

##### Request Params

| Attribute                                                        | Type                 | Description                                                           |
|------------------------------------------------------------------|----------------------|-----------------------------------------------------------------------|
| `applicationIds`<span class="required" title="Required">*</span> | `String[]`           | Applications that are capable of approving the operation.             |
| `userId`                                                         | `String`             | User with which the assertion should be associated with. Can be null. |
| `externalId`                                                     | `String`             | Link to transaction in other system (i.e., core system transaction).  |
| `templateName`<span class="required" title="Required">*</span>   | `String`             | Template on which this assertion should be based.                     |
| `parameters`                                                     | `Map<String,String>` | Template parameters.                                                  |

#### Response 200

If the challenge is successfully created, API returns the following response:

```json
{
  "status": "string",
  "responseObject": {
    "applicationIds": [
      "string"
    ],
    "challenge": "string",
    "userId": "string",
    "failedAttempts": 0,
    "maxFailedAttempts": 0,
    "allowCredentials": [
      {
        "credentialId": "string",
        "type": "string",
        "transports": [
          "string"
        ]
      }
    ]
  }
}
```

##### Response Params

| Attribute                                                        | Type                 | Description                                                                     |
|------------------------------------------------------------------|----------------------|---------------------------------------------------------------------------------|
| `applicationIds`<span class="required" title="Required">*</span> | `String[]`           | Applications that are capable of approving the operation.                       |
| `challenge`                                                      | `String`             | The assertion challenge to be signed by the authenticator.                      |
| `userId`                                                         | `String`             | User with which the assertion should be associated with. Can be null.           |
| `failedAttempts`                                                 | `String`             | Information about how many times this assertion was unsuccessfully approved.    |
| `maxFailedAttempts`                                              | `String`             | Information about how many times this assertion can be unsuccessfully approved. |
| `allowCredentials`                                               | `AllowCredentials`   | Credentials that are associated with this assertion.                            |

##### `AllowCredentials` Object

| Attribute                                                      | Type       | Description                                           |
|----------------------------------------------------------------|------------|-------------------------------------------------------|
| `credentialId`<span class="required" title="Required">*</span> | `String`   | Credential ID, byte array encoded in Base64 encoding. |
| `type`                                                         | `String`   | Type of credentials, mostly `public-key` value.       |
| `transports`                                                   | `String[]` | Allowed authenticator transport modes.                |

<!-- end -->

<!-- begin api POST /fido2/assertions -->
### Verify a FIDO2 Assertion

Verify a provided FIDO2 assertion.

#### Request

```json
{
  "requestObject": {
    "id": "string",
    "type": "string",
    "authenticatorAttachment": "string",
    "response": "...",
    "applicationId": "string",
    "relyingPartyId": "string",
    "allowedOrigins": [
      "string"
    ],
    "allowedTopOrigins": [
      "string"
    ],
    "requiresUserVerification": true,
    "expectedChallenge": "string"
  }
}
```

##### Request Params

| Attribute                                                                 | Type     | Description                                                                       |
|---------------------------------------------------------------------------|----------|-----------------------------------------------------------------------------------|
| `credentialId`<span class="required" title="Required">*</span>                      | `String` | Credential ID.                                                                    |
| `type`<span class="required" title="Required">*</span>                    | `String` | Credential type (`public-key`).                                                   |
| `authenticatorAttachment`<span class="required" title="Required">*</span> | `String` | Information about authenticator attachment.                                       |
| `response`<span class="required" title="Required">*</span>                | `String` | Authenticator response (value provided by authenticator, encoded as Base64).      |
| `applicationId`                                                           | `String` | Application identifier, to verify the challenge can be approved by given app.     |
| `relyingPartyId`                                                          | `String` | Identification of relying party, typically the domain, i.e., `example.com`.       |
| `allowedOrigins`                                                          | `String` | Collection of origins that should be allowed to provide the assertion.            |
| `allowedTopOrigins`                                                       | `String` | Collection of top origins that should be allowed to provide the assertion.        |
| `requiresUserVerification`                                                | `String` | Information if user verification flag must be present (if user was verified).     |
| `expectedChallenge`                                                       | `String` | Expected challenge value. If present, it is checked against the actual challenge. |

#### Response 200

If the challenge is successfully verified, API returns the following response:

```json
{
  "status": "string",
  "responseObject": {
    "assertionValid": true,
    "userId": "string",
    "activationId": "string",
    "applicationId": "string",
    "activationStatus": "CREATED",
    "blockedReason": "string",
    "remainingAttempts": 0,
    "applicationRoles": [
      "string"
    ],
    "activationFlags": [
      "string"
    ]
  }
}
```

##### Response Params

| Attribute                                                        | Type       | Description                                                                         |
|------------------------------------------------------------------|------------|-------------------------------------------------------------------------------------|
| `assertionValid`<span class="required" title="Required">*</span> | `Boolean`  | Result of assertion validation.                                                     |
| `userId`                                                         | `String`   | User with which the assertion should be associated with. Can be null.               |
| `activationId`                                                   | `String`   | ID of activation that was used for verification.                                    |
| `applicationId`                                                  | `String`   | Information about what application was used for approval.                           |
| `activationStatus`                                               | `String`   | Associated activation status.                                                       |
| `blockedReason`                                                  | `String`   | If activation is blocked, the value contains information about reason for blocking. |
| `remainingAttempts`                                              | `String`   | How many attempts remain to approve the assertion (authenticator counter).          |
| `applicationRoles`                                               | `String[]` | Roles associated with the related application.                                      |
| `activationFlags`                                                | `String[]` | Flags associated with the related activation.                                       |

<!-- end -->