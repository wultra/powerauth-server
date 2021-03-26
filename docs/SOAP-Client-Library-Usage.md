# SOAP Client Library Usage

This chapter explains how to use the SOAP client.

## PowerAuth Protocol Compatibility Notice 

The SOAP client supports two versions of PowerAuth protocol:
- The version `3` methods are available as default implementation directly on the client class. 
- You can access the version `2` specific methods using the `v2()` method in the client. This method will be deprecated in a future release.

All samples in this chapter use the version `3` client methods. See chapter [Web Services - Method Compatibility](WebServices-Method-Compatibility.md) for additional details about SOAP interface versioning.

## Obtaining the New Activation Data

To generate a new activation data for a given user ID, call the `initActivation` method of the `PowerAuthServiceClient` instance. 

In response, you will obtain a new activation data. Your goal is to display `activationCode` and optionally `activationSignature` attributes in user interface so that a user can enter these information in his PowerAuth Client application.

Also, you will receive `activationId` in the response that you can use to query for activation status or to commit the activation. Finally, response contains the `userId` as a back-reference to your request data.

```java
// Your actual user identifier
String userId = "1234";

// Short way to read the activations
InitActivationResponse activation = powerAuthServiceClient.initActivation(userId);

// More control over how the activation is created
Long maximumFailedAttempts = 10; // default: 5
Date expireBefore = dateIn10Minutes; // default: in 2 minutes
InitActivationResponse activation = powerAuthServiceClient.initActivation(userId, maximumFailedAttempts, expireBefore);

// ... or using the original SOAP request-response notion ...
InitActivationRequest request = new InitActivationRequest();
request.setUserId(userId);
request.setMaxFailureCount(maximumFailedAttempts); // optional
request.setTimestampActivationExpire(xmlCalendarWithDate(expireBefore)); // optional
InitActivationResponse response = powerAuthServiceClient.initActivation(request);
```

## Committing Activation

To commit an activation with given `activationId`, call the `commitActivation` method of the `PowerAuthServiceClient` instance. You should allow committing an activation as soon as it changes it's state from `CREATED` (initial state) to `PENDING_COMMIT` (state after the key exchange is complete).

```java
// Your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to block the activation
CommitActivationResponse response = powerAuthServiceClient.commitActivation(activationId);

// ... or using the original SOAP request-response notion ...
CommitActivationRequest request = new CommitActivationRequest();
request.setActivationId(activationId)
CommitActivationResponse response = powerAuthServiceClient.commitActivation(request);
```

## Getting the List and Detail For the Given Activation

To get the list of activations for a given user ID, call the `getActivationListForUser` method of the `PowerAuthServiceClient` instance. Use this method to display the list of activations in a user interface, for the purpose of activation management. Each activation contains following attributes:

- `activationId` - Identifier of the activation.
- `activationStatus` - Status of the activation: `CREATED`, `PENDING_COMMIT`, `ACTIVE`, `BLOCKED`, or `REMOVED`.
- `blockedReason` - Reason why activation was blocked (only in activation state `BLOCKED`).
- `activationName` - Name of the activation, as the user created it.
- `userId` - Reference to the user to whom the activation belongs.
- `timestampCreated` - Timestamp representing the moment an activation was created (milliseconds since the Unix epoch start).
- `timestampLastUsed`  - Timestamp representing the moment an activation was last used for signature verification (milliseconds since the Unix epoch start).
- `extras` - Extra data, content depends on application specific requirements.
- `version` - PowerAuth protocol version.

```java
// Your actual user identifier
String userId = "1234";

// Short way to read the activations
List<Activations> activations = powerAuthServiceClient.getActivationListForUser(userId);

// ... or using the original SOAP request-response notion ...
GetActivationListForUserRequest request = new GetActivationListForUserRequest();
request.setUserId(userId);
GetActivationListForUserResponse response = powerAuthServiceClient.getActivationListForUser(request);
List<Activations> activations = response.getActivations();
```

You can also get a detail of an individual activation based on `activationId` by calling the `getActivationStatus` method of the `PowerAuthServiceClient`.

```java
// Your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to read the activation status
GetActivationStatusResponse response = powerAuthServiceClient.getActivationStatus(activationId);

// ... or using the original SOAP request-response notion ...
GetActivationStatusRequest request = new GetActivationStatusRequest();
request.setActivationId(activationId)
GetActivationStatusResponse response = powerAuthServiceClient.getActivationStatus(request);
```

## Blocking, Unblocking and Removing Activation

To block an activation with given `activationId`, call the `blockActivation` method of the `PowerAuthServiceClient` instance. Only activations in `ACTIVE` state can be blocked.

```java
// Your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";
String blockedReason = "NOT_SPECIFIED";

// Short way to block the activation
BlockActivationResponse response = powerAuthServiceClient.blockActivation(activationId, blockedReason);

// ... or using the original SOAP request-response notion ...
BlockActivationRequest request = new BlockActivationRequest();
request.setActivationId(activationId);
request.setBlockedReason(blockedReason);
BlockActivationResponse response = powerAuthServiceClient.blockActivation(request);
```

To unblock an activation with given `activationId`, call the `unblockActivation` method of the `PowerAuthServiceClient` instance. Only activations in `BLOCKED` state can be unblocked.

```java
// Your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to unblock the activation
UnblockActivationResponse response = powerAuthServiceClient.unblockActivation(activationId);

// ... or using the original SOAP request-response notion ...
UnblockActivationRequest request = new UnblockActivationRequest();
request.setActivationId(activationId)
UnblockActivationResponse response = powerAuthServiceClient.unblockActivation(request);
```

To remove an activation with given `activationId`, call the `removeActivation` method of the `PowerAuthServiceClient` instance. Note that unlike with the PowerAuth Standard RESTful API (usually called by PowerAuth Client), this call does not require PowerAuth authorization signature. You can remove activation in any activation state.

```java
// Your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to remove the activation
RemoveActivationResponse response = powerAuthServiceClient.removeActivation(activationId);

// ... or using the original SOAP request-response notion ...
RemoveActivationRequest request = new RemoveActivationRequest();
request.setActivationId(activationId)
RemoveActivationResponse response = powerAuthServiceClient.removeActivation(request);
```

## Getting the Signature Audit Records

To get the list of performed signature attempts for a given user ID, call the `getSignatureAuditLog` method of the `PowerAuthServiceClient` instance. Use this method to display the list of performed signature attempts, for example in a back-office user interface. This is especially useful for the purpose of security auditing and customer support. Each signature audit record contains following attributes:

- `id` - Identifier of the signature audit record.
- `userId` - Reference to the user who attempted to compute the signature.
- `activationId` - Identifier of the activation that was used to construct the signature.
- `activationCounter` - Value of the numeric counter.
- `activationCtrData` - Value of the hash based counter (available only in version `3.0`).
- `activationStatus` - Status of the activation: `CREATED`, `PENDING_COMMIT`, `ACTIVE`, `BLOCKED`, or `REMOVED`. 
- `additionalInfo` - Additional information related to the signature request in JSON format.
- `dataBase64` - Data used for the signature, base64 encoded.
- `signatureType` - Type of the signature that was requested.
- `signature` - Signature as it was delivered.
- `note` - Additional information about the validation result.
- `valid` - Whether signature is valid.
- `timestampCreated` - Timestamp representing the moment a signature audit record was created (milliseconds since the Unix epoch start).
- `version` - PowerAuth protocol version.

```java
// Your actual user identifier
String userId = "1234";

// Date range
Date endingDate = new Date();
Date startingDate = new Date(endingDate.getTime() - (7L * 24L * 60L * 60L * 1000L));

// Short way to read the signature audit log
List<SignatureAuditResponse.Items> signatureAuditItems = getSignatureAuditLog(userId,startingDate, endingDate);

// ... or using the original SOAP request-response notion ...
SignatureAuditRequest request = new SignatureAuditRequest();
request.setUserId(userId);
request.setTimestampFrom(calendarWithDate(startingDate));
request.setTimestampTo(calendarWithDate(endingDate));
SignatureAuditResponse response = powerAuthServiceClient.getSignatureAuditLog(request);
List<SignatureAuditResponse.Items> signatureAuditItems = response.getItems();
```
