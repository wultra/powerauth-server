# Migration from 2.0.x to 2.1.0

## REST API Changes

### POST /fido2/assertions

The `$.requestObject.applicationId` attribute used to verify the challenge can be approved by given application is no longer mandatory. If not present, the user ID retrieved from `$.requestObject.response.userHandle` is used to determine the application ID. 

### POST /fido2/assertions/challenge

The response contains a new `$.responseObject.operationId` attribute representing the operation ID the assertion is associated with.
