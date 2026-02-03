# PowerAuth Server – Migration Guide from REST API v3 to v4

This document describes how to migrate client integrations from **PowerAuth Server REST API v3** to **v4**.

## General Migration Rules

1. Replace `/rest/v3` with `/rest/v4`.
2. Update controller path segments as described below.
3. Unless explicitly stated, **request and response payloads are unchanged**.

## Online Authentication Verification

v3 endpoint:
```
POST /rest/v3/signature/verify
```

v4 endpoint:
```
POST /rest/v4/auth/verify
```

### Migration Steps

1. Change endpoint path from `/rest/v3/signature/verify` to `/rest/v4/auth/verify`.
2. Request parameter `signature` was changed to `authenticationCode`.
3. Request parameter `signatureType` was changed to `authenticationCodeType`.
4. Request parameter `signatureVersion` was changed to `authenticationVersion`.
5. Response parameter `signatureValid` was changed to `authenticationValid`.
6. Response parameter `signatureType` was changed to `authenticationCodeType`.

## Offline Authentication Verification

v3 endpoint:
```
POST /rest/v3/signature/offline/verify
```

v4 endpoint:
```
POST /rest/v4/auth/offline/verify
```

### Migration Steps

1. Update endpoint path to `/rest/v4/auth/offline/verify`.
2. Request parameter `signature` was changed to `authenticationCode`.
3. Response parameter `signatureValid` was changed to `authenticationValid`.
4. Response parameter `signatureType` was changed to `authenticationCodeType`.

## Create Personalized Offline Authentication Payload

v3 endpoint:
```
POST /rest/v3/signature/offline/personalized/create
```

v4 endpoint:
```
POST /rest/v4/auth/offline/personalized/create
```

### Migration Steps

1. Replace `/signature/offline/personalized/create` with `/auth/offline/personalized/create`.
2. Request and response payload remain unchanged.

## Create Non-Personalized Offline Authentication Payload

v3 endpoint:
```
POST /rest/v3/signature/offline/non-personalized/create
```

v4 endpoint:
```
POST /rest/v4/auth/offline/non-personalized/create
```

### Migration Steps

1. Replace `/signature/offline/non-personalized/create` with `/auth/offline/non-personalized/create`.
2. Payload and response remain unchanged.

## Authentication Audit Log

v3 endpoint:
```
POST /rest/v3/signature/list
```

v4 endpoint:
```
POST /rest/v4/audit/list
```

### Migration Steps

1. Change endpoint path from `/signature/list` to `/audit/list`. 
2. No request or response parameter changes.

## ECDSA Signing → DSA Signing

v3 endpoint:
```
POST /rest/v3/signature/ecdsa/sign
```

v4 endpoint:
```
POST /rest/v4/dsa/sign
```

### Migration Steps

1. Replace endpoint with `/rest/v4/dsa/sign`.
2. No existing request or response parameter changes.
3. You can start using the ML-DSA signature `signatureMldsa`.

## ECDSA Verification → DSA Verification

v3 endpoint:
```
POST /rest/v3/signature/ecdsa/verify
```

v4 endpoint:
```
POST /rest/v4/dsa/verify
```

### Migration Steps

1. Replace endpoint with `/rest/v4/dsa/verify`.
2. No existing request or response parameter changes.
3. Parameter `signatureType` can be used with value `MLDSA` to verify the ML-DSA signature instead of ECDSA signature.


