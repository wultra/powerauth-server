# PowerAuth Server – Migration Guide from REST API v3 to v4

This document describes how to migrate client integrations from **PowerAuth Server REST API v3** to **v4**.

## General Migration Rules

1. Replace `/rest/v3` with `/rest/v4`.
2. Update controller path segments as described below.
3. Unless explicitly stated, **request and response payloads are unchanged**.

## Online Authentication Verification

### v3
```
POST /rest/v3/signature/verify
```

### v4
```
POST /rest/v4/auth/verify
```

### Migration Steps

1. Change endpoint path from `/signature/verify` to `/auth/verify`.
2. Request parameter `signature` should be changed to `authenticationCode`.
3. Request parameter `signatureType` should be changed to `authenticationCodeType`.
4. Request parameter `signatureVersion` should be changed to `authenticationVersion`.
5. Response parameter `signatureValid` should be changed to `authenticationValid`.
6. Response parameter `signatureType` should be changed to `authenticationCodeType`.

## Offline Authentication Verification

### v3
```
POST /rest/v3/signature/offline/verify
```

### v4
```
POST /rest/v4/auth/offline/verify
```

### Migration Steps

1. Update endpoint path to `/rest/v4/auth/offline/verify`.
2. Request parameter `signature` should be changed to `authenticationCode`.
3. Response parameter `signatureValid` should be changed to `authenticationValid`.
4. Response parameter `signatureType` should be changed to `authenticationCodeType`.

## Create Personalized Offline Authentication Payload

### v3
```
POST /rest/v3/signature/offline/personalized/create
```

### v4
```
POST /rest/v4/auth/offline/personalized/create
```

### Migration Steps

1. Replace `/signature/offline/personalized/create` with `/auth/offline/personalized/create`.
2. Payload and response remain unchanged.

## Create Non-Personalized Offline Authentication Payload

### v3
```
POST /rest/v3/signature/offline/non-personalized/create
```

### v4
```
POST /rest/v4/auth/offline/non-personalized/create
```

### Migration Steps

1. Replace `/signature/offline/non-personalized/create` with `/auth/offline/non-personalized/create`.
2. Payload and response remain unchanged.

## Signature / Authentication Audit Log

### v3
```
POST /rest/v3/signature/list
```

### v4
```
POST /rest/v4/audit/list
```

### Migration Steps

1. Change endpoint path from `/signature/list` to `/audit/list`. 
2. No request or response parameter changes.

## ECDSA Signing → DSA Signing

### v3
```
POST /rest/v3/signature/ecdsa/sign
```

### v4
```
POST /rest/v4/dsa/sign
```

### Migration Steps

1. Replace endpoint with `/rest/v4/dsa/sign`.
2. No existing request or response parameter changes.
3. You can start using the ML-DSA signature `signatureMldsa`.

## ECDSA Verification → DSA Verification

### v3
```
POST /rest/v3/signature/ecdsa/verify
```

### v4
```
POST /rest/v4/dsa/verify
```

### Migration Steps

1. Replace endpoint with `/rest/v4/dsa/verify`.
2. No existing request or response parameter changes.
3. Parameter `signatureType` can be used with value `MLDSA` to verify the ML-DSA signature instead of ECDSA signature.


