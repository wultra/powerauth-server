---
layout: page
title: SOAP Method Compatibility
---

## SOAP Method Compatibility

This chapter describes SOAP interface changes per each SOAP method between PowerAuth protocol versions `2.x` and `3.0`. 
The table below lists which methods are available for each version of PowerAuth protocol and describes how to handle the interface change.

| Method                      | `v2` | `v3` | Compatibility issues | Migration notes |
| --------------------------- |:----:|:----:| -------------------- | --------------- |
| `getActivationStatus`       |      |  X   | Binary representation of encrypted status blob changed | Method moved to `v3`, use `v3` method, migrate to updated `PowerAuthServerActivation.encryptedStatusBlob` method |
| `initActivation`            |      |  X   | Removed `activationOTP`, renamed `activationIdShort` to `activationCode`, `activationSignature` is calculated only from `activationCode` | Migrate to response with new activation code structure |
| `prepareActivation`         |  X   |  X   | `v3` version uses ECIES, incompatible with `v2`| Use either `v2` (will be deprecated in future release) or migrate to ECIES in `v3` | 
| `createActivation`          |  X   |  X   | `v3` version uses ECIES, incompatible with `v2`| Use either `v2` (will be deprecated in future release) or migrate to ECIES in `v3` |
| `vaultUnlock`               |  X   |  X   | `v3` version uses ECIES, incompatible with `v2`| Use either `v2` (will be deprecated in future release) or migrate to ECIES in `v3` |
| `verifySignature`           |      |  X   | Added `signatureVersion`, PowerAuth uses signature version based on activation version, `signatureVersion` parameter is used during upgrade and is optional | Method moved to `v3`, use `v3` method |
| `createPersOfflineSigPl`    |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `createNonPersOfflineSigPl` |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `verifyOfflineSignature`    |      |  X   | PowerAuth server uses `v2` or `v3` version of signature based on version of activation | Method moved to `v3`, use `v3` method   |
| `generateE2EPersEncKey`     |  X   |      | Not supported in `v3`, used in legacy E2E encryption | ECIES-based encryption should be used as replacement for legacy E2E encryption |
| `generateE2ENonPersEncKey`  |  X   |      | Not supported in `v3`, used in legacy E2E encryption | ECIES-based encryption should be used as replacement for legacy E2E encryption |
| `createToken`               |  X   |  X   | ECIES keys and `sharedInfo` parameters have changed in `v3` which broke compatibility | Use either `v2` (will be deprecated in future release) or migrate to new ECIES parameters in `v3` |
| `validateToken`             |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `removeToken`               |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getSystemStatus`           |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getActivationListForUser`  |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getErrorCodeList`          |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `commitActivation`          |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `removeActivation`          |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `blockActivation`           |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `unblockActivation`         |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `verifyECDSASignature`      |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getSignatureAuditLog`      |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getActivationHistory`      |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getApplicationList`        |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getApplicationDetail`      |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `lookupApplicationByAppKey` |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `createApplication`         |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `createApplicationVersion`  |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `unsupportApplVersion`      |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `supportApplicationVersion` |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `createIntegration`         |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getIntegrationList`        |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `removeIntegration`         |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `createCallbackUrl`         |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `getCallbackUrlList`        |      |  X   |                      | Method moved to `v3`, use `v3` method   |
| `removeCallbackUrl`         |      |  X   |                      | Method moved to `v3`, use `v3` method   |

New `v3` methods (added for completeness, they have no impact on compatibility):
- `getEciesDecryptor`
- `startUpgrade`
- `commitUpgrade`
