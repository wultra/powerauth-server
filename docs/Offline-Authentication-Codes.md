# Offline Authentication Codes

Offline authentication codes enable authorization of operations in scenarios where the mobile application cannot
communicate online with backend services directly.

Instead of communicating directly with the server, the mobile application derives a numeric authentication code from
structured payload delivered through an alternative channel, typically using an intermediate application that presents
the structured payload as a QR code.

The mobile application processes the structured payload locally and computes the authentication code without requiring
network connectivity. The resulting authentication code must then be delivered to PowerAuth Server for verification, for
example by manually entering the authentication code into the intermediate application, which then forwards the code
to the PowerAuth Server.

The PowerAuth Server provides an API for generating structured offline authentication payloads intended for delivery to
the user as a QR code content, and an API for verifying authentication codes computed by the mobile application.

This chapter describes how to generate the offline authentication payload and how to verify the authentication code
returned by the user.

## Request Authentication Payload

The PowerAuth Server supports two types of offline authentication payloads: personalized and non-personalized.
These payload types differ in whether the operation to be authorized is already associated with a specific activation.

A non-personalized offline authentication payload is used when the operation is not yet associated with a specific
activation and the activation identifier is therefore not available. A typical use case is offline verification for
a login operation. See REST method [createNonPersonalizedOfflineAuthPayload](WebServices-Methods-V4.md#method-createnonpersonalizedofflineauthpayload)
reference documentation for further details, or the legacy V3 protocol alternative [createNonPersonalizedOfflineSignaturePayload](WebServices-Methods-V3.md#method-createnonpersonalizedofflinesignaturepayload).

A personalized offline authentication payload is used when the operation is already associated with a specific
activation and the activation identifier is known. A typical use case is offline verification of a payment operation.
See REST method [createPersonalizedOfflineAuthPayload](WebServices-Methods-V4.md#method-createpersonalizedofflineauthpayload)
reference documentation for further details, or the legacy V3 protocol alternative [createPersonalizedOfflineSignaturePayload](WebServices-Methods-V3.md#method-createpersonalizedofflinesignaturepayload).

### Request and Response Attributes

Both methods for requesting personalized and non-personalized offline authentication payloads use the request
attribute `data`. The `data` attribute defines the data block to be included in the generated offline authentication
payload. The data block should have a [structured representation](#data-structure) as described later.

Both methods also return the response attribute `offlineData`. The `offlineData` contains the provided data block
concatenated with additional attributes and a cryptographic signature in the following format:

```
{DATA}\n{NONCE_B64}\n{KEY_TYPE}{DATA_SIGNATURE_B64}
```

Where
- `{DATA}` is the data block passed in `data` request attribute,
- `{NONCE_B64}` is a randomly generated 16-byte nonce encoded in Base64,
- `{KEY_TYPE}` is a single digit identifying the signing key,
- `{DATA_SIGNATURE_B64}` is the cryptographic signature of all preceding fields.

As the `{DATA}` should follow the structured representation, the `offlineData` can be directly encoded into a QR code
and transferred as a complete offline authentication payload to the mobile token application.

The `{KEY_TYPE}` field may contain one of the following values:
- `0` indicates that `KEY_MASTER_ECDSA_P384_PRIVATE` key was used for ECDSA signature (or `KEY_MASTER_P256_PRIVATE` if V3 protocol is in use),
- `1` indicates that `KEY_SERVER_P256_PRIVATE` key and protocol V3 was used for ECDSA signature,
- `2` indicates that `KEY_MAC_PERSONALIZED_DATA` personalized key derived from the `KDK_UTILITY` key was used for KMAC-256 signature in V4 protocol.

### Data Structure

The data block passed to the personalized or non-personalized authentication payload should follow a predefined
structure to enable compatibility with the PowerAuth and enable the authentication payload transfer as a QR code
to the mobile token application.

The data block should contain attributes of the operation, i.e. operation ID, title, description, structured operation
data and flags as a new-line separated list in the following format:

```
{OPERATION_ID}\n
{TITLE}\n
{MESSAGE}\n
{OPERATION_DATA}\n
{FLAGS}
```

Where
1. `{OPERATION_ID}` - operation identifier (UUID-like identifier).
2. `{TITLE}` - operation title in UTF8 format.
    - ASCII control characters (code < 32) are forbidden.
    - `\n` can be used for newline character.
    - `\\` can be used for backslash.
3. `{MESSAGE}` - message associated with operation, in UTF8 format.
    - ASCII control characters (code < 32) are forbidden.
    - `\n` can be used for newline character.
    - `\\` can be used for backslash.
4. `{OPERATION_DATA}` - structured operation data.
5. `{FLAGS}` - optional flags that affect the operation processing

The resulting offline authentication payload produced by PowerAuth Server has therefore following format:

```
{OPERATION_ID}\n
{TITLE}\n
{MESSAGE}\n
{OPERATION_DATA}\n
{FLAGS}\n
{NONCE_B64}\n
{KEY_TYPE}{DATA_SIGNATURE_B64}
```

### Data Compatibility

The data format is designed for forward compatibility, allowing older parsers to process payloads that include new
attributes. This is achieved through the following contract rules:

- Offline authentication payload must end with sequence `{NONCE_B64}\n{KEY_TYPE}{DATA_SIGNATURE_B64}`.
- `{DATA_SIGNATURE_B64}` must always be calculated over all preceding attributes,
- Any new operation attribute must be added only as a separate line immediately before `{NONCE_B64}`.

### Proximity Anti-Fraud Check

When requesting a personalized offline authentication payload, the proximity anti-fraud feature may be enabled.
To enable this feature, specify `nonce`, `proximityCheck.seed`, and `proximityCheck.stepLength` in the request.
If proximity anti-fraud is enabled, the `offlineData` response format changes to:

```
{DATA}\n{TOTP}\n{NONCE_B64}\n{KEY_TYPE}{DATA_SIGNATURE_B64}
```

## Verify the Authentication Code

To verify the authentication code, use REST method [verifyOfflineAuthentication](WebServices-Methods-V4.md#method-verifyofflineauthentication),
or the legacy V3 protocol alternative [verifyOfflineSignature](WebServices-Methods-V3.md#method-verifyofflinesignature).

By default, the `authenticationCode` request attribute must contain zero-padded 8-digit long number for each
authentication factor used, concatenated with a dash symbol. For example, when two factors are used, the
authentication code may have the following form: `88457234-00630125`.

The `data` attribute of the REST method request must be [normalized](https://developers.wultra.com/components/powerauth-crypto/develop/documentation/Computing-and-Validating-Authentication-Codes#normalized-data-for-http-requests)
to match the format that was used by the mobile application that generated the authentication code.
The normalized format for offline authentication is:

```
{REQUEST_METHOD}&{URI_IDENTIFIER_B64}&{NONCE_B64}&{DATA_B64}
```

Where
- `{REQUEST_METHOD}` is string `POST`,
- `{URI_IDENTIFIER_B64}` is string `/operation/authorize/offline` encoded in Base64,
- `{NONCE_B64}` is the nonce received from the PowerAuth Server, and
- `{DATA_B64}` is `{OPERATION_ID}&{OPERATION_DATA}`, that were used in the structured data block, encoded in Base64.

For convenience, a Java implementation of the normalization procedure is available in the class
[PowerAuthHttpBody](https://github.com/wultra/powerauth-crypto/blob/develop/powerauth-java-http/src/main/java/com/wultra/security/powerauth/http/PowerAuthHttpBody.java).
