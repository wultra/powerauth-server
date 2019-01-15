Offline signatures are used in case when the mobile device is not connected to the internet. An intermediate web application with connection to the PowerAuth server can generate a QR code which is scanned by the mobile device and an offline signature is generated based on scanned QR code data. The offline signature consists of digits which can be rewritten into the web application which performs online code verification against PowerAuth server.

The following endpoints are available for offline signatures:
1. [Generating personalized offline signature payload](./Offline-Signatures#generating-personalized-offline-signature-payload)
2. [Generating non-personalized offline signature payload](./Offline-Signatures#generating-non-personalized-offline-signature-payload)
3. [Verifying offline signatures](./Offline-Signatures#verifying-offline-signatures)

## Generating personalized offline signature payload

Personalized offline signatures are used when activation ID is known (e.g. an activated mobile token). A typical use case is offline verification of signature for payments.

SOAP method: [createPersonalizedOfflineSignaturePayload](./SOAP-Service-Methods#method-createpersonalizedofflinesignaturepayload)

For Web Flow the format of request `data` is documented in the [Offline Signatures QR Code](https://github.com/lime-company/powerauth-webflow/wiki/Off-line-Signatures-QR-Code) documentation chapter.

The `offlineData` in response already contains all data required to display a QR code. The validity of the QR code should be verified by computing the ECDSA signature of `offlineData` content before the computed signature and comparing it with the `ECDSA_SIGNATURE` in `offlineData`. The `nonce` in response will be required during offline signature verification step.

## Generating non-personalized offline signature payload

Non-personalized offline signatures are used when activation ID is not known. A typical use case is offline verification for login operation.

SOAP method: [createNonPersonalizedOfflineSignaturePayload](./SOAP-Service-Methods#method-createpersonalizedofflinesignaturepayload)

For Web Flow the format of request data is documented in the [Offline Signatures QR Code](https://github.com/lime-company/powerauth-webflow/wiki/Off-line-Signatures-QR-Code) documentation chapter.

The `offlineData` in response already contains all data required to display a QR code. The validity of the QR code should be verified by computing the ECDSA signature of `offlineData` content before the computed signature and comparing it with the `ECDSA_SIGNATURE` in `offlineData`. The `nonce` in response will be required during offline signature verification step.

## Verifying offline signatures

Once the mobile device successfully scans the QR code and verifies the QR code data signature, the signature of the data related to the operation can be computed as described in [Computing and Validating Signatures](https://github.com/lime-company/powerauth-crypto/wiki/Computing-and-Validating-Signatures). The generated signature can be verified against PowerAuth server.

SOAP method: [verifyOfflineSignature](./SOAP-Service-Methods#method-verifyofflinesignature)

The normalized `data` for verifyOfflineSignature requests should be constructed as described in [Normalized data for HTTP requests](https://github.com/lime-company/powerauth-crypto/wiki/Computing-and-Validating-Signatures#normalized-data-for-http-requests). The `nonce` generated in the generate offline signature payload step should be used.

The validity of the offline signature can be checked by verifying the `signatureValid` value in VerifyOfflineSignatureResponse.
