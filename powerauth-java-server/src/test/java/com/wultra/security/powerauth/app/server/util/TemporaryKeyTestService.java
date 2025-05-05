/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package com.wultra.security.powerauth.app.server.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.TemporaryKeyBehaviorAead;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import lombok.AllArgsConstructor;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/**
 * Utilities for handling temporary keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@AllArgsConstructor
public class TemporaryKeyTestService {

    private final TemporaryKeyBehaviorAead temporaryKeyBehavior;

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final PqcDsa PQC_DSA = new PqcDsa();

    /**
     * Fetch a temporary key.
     *
     * @param requestCryptogram Request cryptogram for AEAD client request.
     * @param applicationVersion Application version.
     * @return JWSObjectJSON object containing information about temporary key.
     * @throws GenericServiceException Thrown in case of a business logic error.
     * @throws CryptoProviderException Thrown in case crypto provider is not initialized properly.
     * @throws GenericCryptoException Thrown in case of a cryptography error.
     * @throws ParseException Thrown in case of invalid response from server.
     */
    public JWSObjectJSON fetchTemporaryKey(RequestCryptogram requestCryptogram, ApplicationVersion applicationVersion) throws GenericServiceException, CryptoProviderException, GenericCryptoException, ParseException {
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final byte[] secretKeyBytes = Base64.getDecoder().decode(applicationVersion.getApplicationSecret());
        final SecretKey secretKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(secretKeyBytes);
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, applicationVersion.getApplicationKey(), null, challenge, secretKey, requestCryptogram);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        return JWSObjectJSON.parse(response.getJwt());
    }

    /**
     * Create a JWT request for temporary key.
     *
     * @param scope Encryptor scope.
     * @param applicationKey Application key.
     * @param activationId Activation identifier.
     * @param challenge Request challenge.
     * @param secretKey Secret key for signing key derivation.
     * @param requestCryptogram Request cryptogram for AEAD client request.
     * @return Response JWT.
     * @throws GenericCryptoException Thrown in case of a cryptography error.
     * @throws CryptoProviderException Thrown in case crypto provider is not initialized properly.
     */
    public String createJwtRequest(EncryptorScope scope, String applicationKey, String activationId, String challenge, SecretKey secretKey, RequestCryptogram requestCryptogram) throws GenericCryptoException, CryptoProviderException {
        final Instant now = Instant.now();
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .claim("applicationKey", applicationKey)
                .claim("activationId", activationId)
                .claim("challenge", challenge)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)));
        final Object request = requestCryptogram.getSharedSecretRequest();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        if (request instanceof SharedSecretRequestEcdhe ecdhe) {
            sharedSecretRequest.setAlgorithm("EC_P384");
            sharedSecretRequest.setEcdhe(ecdhe.getEcClientPublicKey());
        } else if (request instanceof SharedSecretRequestHybrid hybrid) {
            sharedSecretRequest.setAlgorithm("EC_P384_ML_L3");
            sharedSecretRequest.setEcdhe(hybrid.getEcClientPublicKey());
            sharedSecretRequest.setMlkem(hybrid.getPqcEncapsulationKey());
        } else {
            throw new IllegalStateException("Invalid cryptogram");
        }
        builder.claim("sharedSecretRequest", sharedSecretRequest);
        final JWTClaimsSet jwtClaims = builder.build();
        final byte[] signingKey = deriveSigningKey(scope, secretKey);
        return signJwt(jwtClaims, signingKey);
    }

    /**
     * Derive signing key from the source key.
     *
     * @param scope Encryptor scope.
     * @param sourceKey Source key.
     * @return Derived signing key.
     * @throws GenericCryptoException Thrown in case of a cryptography error.
     */
    public byte[] deriveSigningKey(EncryptorScope scope, SecretKey sourceKey) throws GenericCryptoException {
        return switch (scope) {
            case APPLICATION_SCOPE -> {
                final SecretKey secretKey = KeyFactory.deriveKeyMacGetAppTempKey(sourceKey);
                yield KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(secretKey);
            }
            case ACTIVATION_SCOPE -> {
                final SecretKey secretKey = KeyFactory.deriveKeyMacGetActTempKey(sourceKey);
                yield KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(secretKey);
            }
        };
    }

    /**
     * Sign a JWT request.
     *
     * @param jwtClaims JWT claims
     * @param signingKey Secret key used for signing.
     * @return JWT payload with signature.
     * @throws GenericCryptoException Thrown in case of a cryptography error.
     * @throws CryptoProviderException Thrown in case crypto provider is not initialized properly.
     */
    public String signJwt(JWTClaimsSet jwtClaims, byte[] signingKey) throws GenericCryptoException, CryptoProviderException {
        final JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        final byte[] payloadBytes = jwtClaims.toPayload().toBytes();
        final Base64URL encodedHeader = jwsHeader.toBase64URL();
        final Base64URL encodedPayload = Base64URL.encode(payloadBytes);
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] hash = new HMACHashUtilities().hash(signingKey, signingInput.getBytes(StandardCharsets.UTF_8));
        final Base64URL signature = Base64URL.encode(hash);
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    /**
     * Validates a JWS signature of the given payload.
     * This method supports validation of signatures generated using
     * the {@code ES384} or {@code ML-DSA-65} algorithms.
     *
     * @param payload JWS payload.
     * @param signature Item from the JWS signatures array.
     * @param publicKey Public key to use for signature verification.
     * @return Whether signature is valid.
     * @throws IOException Thrown in case of a conversion error.
     * @throws GenericCryptoException Thrown in case of a cryptography error.
     * @throws InvalidKeyException Thrown in case the public key is invalid.
     * @throws CryptoProviderException Thrown in case crypto provider is not initialized properly.
     */
    public boolean validateJwsSignature(Payload payload, JWSObjectJSON.Signature signature, PublicKey publicKey) throws IOException, GenericCryptoException, InvalidKeyException, CryptoProviderException {
        final String signingInput = signature.getHeader().getParsedBase64URL() + "." + payload.toBase64URL();

        return switch (signature.getHeader().getAlgorithm().getName()) {
            case "ES384" -> SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, signingInput.getBytes(StandardCharsets.UTF_8), convertRawSignatureToDER(signature.getSignature().decode()), publicKey);
            case "ML-DSA-65" -> PQC_DSA.verify(publicKey, signingInput.getBytes(StandardCharsets.UTF_8), signature.getSignature().decode());
            default -> throw new IllegalStateException("Unexpected value: " + signature.getHeader().getAlgorithm().getName());
        };
    }

    /**
     * Convert raw signature to DER format.
     *
     * @param rawSignature Raw signature.
     * @return Signature in DER format.
     * @throws IOException Thrown in case of a conversion error.
     */
    private static byte[] convertRawSignatureToDER(byte[] rawSignature) throws IOException {
        if (rawSignature.length % 2 != 0) {
            throw new IllegalArgumentException("Invalid ECDSA signature format");
        }
        int len = rawSignature.length / 2;
        byte[] rBytes = new byte[len];
        byte[] sBytes = new byte[len];
        System.arraycopy(rawSignature, 0, rBytes, 0, len);
        System.arraycopy(rawSignature, len, sBytes, 0, len);
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DLSequence(v).getEncoded();
    }
}
