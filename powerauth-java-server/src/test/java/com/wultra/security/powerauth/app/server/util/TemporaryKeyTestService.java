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
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.TemporaryKeyBehaviorAead;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
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

    public SignedJWT fetchTemporaryKey(RequestCryptogram requestCryptogram, ApplicationVersion applicationVersion) throws Exception {
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final byte[] secretKeyBytes = Base64.getDecoder().decode(applicationVersion.getApplicationSecret());
        final SecretKey secretKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(secretKeyBytes);
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, applicationVersion.getApplicationKey(), null, challenge, secretKey, requestCryptogram);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        return SignedJWT.parse(response.getJwt());
    }

    public String createJwtRequest(EncryptorScope scope, String applicationKey, String activationId, String challenge, SecretKey secretKey, RequestCryptogram requestCryptogram) throws Exception {
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

    public byte[] deriveSigningKey(EncryptorScope scope, SecretKey sourceKey) throws Exception {
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

    public String signJwt(JWTClaimsSet jwtClaims, byte[] secretKey) throws Exception {
        final JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        final byte[] payloadBytes = jwtClaims.toPayload().toBytes();
        final Base64URL encodedHeader = jwsHeader.toBase64URL();
        final Base64URL encodedPayload = Base64URL.encode(payloadBytes);
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] hash = new HMACHashUtilities().hash(secretKey, signingInput.getBytes(StandardCharsets.UTF_8));
        final Base64URL signature = Base64URL.encode(hash);
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    public boolean validateJwtSignature(SignedJWT jwt, PublicKey publicKey) throws Exception {
        final Base64URL[] jwtParts = jwt.getParsedParts();
        final Base64URL encodedHeader = jwtParts[0];
        final Base64URL encodedPayload = jwtParts[1];
        final Base64URL encodedSignature = jwtParts[2];
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] signatureBytes = convertRawSignatureToDER(encodedSignature.decode());
        return SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes, publicKey);
    }

    private static byte[] convertRawSignatureToDER(byte[] rawSignature) throws Exception {
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
