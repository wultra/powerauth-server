/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
 */
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.app.server.service.util.SdkConfigurationSerializer;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link TemporaryKeyBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@Transactional
@ActiveProfiles("test")
class TemporaryKeyBehaviourTest {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final PowerAuthServerKeyFactory PA_SERVER_KEY_FACTORY = new PowerAuthServerKeyFactory();

    private final TemporaryKeyBehavior temporaryKeyBehavior;
    private final ApplicationServiceBehavior applicationServiceBehavior;
    private final ActivationServiceBehavior activationServiceBehavior;
    private final ActivationRepository activationRepository;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;

    @Autowired
    TemporaryKeyBehaviourTest(TemporaryKeyBehavior temporaryKeyBehavior, ApplicationServiceBehavior applicationServiceBehavior, ActivationServiceBehavior activationServiceBehavior, ActivationRepository activationRepository, ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.temporaryKeyBehavior = temporaryKeyBehavior;
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
        this.activationRepository = activationRepository;
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    @Test
    void testJwtRequestEmpty() {
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt("");
        assertThrows(GenericServiceException.class, () -> temporaryKeyBehavior.requestTemporaryKey(request));
    }

    @Test
    void testJwtRequestInvalidClaims() throws Exception {
        final JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().build();
        final byte[] secretKey = getSecretKey(EncryptorScope.APPLICATION_SCOPE, "test", null);
        final String jwtRequest = signJwt(jwtClaims, secretKey);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        assertThrows(GenericServiceException.class, () -> temporaryKeyBehavior.requestTemporaryKey(request));
    }

    @Test
    void testJwtRequestValidApplicationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());
        final SignedJWT decodedJWT = SignedJWT.parse(request.getJwt());
        final String masterPublicKeyBase64 = SdkConfigurationSerializer.deserialize(defaultVersion.getMobileSdkConfig()).masterPublicKeyBase64();
        final PublicKey masterPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(masterPublicKeyBase64));
        validateJwtSignature(decodedJWT, masterPublicKey);
        assertEquals(defaultVersion.getApplicationKey(), decodedJWT.getJWTClaimsSet().getClaim("applicationKey"));
        assertEquals(challenge, decodedJWT.getJWTClaimsSet().getClaim("challenge"));
        assertNull(decodedJWT.getJWTClaimsSet().getClaim("activationId"));
    }

    @Test
    void testJwtRequestValidApplicationScopeWithRemove() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());
        final String jwtResponse = response.getJwt();
        final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
        final String temporaryKeyId = (String) decodedJWT.getJWTClaimsSet().getClaim("sub");
        final RemoveTemporaryPublicKeyRequest removeRequest = new RemoveTemporaryPublicKeyRequest();
        removeRequest.setId(temporaryKeyId);
        final RemoveTemporaryPublicKeyResponse removeResponse = temporaryKeyBehavior.removeTemporaryKey(removeRequest);
        assertEquals(temporaryKeyId, removeResponse.getId());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    void testJwtRequestValidActivationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());
        final String jwtResponse = response.getJwt();
        final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
        final String temporaryKeyId = (String) decodedJWT.getJWTClaimsSet().getClaim("sub");
        final String temporaryPublicKeyRaw = (String) decodedJWT.getJWTClaimsSet().getClaim("publicKey");
        final PublicKey temporaryPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(temporaryPublicKeyRaw));
        // extract temporary key and use it during an activation
        final String activationId = createActivation(defaultVersion, temporaryKeyId, temporaryPublicKey);
        final byte[] challengeBytesActivation = KEY_GENERATOR.generateRandomBytes(18);
        final String challengeActivation = Base64.getEncoder().encodeToString(challengeBytesActivation);
        final SecretKey transportMasterKey = getMasterTransportKey(activationId);
        final String jwtRequestActivation = createJwtRequest(EncryptorScope.ACTIVATION_SCOPE, defaultVersion.getApplicationKey(), activationId, challengeActivation, defaultVersion.getApplicationSecret(), transportMasterKey);
        final TemporaryPublicKeyRequest requestTempKeyActivation = new TemporaryPublicKeyRequest();
        requestTempKeyActivation.setJwt(jwtRequestActivation);
        final TemporaryPublicKeyResponse responseTempKeyActivation = temporaryKeyBehavior.requestTemporaryKey(requestTempKeyActivation);
        assertNotNull(responseTempKeyActivation.getJwt());
        final SignedJWT decodedJWTActivation = SignedJWT.parse(responseTempKeyActivation.getJwt());
        validateJwtSignature(decodedJWTActivation, getServerPublicKey(activationId));
        assertEquals(defaultVersion.getApplicationKey(), decodedJWTActivation.getJWTClaimsSet().getClaim("applicationKey"));
        assertEquals(challengeActivation, decodedJWTActivation.getJWTClaimsSet().getClaim("challenge"));
        assertEquals(activationId, decodedJWTActivation.getJWTClaimsSet().getClaim("activationId"));
    }

    @Test
    void testJwtRequestInvalidSignature() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String appSecretInvalid = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(8));
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, appSecretInvalid, null);
        request.setJwt(jwtRequest);
        assertThrows(GenericServiceException.class, () -> temporaryKeyBehavior.requestTemporaryKey(request));
    }

    private ApplicationVersion createApplication() throws GenericServiceException {
        final CreateApplicationRequest appRequest = new CreateApplicationRequest();
        appRequest.setApplicationId(UUID.randomUUID().toString());
        final CreateApplicationResponse appResponse = applicationServiceBehavior.createApplication(appRequest);
        final GetApplicationDetailRequest appDetailRequest = new GetApplicationDetailRequest();
        appDetailRequest.setApplicationId(appResponse.getApplicationId());
        final GetApplicationDetailResponse appDetailResponse = applicationServiceBehavior.getApplicationDetail(appDetailRequest);
        return appDetailResponse.getVersions().get(0);
    }

    private String createActivation(ApplicationVersion applicationVersion, String temporaryKeyId, PublicKey temporaryPublicKey) throws Exception {
        final String publicKeyBytes = generatePublicKey();
        final ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();
        activationLayer2Request.setDevicePublicKey(publicKeyBytes);

        final String applicationKey = applicationVersion.getApplicationKey();
        final String applicationSecret = applicationVersion.getApplicationSecret();

        final ClientEncryptor clientEncryptor = new EncryptorFactory().getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters("3.3", applicationKey, null, temporaryKeyId),
                new ClientEncryptorSecrets(temporaryPublicKey, applicationSecret));
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(activationLayer2Request));

        final CreateActivationRequest activationRequest = new CreateActivationRequest();
        activationRequest.setUserId(UUID.randomUUID().toString());
        activationRequest.setApplicationKey(applicationKey);
        activationRequest.setProtocolVersion("3.3");
        activationRequest.setTemporaryKeyId(temporaryKeyId);
        activationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        activationRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        activationRequest.setMac(encryptedRequest.getMac());
        activationRequest.setNonce(encryptedRequest.getNonce());
        activationRequest.setTimestamp(encryptedRequest.getTimestamp());
        final CreateActivationResponse response = activationServiceBehavior.createActivation(activationRequest);
        final CommitActivationRequest commitRequest = new CommitActivationRequest();
        commitRequest.setActivationId(response.getActivationId());
        activationServiceBehavior.commitActivation(commitRequest);
        return response.getActivationId();
    }

    private String generatePublicKey() throws Exception {
        final KeyGenerator keyGenerator = new KeyGenerator();
        final KeyPair keyPair = keyGenerator.generateKeyPair();
        final byte[] publicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private PublicKey getServerPublicKey(String activationId) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId).get();
        final String serverPublicKeyBase64 = activation.getServerPublicKeyBase64();
        return KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(serverPublicKeyBase64));
    }

    private SecretKey getMasterTransportKey(String activationId) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId).get();
        // Get the server private key, decrypt it if required
        final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
        final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
        final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
        final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
        final PrivateKey serverPrivateKey = KEY_CONVERTOR.convertBytesToPrivateKey(serverPrivateKeyBytes);

        // Get application secret and transport key used in sharedInfo2 parameter of ECIES
        final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
        final PublicKey devicePublicKey = KEY_CONVERTOR.convertBytesToPublicKey(devicePublicKeyBytes);
        final SecretKey transportKey = PA_SERVER_KEY_FACTORY.deriveTransportKey(serverPrivateKey, devicePublicKey);
        final byte[] transportKeyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportKey);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(transportKeyBytes);
    }

    private static String createJwtRequest(EncryptorScope scope, String applicationKey, String activationId, String challenge, String appSecret, SecretKey transportMasterKey) throws Exception {
        final Instant now = Instant.now();
        final JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .claim("applicationKey", applicationKey)
                .claim("activationId", activationId)
                .claim("challenge", challenge)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                .build();
        final byte[] secretKey = getSecretKey(scope, appSecret, transportMasterKey);
        return signJwt(jwtClaims, secretKey);
    }

    private static byte[] getSecretKey(EncryptorScope scope, String appSecret, SecretKey transportMasterKey) throws Exception {
        if (scope == EncryptorScope.APPLICATION_SCOPE) {
            return Base64.getDecoder().decode(appSecret);
        } else if (scope == EncryptorScope.ACTIVATION_SCOPE) {
            final byte[] appSecretBytes = Base64.getDecoder().decode(appSecret);
            final SecretKey secretKeyBytes = KEY_GENERATOR.deriveSecretKeyHmac(transportMasterKey, appSecretBytes);
            return KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKeyBytes);
        }
        return null;
    }

    private static String signJwt(JWTClaimsSet jwtClaims, byte[] secretKey) throws Exception {
        final JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        final byte[] payloadBytes = jwtClaims.toPayload().toBytes();
        final Base64URL encodedHeader = jwsHeader.toBase64URL();
        final Base64URL encodedPayload = Base64URL.encode(payloadBytes);
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] hash = new HMACHashUtilities().hash(secretKey, signingInput.getBytes(StandardCharsets.UTF_8));
        final Base64URL signature = Base64URL.encode(hash);
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    private static boolean validateJwtSignature(SignedJWT jwt, PublicKey publicKey) throws Exception {
        final Base64URL[] jwtParts = jwt.getParsedParts();
        final Base64URL encodedHeader = jwtParts[0];
        final Base64URL encodedPayload = jwtParts[1];
        final Base64URL encodedSignature = jwtParts[2];
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] signatureBytes = convertRawSignatureToDER(encodedSignature.decode());
        return SIGNATURE_UTILS.validateECDSASignature(signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes, publicKey);
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
