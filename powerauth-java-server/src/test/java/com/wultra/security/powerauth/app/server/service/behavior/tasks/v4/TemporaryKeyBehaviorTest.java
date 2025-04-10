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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.converter.ServerPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeys;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.entity.v4.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.SharedSecretResponse;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.model.response.RemoveTemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreateActivationResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.SharedSecretClientContextHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
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
 * Test for {@link TemporaryKeyBehaviorAead}, version 4 requests and responses.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@Transactional
@ActiveProfiles("test")
class TemporaryKeyBehaviorTest {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final PowerAuthServerKeyFactory SERVER_KEY_FACTORY = new PowerAuthServerKeyFactory();

    private static final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private static final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

    private final TemporaryKeyBehaviorAead temporaryKeyBehavior;
    private final ApplicationServiceBehavior applicationServiceBehavior;
    private final ActivationServiceBehavior activationServiceBehavior;
    private final ActivationRepository activationRepository;
    private final ServerPrivateKeysConverter serverPrivateKeysConverter;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final PublicKeysConverter publicKeysConverter;

    @Autowired
    TemporaryKeyBehaviorTest(TemporaryKeyBehaviorAead temporaryKeyBehavior, ApplicationServiceBehavior applicationServiceBehavior, ActivationServiceBehavior activationServiceBehavior, ActivationRepository activationRepository, ServerPrivateKeysConverter serverPrivateKeysConverter, ApplicationVersionRepository applicationVersionRepository, MasterKeyPairRepository masterKeyPairRepository, PublicKeysConverter publicKeysConverter) {
        this.temporaryKeyBehavior = temporaryKeyBehavior;
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
        this.activationRepository = activationRepository;
        this.serverPrivateKeysConverter = serverPrivateKeysConverter;
        this.applicationVersionRepository = applicationVersionRepository;
        this.masterKeyPairRepository = masterKeyPairRepository;
        this.publicKeysConverter = publicKeysConverter;
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
    void testJwtRequestEcdheValidApplicationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null, requestCryptogram);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());
        final SignedJWT decodedJWT = SignedJWT.parse(response.getJwt());

        // TODO - use serialized keys instead of querying database after serialization of new keys is available
        final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(defaultVersion.getApplicationKey());
        final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationVersion.getApplication().getId());
        final String masterPublicKeys = masterKeyPair.getMasterPublicKeys();
        final PublicKeyRegistry publicKeys = publicKeysConverter.fromDBValue(masterPublicKeys);
        final PublicKey masterPublicKeyEc384 = publicKeys.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> new IllegalStateException("Missing public key"));

        assertTrue(validateJwtSignature(decodedJWT, masterPublicKeyEc384));
        assertEquals(defaultVersion.getApplicationKey(), decodedJWT.getJWTClaimsSet().getClaim("applicationKey"));
        assertEquals(challenge, decodedJWT.getJWTClaimsSet().getClaim("challenge"));
        assertNull(decodedJWT.getJWTClaimsSet().getClaim("activationId"));
        assertNotNull(decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse"));
    }

    @Test
    void testJwtRequestHybridValidApplicationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID.generateRequestCryptogram();
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null, requestCryptogram);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());
        final SignedJWT decodedJWT = SignedJWT.parse(response.getJwt());

        // TODO - use serialized keys instead of querying database after serialization of new keys is available
        final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(defaultVersion.getApplicationKey());
        final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationVersion.getApplication().getId());
        final String masterPublicKeys = masterKeyPair.getMasterPublicKeys();
        final PublicKeyRegistry publicKeys = publicKeysConverter.fromDBValue(masterPublicKeys);
        final PublicKey masterPublicKeyEc384 = publicKeys.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> new IllegalStateException("Missing public key"));

        // TODO - validate Dilithium signature after it is available
        assertTrue(validateJwtSignature(decodedJWT, masterPublicKeyEc384));

        assertEquals(defaultVersion.getApplicationKey(), decodedJWT.getJWTClaimsSet().getClaim("applicationKey"));
        assertEquals(challenge, decodedJWT.getJWTClaimsSet().getClaim("challenge"));
        assertNull(decodedJWT.getJWTClaimsSet().getClaim("activationId"));
        assertNotNull(decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse"));
        final Object claim = decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        assertNotNull(serverResponse.getEcdhe());
        assertNotNull(serverResponse.getMlkem());
    }

    @Test
    void testJwtRequestValidApplicationScopeWithRemove() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null, requestCryptogram);
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
    void testJwtRequestEcdheValidActivationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null, requestCryptogram);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());
        final String jwtResponse = response.getJwt();
        final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
        final String temporaryKeyId = (String) decodedJWT.getJWTClaimsSet().getClaim("sub");
        final Object claim = decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        assertNotNull(serverResponse.getEcdhe());
        // extract temporary key and use it during an activation
        final String activationId = createActivation(defaultVersion, temporaryKeyId, requestCryptogram.getSharedSecretClientContext(), serverResponse);
        final byte[] challengeBytesActivation = KEY_GENERATOR.generateRandomBytes(18);
        final String challengeActivation = Base64.getEncoder().encodeToString(challengeBytesActivation);
        final SecretKey transportMasterKey = getMasterTransportKey(activationId);
        final RequestCryptogram requestCryptogramActivation = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final String jwtRequestActivation = createJwtRequest(EncryptorScope.ACTIVATION_SCOPE, defaultVersion.getApplicationKey(), activationId, challengeActivation, defaultVersion.getApplicationSecret(), transportMasterKey, requestCryptogramActivation);
        final TemporaryPublicKeyRequest requestTempKeyActivation = new TemporaryPublicKeyRequest();
        requestTempKeyActivation.setJwt(jwtRequestActivation);
        final TemporaryPublicKeyResponse responseTempKeyActivation = temporaryKeyBehavior.requestTemporaryKey(requestTempKeyActivation);
        assertNotNull(responseTempKeyActivation.getJwt());
        final SignedJWT decodedJWTActivation = SignedJWT.parse(responseTempKeyActivation.getJwt());
        assertTrue(validateJwtSignature(decodedJWTActivation, getServerPublicKey(activationId)));
        assertEquals(defaultVersion.getApplicationKey(), decodedJWTActivation.getJWTClaimsSet().getClaim("applicationKey"));
        assertEquals(challengeActivation, decodedJWTActivation.getJWTClaimsSet().getClaim("challenge"));
        assertEquals(activationId, decodedJWTActivation.getJWTClaimsSet().getClaim("activationId"));
        assertNotNull(decodedJWTActivation.getJWTClaimsSet().getClaim("sharedSecretResponse"));
        final Object claimActivation = decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponseActivation = OBJECT_MAPPER.convertValue(claimActivation, SharedSecretResponse.class);
        assertNotNull(serverResponseActivation.getEcdhe());
    }

    @Test
    void testJwtRequestHybridValidActivationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID.generateRequestCryptogram();
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, defaultVersion.getApplicationSecret(), null, requestCryptogram);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());
        final String jwtResponse = response.getJwt();
        final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
        final String temporaryKeyId = (String) decodedJWT.getJWTClaimsSet().getClaim("sub");
        final Object claim = decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        assertNotNull(serverResponse.getEcdhe());
        assertNotNull(serverResponse.getMlkem());
        // extract temporary key and use it during an activation
        final String activationId = createActivation(defaultVersion, temporaryKeyId, requestCryptogram.getSharedSecretClientContext(), serverResponse);
        final byte[] challengeBytesActivation = KEY_GENERATOR.generateRandomBytes(18);
        final String challengeActivation = Base64.getEncoder().encodeToString(challengeBytesActivation);
        final SecretKey transportMasterKey = getMasterTransportKey(activationId);
        final RequestCryptogram requestCryptogramActivation = SHARED_SECRET_HYBRID.generateRequestCryptogram();
        final String jwtRequestActivation = createJwtRequest(EncryptorScope.ACTIVATION_SCOPE, defaultVersion.getApplicationKey(), activationId, challengeActivation, defaultVersion.getApplicationSecret(), transportMasterKey, requestCryptogramActivation);
        final TemporaryPublicKeyRequest requestTempKeyActivation = new TemporaryPublicKeyRequest();
        requestTempKeyActivation.setJwt(jwtRequestActivation);
        final TemporaryPublicKeyResponse responseTempKeyActivation = temporaryKeyBehavior.requestTemporaryKey(requestTempKeyActivation);
        assertNotNull(responseTempKeyActivation.getJwt());
        final SignedJWT decodedJWTActivation = SignedJWT.parse(responseTempKeyActivation.getJwt());
        assertTrue(validateJwtSignature(decodedJWTActivation, getServerPublicKey(activationId)));
        assertEquals(defaultVersion.getApplicationKey(), decodedJWTActivation.getJWTClaimsSet().getClaim("applicationKey"));
        assertEquals(challengeActivation, decodedJWTActivation.getJWTClaimsSet().getClaim("challenge"));
        assertEquals(activationId, decodedJWTActivation.getJWTClaimsSet().getClaim("activationId"));
        assertNotNull(decodedJWTActivation.getJWTClaimsSet().getClaim("sharedSecretResponse"));
        final Object claimActivation = decodedJWT.getJWTClaimsSet().getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponseActivation = OBJECT_MAPPER.convertValue(claimActivation, SharedSecretResponse.class);
        assertNotNull(serverResponseActivation.getEcdhe());
        assertNotNull(serverResponseActivation.getMlkem());
    }

    @Test
    void testJwtRequestInvalidSignature() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String appSecretInvalid = Base64.getEncoder().encodeToString(KEY_GENERATOR.generateRandomBytes(8));
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final String jwtRequest = createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, appSecretInvalid, null, requestCryptogram);
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

    private String createActivation(ApplicationVersion applicationVersion, String temporaryKeyId, SharedSecretClientContext clientContext, SharedSecretResponse serverResponse) throws Exception {
        final String publicKeyBytes = generatePublicKey();
        final ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();
        activationLayer2Request.setDevicePublicKey(publicKeyBytes);

        final String applicationKey = applicationVersion.getApplicationKey();
        final String applicationSecret = applicationVersion.getApplicationSecret();
        final SecretKey sharedSecret;
        if (clientContext instanceof SharedSecretClientContextEcdhe contextEcdhe) {
            final SharedSecretResponseEcdhe sharedSecretResponseEcdhe = new SharedSecretResponseEcdhe();
            sharedSecretResponseEcdhe.setEcServerPublicKey(serverResponse.getEcdhe());
            sharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret(contextEcdhe, sharedSecretResponseEcdhe);
        } else if (clientContext instanceof SharedSecretClientContextHybrid contextHybrid) {
            final SharedSecretResponseHybrid sharedSecretResponseHybrid = new SharedSecretResponseHybrid();
            sharedSecretResponseHybrid.setEcServerPublicKey(serverResponse.getEcdhe());
            sharedSecretResponseHybrid.setPqcEncapsulation(serverResponse.getMlkem());
            sharedSecret = SHARED_SECRET_HYBRID.computeSharedSecret(contextHybrid, sharedSecretResponseHybrid);
        } else {
            throw new IllegalStateException("Invalid client context");
        }
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = new EncryptorFactory().getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters("4.0", applicationKey, null, temporaryKeyId),
                new AeadSecrets(sharedSecret.getEncoded(), applicationSecret));
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(activationLayer2Request));

        final CreateActivationRequest activationRequest = new CreateActivationRequest();
        activationRequest.setUserId(UUID.randomUUID().toString());
        activationRequest.setApplicationKey(applicationKey);
        activationRequest.setProtocolVersion("4.0");
        activationRequest.setTemporaryKeyId(temporaryKeyId);
        activationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
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
        final KeyPair keyPair = keyGenerator.generateKeyPair(EcCurve.P384);
        final byte[] publicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private PublicKey getServerPublicKey(String activationId) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId).orElseThrow(() -> new IllegalStateException("Missing activation"));
        final String serverPublicKeys = activation.getServerPublicKeys();
        final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(serverPublicKeys);
        return publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> new IllegalStateException("Missing public key"));
    }

    private SecretKey getMasterTransportKey(String activationId) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId).orElseThrow(() -> new IllegalStateException("Missing activation"));
        // Get the server private key, decrypt it if required

        final String serverPrivateKeys = activation.getServerPrivateKeys();
        final EncryptionMode encryptionMode = activation.getServerPrivateKeysEncryption();
        final PrivateKeys privateKeys = new PrivateKeys(encryptionMode, serverPrivateKeys);
        final PrivateKeyRegistry privateKeyRegistry = serverPrivateKeysConverter.fromDBValue(privateKeys, activation.getUserId(), activation.getActivationId());
        final PrivateKey serverPrivateKey = privateKeyRegistry.getPrivateKey(KeyType.ECDSA_P384).orElseThrow(() -> new IllegalStateException("Missing private key"));

        final String devicePublicKeys = activation.getDevicePublicKeys();
        final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(devicePublicKeys);
        final PublicKey devicePublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> new IllegalStateException("Missing public key"));
        // TODO - switch to a key derived with KMAC-256 after activation is implemented
        final SecretKey transportKey = SERVER_KEY_FACTORY.deriveTransportKey(serverPrivateKey, devicePublicKey);

        final byte[] transportKeyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportKey);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(transportKeyBytes);
    }

    private static String createJwtRequest(EncryptorScope scope, String applicationKey, String activationId, String challenge, String appSecret, SecretKey transportMasterKey, RequestCryptogram requestCryptogram) throws Exception {
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
        final byte[] secretKey = getSecretKey(scope, appSecret, transportMasterKey);
        return signJwt(jwtClaims, secretKey);
    }

    private static byte[] getSecretKey(EncryptorScope scope, String appSecret, SecretKey transportMasterKey) throws Exception {
        if (scope == EncryptorScope.APPLICATION_SCOPE) {
            return Base64.getDecoder().decode(appSecret);
        } else if (scope == EncryptorScope.ACTIVATION_SCOPE) {
            // TODO - switch to a key derived with KMAC-256 after activation is implemented
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
