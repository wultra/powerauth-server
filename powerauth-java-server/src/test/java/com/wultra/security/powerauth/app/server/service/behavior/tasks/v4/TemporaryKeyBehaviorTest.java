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
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jwt.JWTClaimsSet;
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.SdkConfiguration;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.response.v4.ActivationLayer2Response;
import com.wultra.security.powerauth.app.server.service.util.SdkConfigurationSerializer;
import com.wultra.security.powerauth.app.server.service.util.jwt.JWSAlgorithmMLDSA;
import com.wultra.security.powerauth.app.server.util.TemporaryKeyTestService;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.entity.v4.request.DevicePublicKeys;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.response.SharedSecretResponse;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.RemoveTemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreateActivationResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.DefaultSharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretFactory;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
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
    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsa PQC_DSA = new MlDsa();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_ECDHE = SharedSecretFactory.getEcdhe();
    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_HYBRID_ML_L3 = SharedSecretFactory.getHybridMlL3();

    private final TemporaryKeyBehaviorAead temporaryKeyBehavior;
    private final ApplicationServiceBehavior applicationServiceBehavior;
    private final ApplicationDetailServiceBehavior applicationDetailServiceBehavior;
    private final ActivationServiceBehavior activationServiceBehavior;
    private final ActivationCreateServiceBehavior activationServiceBehaviorV4;
    private final ActivationRepository activationRepository;
    private final PublicKeysConverter publicKeysConverter;

    private final TemporaryKeyTestService temporaryKeyTestService;

    @Autowired
    TemporaryKeyBehaviorTest(TemporaryKeyBehaviorAead temporaryKeyBehavior, ApplicationServiceBehavior applicationServiceBehavior, ApplicationDetailServiceBehavior applicationDetailServiceBehavior, ActivationServiceBehavior activationServiceBehavior, ActivationCreateServiceBehavior activationServiceBehaviorV4, ActivationRepository activationRepository, PublicKeysConverter publicKeysConverter, TemporaryKeyTestService temporaryKeyTestService) {
        this.temporaryKeyBehavior = temporaryKeyBehavior;
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.applicationDetailServiceBehavior = applicationDetailServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
        this.activationServiceBehaviorV4 = activationServiceBehaviorV4;
        this.activationRepository = activationRepository;
        this.publicKeysConverter = publicKeysConverter;
        this.temporaryKeyTestService = temporaryKeyTestService;
    }

    @Test
    void testJwtRequestEmpty() {
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt("");
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> temporaryKeyBehavior.requestTemporaryKey(request));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void testJwtRequestInvalidClaims() throws Exception {
        final JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().build();
        final SecretKey secretKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey("test".getBytes(StandardCharsets.UTF_8));
        final byte[] signingKey = temporaryKeyTestService.deriveSigningKey(EncryptorScope.APPLICATION_SCOPE, secretKey);
        final String jwtRequest = temporaryKeyTestService.signJwt(jwtClaims, signingKey);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> temporaryKeyBehavior.requestTemporaryKey(request));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void testJwtRequestEcdheValidApplicationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final byte[] secretKeyBytes = Base64.getDecoder().decode(defaultVersion.getApplicationSecret());
        final SecretKey secretKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(secretKeyBytes);
        final String jwtRequest = temporaryKeyTestService.createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, secretKey, requestCryptogram);
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        request.setJwt(jwtRequest);
        final TemporaryPublicKeyResponse response = temporaryKeyBehavior.requestTemporaryKey(request);
        assertNotNull(response.getJwt());

        final JWSObjectJSON jws = JWSObjectJSON.parse(response.getJwt());
        assertEquals(1, jws.getSignatures().size());
        assertTrue(hasValidSignature(jws, JWSAlgorithm.ES384, getMasterPublicEcKey(defaultVersion)));

        final JWTClaimsSet claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject());
        assertEquals(defaultVersion.getApplicationKey(), claims.getStringClaim("applicationKey"));
        assertEquals(challenge, claims.getStringClaim("challenge"));
        assertNull(claims.getClaim("activationId"));
        assertNotNull(claims.getClaim("sharedSecretResponse"));
    }

    @Test
    void testJwtRequestHybridValidApplicationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID_ML_L3.generateRequestCryptogram();
        final JWSObjectJSON jws = temporaryKeyTestService.fetchTemporaryKey(requestCryptogram, defaultVersion);

        assertEquals(2, jws.getSignatures().size());
        assertTrue(hasValidSignature(jws, JWSAlgorithm.ES384, getMasterPublicEcKey(defaultVersion)));
        assertTrue(hasValidSignature(jws, JWSAlgorithmMLDSA.MLDSA65, getMasterPublicPqcKey(defaultVersion)));

        final JWTClaimsSet claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject());
        assertEquals(defaultVersion.getApplicationKey(), claims.getClaim("applicationKey"));
        assertNull(claims.getClaim("activationId"));
        assertNotNull(claims.getClaim("sharedSecretResponse"));
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        assertNotNull(serverResponse.getEncapsulatedKeys().get(0));
        assertNotNull(serverResponse.getEncapsulatedKeys().get(1));
    }

    @Test
    void testJwtRequestApplicationScope_wrongApplicationKey() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        defaultVersion.setApplicationKey("wrongApplicationKey");

        final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID_ML_L3.generateRequestCryptogram();
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> temporaryKeyTestService.fetchTemporaryKey(requestCryptogram, defaultVersion));
        assertEquals(ServiceError.INVALID_APPLICATION, exception.getCode());
    }

    @Test
    void testJwtRequestHybridApplicationScope_wrongMlDsaPublicKey() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID_ML_L3.generateRequestCryptogram();
        final JWSObjectJSON jws = temporaryKeyTestService.fetchTemporaryKey(requestCryptogram, defaultVersion);

        assertEquals(2, jws.getSignatures().size());
        assertFalse(hasValidSignature(jws, JWSAlgorithmMLDSA.MLDSA65, PQC_DSA.generateKeyPair().getPublic()));
    }

    @Test
    void testJwtRequestValidApplicationScopeWithRemove() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final JWSObjectJSON jws = temporaryKeyTestService.fetchTemporaryKey(requestCryptogram, defaultVersion);
        final JWTClaimsSet claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject());

        final String temporaryKeyId = claims.getSubject();
        final RemoveTemporaryPublicKeyRequest removeRequest = new RemoveTemporaryPublicKeyRequest();
        removeRequest.setId(temporaryKeyId);
        final RemoveTemporaryPublicKeyResponse removeResponse = temporaryKeyBehavior.removeTemporaryKey(removeRequest);
        assertEquals(temporaryKeyId, removeResponse.getId());
        assertTrue(removeResponse.isRemoved());
    }

    @Test
    void testJwtRequestEcdheValidActivationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final JWSObjectJSON jws = temporaryKeyTestService.fetchTemporaryKey(requestCryptogram, defaultVersion);
        final JWTClaimsSet claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject());

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        assertNotNull(serverResponse.getEncapsulatedKeys().get(0));
        // extract temporary key and use it during an activation
        final ActivationContext activationContext = createActivation(defaultVersion, temporaryKeyId, requestCryptogram.getSharedSecretClientContext(), serverResponse);
        final String activationId = activationContext.activationLayer2Response.getActivationId();
        final byte[] challengeBytesActivation = KEY_GENERATOR.generateRandomBytes(18);
        final String challengeActivation = Base64.getEncoder().encodeToString(challengeBytesActivation);
        final SecretKey signingKeyActivation = deriveSharedSecret(activationContext.sharedSecretClientContext, activationContext.activationLayer2Response.getSharedSecretResponse());
        final RequestCryptogram requestCryptogramActivation = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final String jwtRequestActivation = temporaryKeyTestService.createJwtRequest(EncryptorScope.ACTIVATION_SCOPE, defaultVersion.getApplicationKey(), activationId, challengeActivation, signingKeyActivation, requestCryptogramActivation);
        final TemporaryPublicKeyRequest requestTempKeyActivation = new TemporaryPublicKeyRequest();
        requestTempKeyActivation.setJwt(jwtRequestActivation);
        final TemporaryPublicKeyResponse responseTempKeyActivation = temporaryKeyBehavior.requestTemporaryKey(requestTempKeyActivation);
        assertNotNull(responseTempKeyActivation.getJwt());

        final JWSObjectJSON decodedJWSActivation = JWSObjectJSON.parse(responseTempKeyActivation.getJwt());
        assertEquals(1, decodedJWSActivation.getSignatures().size());
        assertTrue(hasValidSignature(decodedJWSActivation, JWSAlgorithm.ES384, getServerPublicEcKey(activationId)));

        final JWTClaimsSet claimsActivation = JWTClaimsSet.parse(decodedJWSActivation.getPayload().toJSONObject());
        assertEquals(defaultVersion.getApplicationKey(), claimsActivation.getClaim("applicationKey"));
        assertEquals(challengeActivation, claimsActivation.getClaim("challenge"));
        assertEquals(activationId, claimsActivation.getClaim("activationId"));
        assertNotNull(claimsActivation.getClaim("sharedSecretResponse"));
        final Object claimActivation = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponseActivation = OBJECT_MAPPER.convertValue(claimActivation, SharedSecretResponse.class);
        assertNotNull(serverResponseActivation.getEncapsulatedKeys().get(0));
    }

    @Test
    void testJwtRequestHybridValidActivationScope() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final RequestCryptogram requestCryptogram = SHARED_SECRET_HYBRID_ML_L3.generateRequestCryptogram();
        final JWSObjectJSON jws = temporaryKeyTestService.fetchTemporaryKey(requestCryptogram, defaultVersion);
        final JWTClaimsSet claims = JWTClaimsSet.parse(jws.getPayload().toJSONObject());

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        assertNotNull(serverResponse.getEncapsulatedKeys().get(0));
        assertNotNull(serverResponse.getEncapsulatedKeys().get(1));

        // extract temporary key and use it during an activation
        final ActivationContext activationContext = createActivation(defaultVersion, temporaryKeyId, requestCryptogram.getSharedSecretClientContext(), serverResponse);
        final String activationId = activationContext.activationLayer2Response.getActivationId();
        final byte[] challengeBytesActivation = KEY_GENERATOR.generateRandomBytes(18);
        final String challengeActivation = Base64.getEncoder().encodeToString(challengeBytesActivation);
        final SecretKey signingKeyActivation = deriveSharedSecret(activationContext.sharedSecretClientContext, activationContext.activationLayer2Response.getSharedSecretResponse());
        final RequestCryptogram requestCryptogramActivation = SHARED_SECRET_HYBRID_ML_L3.generateRequestCryptogram();
        final String jwtRequestActivation = temporaryKeyTestService.createJwtRequest(EncryptorScope.ACTIVATION_SCOPE, defaultVersion.getApplicationKey(), activationId, challengeActivation, signingKeyActivation, requestCryptogramActivation);
        final TemporaryPublicKeyRequest requestTempKeyActivation = new TemporaryPublicKeyRequest();
        requestTempKeyActivation.setJwt(jwtRequestActivation);
        final TemporaryPublicKeyResponse responseTempKeyActivation = temporaryKeyBehavior.requestTemporaryKey(requestTempKeyActivation);
        assertNotNull(responseTempKeyActivation.getJwt());

        final JWSObjectJSON decodedJWSActivation = JWSObjectJSON.parse(responseTempKeyActivation.getJwt());
        assertEquals(2, decodedJWSActivation.getSignatures().size());
        assertTrue(hasValidSignature(decodedJWSActivation, JWSAlgorithm.ES384, getServerPublicEcKey(activationId)));
        assertTrue(hasValidSignature(decodedJWSActivation, JWSAlgorithmMLDSA.MLDSA65, getServerPublicPqcKey(activationId)));

        final JWTClaimsSet claimsActivation = JWTClaimsSet.parse(decodedJWSActivation.getPayload().toJSONObject());
        assertEquals(defaultVersion.getApplicationKey(), claimsActivation.getClaim("applicationKey"));
        assertEquals(challengeActivation, claimsActivation.getClaim("challenge"));
        assertEquals(activationId, claimsActivation.getClaim("activationId"));
        assertNotNull(claimsActivation.getClaim("sharedSecretResponse"));
        final Object claimActivation = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponseActivation = OBJECT_MAPPER.convertValue(claimActivation, SharedSecretResponse.class);
        assertNotNull(serverResponseActivation.getEncapsulatedKeys().get(0));
        assertNotNull(serverResponseActivation.getEncapsulatedKeys().get(1));
    }

    @Test
    void testJwtRequestInvalidSignature() throws Exception {
        final ApplicationVersion defaultVersion = createApplication();
        final TemporaryPublicKeyRequest request = new TemporaryPublicKeyRequest();
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final SecretKey secretKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(KEY_GENERATOR.generateRandomBytes(8));
        final RequestCryptogram requestCryptogram = SHARED_SECRET_ECDHE.generateRequestCryptogram();
        final String jwtRequest = temporaryKeyTestService.createJwtRequest(EncryptorScope.APPLICATION_SCOPE, defaultVersion.getApplicationKey(), null, challenge, secretKey, requestCryptogram);
        request.setJwt(jwtRequest);
        assertThrows(GenericServiceException.class, () -> temporaryKeyBehavior.requestTemporaryKey(request));
    }

    private ApplicationVersion createApplication() throws GenericServiceException {
        final CreateApplicationRequest appRequest = new CreateApplicationRequest();
        appRequest.setApplicationId(UUID.randomUUID().toString());
        final CreateApplicationResponse appResponse = applicationServiceBehavior.createApplication(appRequest);
        final GetApplicationDetailRequest appDetailRequest = new GetApplicationDetailRequest();
        appDetailRequest.setApplicationId(appResponse.getApplicationId());
        final GetApplicationDetailResponse appDetailResponse = applicationDetailServiceBehavior.getApplicationDetail(appDetailRequest);
        return appDetailResponse.getVersions().get(0);
    }

    private ActivationContext createActivation(ApplicationVersion applicationVersion, String temporaryKeyId, SharedSecretClientContext clientContext, SharedSecretResponse serverResponse) throws Exception {
        final com.wultra.security.powerauth.app.server.service.model.request.v4.ActivationLayer2Request activationLayer2Request = new com.wultra.security.powerauth.app.server.service.model.request.v4.ActivationLayer2Request();
        final String applicationKey = applicationVersion.getApplicationKey();
        final String applicationSecret = applicationVersion.getApplicationSecret();
        final SecretKey temporarySharedSecret;
        final RequestCryptogram activationSharedSecretRequest;
        if (serverResponse.getEncapsulatedKeys().size() == 1) {
            final KeyPair ecDeviceKeyPair = generateEcDeviceKeypair();
            final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
            sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEncapsulatedKeys().get(0)));
            temporarySharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret((DefaultSharedSecretClientContext) clientContext, sharedSecretResponse);

            final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
            final byte[] ecPublicKeyBytes = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
            devicePublicKeys.setEcdsa(Base64.getEncoder().encodeToString(ecPublicKeyBytes));
            activationLayer2Request.setDevicePublicKeys(devicePublicKeys);
            activationSharedSecretRequest = SHARED_SECRET_ECDHE.generateRequestCryptogram();
            final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
            sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384.toString());
            sharedSecretRequest.setEncapsulationKeys(List.of(((DefaultSharedSecretRequest)activationSharedSecretRequest.getSharedSecretRequest()).getEncapsulationKeys().get(0)));
            activationLayer2Request.setSharedSecretRequest(sharedSecretRequest);

        } else {
            final KeyPair ecDeviceKeyPair = generateEcDeviceKeypair();
            final KeyPair pqcDeviceKeyPair = generatePqcDeviceKeypair();
            final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
            sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEncapsulatedKeys().get(0), serverResponse.getEncapsulatedKeys().get(1)));
            temporarySharedSecret = SHARED_SECRET_HYBRID_ML_L3.computeSharedSecret((DefaultSharedSecretClientContext) clientContext, sharedSecretResponse);

            final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
            final byte[] ecPublicKeyBytes = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecDeviceKeyPair.getPublic());
            final byte[] pqcPublicKeyBytes = KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(pqcDeviceKeyPair.getPublic());
            devicePublicKeys.setEcdsa(Base64.getEncoder().encodeToString(ecPublicKeyBytes));
            devicePublicKeys.setMldsa(Base64.getEncoder().encodeToString(pqcPublicKeyBytes));
            activationLayer2Request.setDevicePublicKeys(devicePublicKeys);
            activationSharedSecretRequest = SHARED_SECRET_HYBRID_ML_L3.generateRequestCryptogram();
            final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
            sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3.name());
            sharedSecretRequest.setEncapsulationKeys(List.of(((DefaultSharedSecretRequest)activationSharedSecretRequest.getSharedSecretRequest()).getEncapsulationKeys().get(0), ((DefaultSharedSecretRequest)activationSharedSecretRequest.getSharedSecretRequest()).getEncapsulationKeys().get(1)));
            activationLayer2Request.setSharedSecretRequest(sharedSecretRequest);
        }
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = new EncryptorFactory().getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters("4.0", applicationKey, null, temporaryKeyId),
                new AeadSecrets(temporarySharedSecret.getEncoded(), applicationSecret));
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(activationLayer2Request));

        final CreateActivationRequest activationRequest = new CreateActivationRequest();
        activationRequest.setUserId(UUID.randomUUID().toString());
        activationRequest.setApplicationKey(applicationKey);
        activationRequest.setProtocolVersion("4.0");
        activationRequest.setTemporaryKeyId(temporaryKeyId);
        activationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        activationRequest.setNonce(encryptedRequest.getNonce());
        activationRequest.setTimestamp(encryptedRequest.getTimestamp());
        final CreateActivationResponse createActivationResponse = activationServiceBehaviorV4.createActivation(activationRequest);
        final CommitActivationRequest commitRequest = new CommitActivationRequest();
        commitRequest.setActivationId(createActivationResponse.getActivationId());
        activationServiceBehavior.commitActivation(commitRequest);

        final AeadEncryptedResponse encryptedResponse = new AeadEncryptedResponse();
        encryptedResponse.setEncryptedData(createActivationResponse.getEncryptedData());
        encryptedResponse.setTimestamp(createActivationResponse.getTimestamp());
        final byte[] decryptedResponse = clientEncryptor.decryptResponse(encryptedResponse);
        final ActivationLayer2Response layer2Response = OBJECT_MAPPER.readValue(decryptedResponse, ActivationLayer2Response.class);
        return new ActivationContext(activationSharedSecretRequest.getSharedSecretClientContext(), layer2Response);
    }

    private KeyPair generateEcDeviceKeypair() throws Exception {
        return KEY_GENERATOR.generateKeyPair(EcCurve.P384);
    }

    private KeyPair generatePqcDeviceKeypair() throws Exception {
        return PQC_DSA.generateKeyPair();
    }

    private PublicKey getServerPublicEcKey(String activationId) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId).orElseThrow(() -> new IllegalStateException("Missing activation"));
        final String serverPublicKeys = activation.getServerPublicKeys();
        final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(serverPublicKeys);
        return publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> new IllegalStateException("Missing public key"));
    }

    private PublicKey getServerPublicPqcKey(String activationId) throws Exception {
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId).orElseThrow(() -> new IllegalStateException("Missing activation"));
        final String serverPublicKeys = activation.getServerPublicKeys();
        final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(serverPublicKeys);
        return publicKeyRegistry.getPublicKey(KeyType.MLDSA_65).orElseThrow(() -> new IllegalStateException("Missing public key"));
    }

    private PublicKey getMasterPublicEcKey(ApplicationVersion applicationVersion) throws GenericCryptoException, InvalidKeySpecException, CryptoProviderException {
        final String mobileSdkConfig = applicationVersion.getMobileSdkConfig();
        final SdkConfiguration sdkConfiguration = SdkConfigurationSerializer.deserialize(mobileSdkConfig);
        final String masterPublicKeyBase64 = Objects.requireNonNull(sdkConfiguration).masterPublicKeyP384();
        final byte[] masterPublicKeyBytes = Base64.getDecoder().decode(masterPublicKeyBase64);
        return KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, masterPublicKeyBytes);
    }

    private PublicKey getMasterPublicPqcKey(ApplicationVersion applicationVersion) throws GenericCryptoException {
        final String mobileSdkConfig = applicationVersion.getMobileSdkConfig();
        final SdkConfiguration sdkConfiguration = SdkConfigurationSerializer.deserialize(mobileSdkConfig);
        final String masterPublicKeyBase64 = Objects.requireNonNull(sdkConfiguration).masterPublicKeyMlDsa65();
        final byte[] masterPublicKeyBytes = Base64.getDecoder().decode(masterPublicKeyBase64);
        return KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(masterPublicKeyBytes);
    }

    private SecretKey deriveSharedSecret(SharedSecretClientContext clientContext, SharedSecretResponse serverResponse) throws Exception {
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        if (serverResponse.getEncapsulatedKeys().size() == 1) {
            sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEncapsulatedKeys().get(0)));
            return SHARED_SECRET_ECDHE.computeSharedSecret((DefaultSharedSecretClientContext) clientContext, sharedSecretResponse);
        } else {
            sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEncapsulatedKeys().get(0), serverResponse.getEncapsulatedKeys().get(1)));
            return SHARED_SECRET_HYBRID_ML_L3.computeSharedSecret((DefaultSharedSecretClientContext) clientContext, sharedSecretResponse);
        }
    }

    private boolean hasValidSignature(JWSObjectJSON jws, JWSAlgorithm algorithm, PublicKey publicKey) throws GenericCryptoException, IOException, InvalidKeyException, CryptoProviderException {
        final JWSObjectJSON.Signature jwsSignature = jws.getSignatures().stream()
                .filter(signature -> Objects.equals(signature.getHeader().getAlgorithm(), algorithm))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No signature found for algorithm: " + algorithm));

        return temporaryKeyTestService.validateJwsSignature(jws.getPayload(), jwsSignature, publicKey);
    }

    @Data
    @AllArgsConstructor
    private static class ActivationContext {

        private SharedSecretClientContext sharedSecretClientContext;
        private ActivationLayer2Response activationLayer2Response;

    }

}
