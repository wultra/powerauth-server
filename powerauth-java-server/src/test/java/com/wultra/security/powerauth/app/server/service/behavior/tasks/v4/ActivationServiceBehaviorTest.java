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
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jwt.JWTClaimsSet;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationInitServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.v4.ActivationLayer2Request;
import com.wultra.security.powerauth.app.server.service.model.response.v4.ActivationLayer2Response;
import com.wultra.security.powerauth.app.server.util.TemporaryKeyTestService;
import com.wultra.security.powerauth.client.model.entity.v4.request.DevicePublicKeys;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.response.SharedSecretResponse;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.request.CommitActivationRequest;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.ConfirmActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.request.v4.PrepareActivationRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreateActivationResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.model.response.v4.PrepareActivationResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ActivationServiceBehavior} (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
class ActivationServiceBehaviorTest {

    @Autowired
    private ActivationCreateServiceBehavior tested;

    private final ApplicationServiceBehavior applicationServiceBehavior;
    private final ApplicationDetailServiceBehavior applicationDetailServiceBehavior;
    private final ActivationServiceBehavior activationServiceBehavior;
    private final ActivationStatusServiceBehavior activationStatusServiceBehavior;
    private final ActivationInitServiceBehavior activationInitServiceBehavior;

    private final TemporaryKeyTestService temporaryKeyTestService;

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsa PQC_DSA = new MlDsa();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String VERSION = "4.0";
    private static final String USER_ID = UUID.randomUUID().toString();

    private static final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_ECDHE = SharedSecretFactory.getEcdhe();
    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_HYBRID_ML_L3 = SharedSecretFactory.getHybridMlL3();

    @Autowired
    ActivationServiceBehaviorTest(ApplicationServiceBehavior applicationServiceBehavior, ApplicationDetailServiceBehavior applicationDetailServiceBehavior, ActivationServiceBehavior activationServiceBehavior, ActivationStatusServiceBehavior activationStatusServiceBehavior, ActivationInitServiceBehavior activationInitServiceBehavior, TemporaryKeyTestService temporaryKeyTestService) {
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.applicationDetailServiceBehavior = applicationDetailServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
        this.activationStatusServiceBehavior = activationStatusServiceBehavior;
        this.activationInitServiceBehavior = activationInitServiceBehavior;
        this.temporaryKeyTestService = temporaryKeyTestService;
    }

    @Test
    void testPrepareActivationWithValidPayloadEcdhe() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Initiate activation of a user
        final InitActivationResponse initActivationResponse = initActivation(detailResponse.getApplicationId());
        final String activationId = initActivationResponse.getActivationId();

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));

        // Generate request for ECDHE
        final RequestCryptogram requestCryptogramActivation = generateRequestCryptogramEcdhe();
        final String ecPublicKey = generateEcPublicKey();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384.toString());
        sharedSecretRequest.setEcdhe(((DefaultSharedSecretRequest)requestCryptogramActivation.getSharedSecretRequest()).getEncapsulationKeys().get(0));
        final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
        devicePublicKeys.setEcdsa(ecPublicKey);

        // Request temporary key
        final RequestCryptogram requestCryptogramTemporary = generateRequestCryptogramEcdhe();
        final JWTClaimsSet claims = requestTemporaryKeyJwt(requestCryptogramTemporary, detailResponse);

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEcdhe()));
        final SecretKey temporarySharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret((DefaultSharedSecretClientContext) requestCryptogramTemporary.getSharedSecretClientContext(), sharedSecretResponse);

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setSharedSecretRequest(sharedSecretRequest);
        requestL2.setDevicePublicKeys(devicePublicKeys);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = getClientEncryptor(detailResponse, temporarySharedSecret, temporaryKeyId);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(requestL2));

        // Prepare activation
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setProtocolVersion(VERSION);
        request.setTemporaryKeyId(temporaryKeyId);
        request.setApplicationKey(applicationKey);
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setTimestamp(encryptedRequest.getTimestamp());
        final PrepareActivationResponse response = tested.prepareActivation(request);
        assertEquals(activationId, response.getActivationId());
        assertNotNull(response.getEncryptedData());

        final ActivationLayer2Response responseL2 = decryptResponse(response, clientEncryptor);
        assertNotNull(responseL2.getCtrData());
        assertNotNull(responseL2.getSharedSecretResponse());
        assertNotNull(responseL2.getSharedSecretResponse().getEcdhe());
        assertNull(responseL2.getSharedSecretResponse().getMlkem());
        assertNotNull(responseL2.getServerPublicKeys());
        assertNotNull(responseL2.getServerPublicKeys().getEcdsa());
        assertNull(responseL2.getServerPublicKeys().getMldsa());
        assertEquals(activationId, responseL2.getActivationId());

        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationId));
    }

    @Test
    void testPrepareActivationWithValidPayloadHybrid() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Initiate activation of a user
        final InitActivationResponse initActivationResponse = initActivation(detailResponse.getApplicationId());
        final String activationId = initActivationResponse.getActivationId();

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));

        // Generate request for ECDHE + MLKEM
        final RequestCryptogram requestCryptogramActivation = generateRequestCryptogramHybrid();
        final String ecPublicKey = generateEcPublicKey();
        final String mlDsaPublicKey = generateMldDsaPublicKey();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L5.toString());
        sharedSecretRequest.setEcdhe(((DefaultSharedSecretRequest)requestCryptogramActivation.getSharedSecretRequest()).getEncapsulationKeys().get(0));
        sharedSecretRequest.setMlkem(((DefaultSharedSecretRequest)requestCryptogramActivation.getSharedSecretRequest()).getEncapsulationKeys().get(1));
        final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
        devicePublicKeys.setEcdsa(ecPublicKey);
        devicePublicKeys.setMldsa(mlDsaPublicKey);

        // Request temporary key in hybrid mode
        final RequestCryptogram requestCryptogramTemporary = generateRequestCryptogramHybrid();
        final JWTClaimsSet claims = requestTemporaryKeyJwt(requestCryptogramTemporary, detailResponse);

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEcdhe(), serverResponse.getMlkem()));
        final SecretKey temporarySharedSecret = SHARED_SECRET_HYBRID_ML_L3.computeSharedSecret((DefaultSharedSecretClientContext) requestCryptogramTemporary.getSharedSecretClientContext(), sharedSecretResponse);

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setSharedSecretRequest(sharedSecretRequest);
        requestL2.setDevicePublicKeys(devicePublicKeys);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = getClientEncryptor(detailResponse, temporarySharedSecret, temporaryKeyId);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(requestL2));

        // Prepare activation
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setProtocolVersion(VERSION);
        request.setTemporaryKeyId(temporaryKeyId);
        request.setApplicationKey(applicationKey);
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setTimestamp(encryptedRequest.getTimestamp());
        final PrepareActivationResponse response = tested.prepareActivation(request);
        assertEquals(activationId, response.getActivationId());
        assertNotNull(response.getEncryptedData());

        final ActivationLayer2Response responseL2 = decryptResponse(response, clientEncryptor);
        assertNotNull(responseL2.getCtrData());
        assertNotNull(responseL2.getSharedSecretResponse());
        assertNotNull(responseL2.getSharedSecretResponse().getEcdhe());
        assertNotNull(responseL2.getSharedSecretResponse().getMlkem());
        assertNotNull(responseL2.getServerPublicKeys());
        assertNotNull(responseL2.getServerPublicKeys().getEcdsa());
        assertNotNull(responseL2.getServerPublicKeys().getMldsa());
        assertEquals(activationId, responseL2.getActivationId());

        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationId));
    }

    @Test
    void testPrepareActivationWithInvalidPayload() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Initiate activation of a user
        final InitActivationResponse initActivationResponse = initActivation(detailResponse.getApplicationId());
        final String activationId = initActivationResponse.getActivationId();

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));

        // Request temporary key
        final RequestCryptogram requestCryptogramTemporary = generateRequestCryptogramEcdhe();
        final JWTClaimsSet claims = requestTemporaryKeyJwt(requestCryptogramTemporary, detailResponse);

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEcdhe()));
        final SecretKey temporarySharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret((DefaultSharedSecretClientContext) requestCryptogramTemporary.getSharedSecretClientContext(), sharedSecretResponse);

        // Create request payload, omit device public key
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3.name());
        requestL2.setSharedSecretRequest(sharedSecretRequest);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = getClientEncryptor(detailResponse, temporarySharedSecret, temporaryKeyId);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(requestL2));

        // Prepare activation with missing devicePublicKey
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();

        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setProtocolVersion(VERSION);
        request.setApplicationKey(applicationKey);
        request.setTemporaryKeyId(temporaryKeyId);
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setTimestamp(encryptedRequest.getTimestamp());

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> tested.prepareActivation(request));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));
    }

    @Test
    void testCreateActivationWithValidPayloadEcdhe() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Generate request for ECDHE
        final RequestCryptogram requestCryptogramActivation = generateRequestCryptogramEcdhe();
        final String ecPublicKey = generateEcPublicKey();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384.toString());
        sharedSecretRequest.setEcdhe(((DefaultSharedSecretRequest)requestCryptogramActivation.getSharedSecretRequest()).getEncapsulationKeys().get(0));
        final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
        devicePublicKeys.setEcdsa(ecPublicKey);

        // Request temporary key
        final RequestCryptogram requestCryptogramTemporary = generateRequestCryptogramEcdhe();
        final JWTClaimsSet claims = requestTemporaryKeyJwt(requestCryptogramTemporary, detailResponse);

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEcdhe()));
        final SecretKey temporarySharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret((DefaultSharedSecretClientContext) requestCryptogramTemporary.getSharedSecretClientContext(), sharedSecretResponse);

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setSharedSecretRequest(sharedSecretRequest);
        requestL2.setDevicePublicKeys(devicePublicKeys);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = getClientEncryptor(detailResponse, temporarySharedSecret, temporaryKeyId);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(requestL2));

        // Create activation
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final CreateActivationRequest request = new CreateActivationRequest();
        request.setApplicationKey(applicationKey);
        request.setUserId(USER_ID);
        request.setProtocolVersion(VERSION);
        request.setTemporaryKeyId(temporaryKeyId);
        request.setNonce(encryptedRequest.getNonce());
        request.setTimestamp(encryptedRequest.getTimestamp());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        final CreateActivationResponse response = tested.createActivation(request);
        assertNotNull(response.getActivationId());
        assertNotNull(response.getEncryptedData());

        final ActivationLayer2Response responseL2 = decryptResponse(response, clientEncryptor);
        assertNotNull(responseL2.getCtrData());
        assertNotNull(responseL2.getSharedSecretResponse());
        assertNotNull(responseL2.getSharedSecretResponse().getEcdhe());
        assertNull(responseL2.getSharedSecretResponse().getMlkem());
        assertNotNull(responseL2.getServerPublicKeys());
        assertNotNull(responseL2.getServerPublicKeys().getEcdsa());
        assertNull(responseL2.getServerPublicKeys().getMldsa());
        assertEquals(response.getActivationId(), responseL2.getActivationId());

        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(response.getActivationId()));
    }

    @Test
    void testCreateActivationWithValidPayloadHybrid() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Generate request for ECDHE + MLKEM
        final RequestCryptogram requestCryptogramActivation = generateRequestCryptogramHybrid();
        final String ecPublicKey = generateEcPublicKey();
        final String mlDsaPublicKey = generateMldDsaPublicKey();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3.toString());
        sharedSecretRequest.setEcdhe(((DefaultSharedSecretRequest)requestCryptogramActivation.getSharedSecretRequest()).getEncapsulationKeys().get(0));
        sharedSecretRequest.setMlkem(((DefaultSharedSecretRequest)requestCryptogramActivation.getSharedSecretRequest()).getEncapsulationKeys().get(1));
        final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
        devicePublicKeys.setEcdsa(ecPublicKey);
        devicePublicKeys.setMldsa(mlDsaPublicKey);

        // Request temporary key in hybrid mode
        final RequestCryptogram requestCryptogramTemporary = generateRequestCryptogramHybrid();
        final JWTClaimsSet claims = requestTemporaryKeyJwt(requestCryptogramTemporary, detailResponse);

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEcdhe(), serverResponse.getMlkem()));
        final SecretKey temporarySharedSecret = SHARED_SECRET_HYBRID_ML_L3.computeSharedSecret((DefaultSharedSecretClientContext) requestCryptogramTemporary.getSharedSecretClientContext(), sharedSecretResponse);

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setSharedSecretRequest(sharedSecretRequest);
        requestL2.setDevicePublicKeys(devicePublicKeys);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = getClientEncryptor(detailResponse, temporarySharedSecret, temporaryKeyId);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(requestL2));

        // Create activation
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final CreateActivationRequest request = new CreateActivationRequest();
        request.setApplicationKey(applicationKey);
        request.setUserId(USER_ID);
        request.setProtocolVersion(VERSION);
        request.setTemporaryKeyId(temporaryKeyId);
        request.setNonce(encryptedRequest.getNonce());
        request.setTimestamp(encryptedRequest.getTimestamp());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        final CreateActivationResponse response = tested.createActivation(request);
        assertNotNull(response.getActivationId());
        assertNotNull(response.getEncryptedData());

        final ActivationLayer2Response responseL2 = decryptResponse(response, clientEncryptor);
        assertNotNull(responseL2.getCtrData());
        assertNotNull(responseL2.getSharedSecretResponse());
        assertNotNull(responseL2.getSharedSecretResponse().getEcdhe());
        assertNotNull(responseL2.getSharedSecretResponse().getMlkem());
        assertNotNull(responseL2.getServerPublicKeys());
        assertNotNull(responseL2.getServerPublicKeys().getEcdsa());
        assertNotNull(responseL2.getServerPublicKeys().getMldsa());
        assertEquals(response.getActivationId(), responseL2.getActivationId());

        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(response.getActivationId()));
    }

    @Test
    void testCreateActivationWithInvalidPayload() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Request temporary key
        final RequestCryptogram requestCryptogramTemporary = generateRequestCryptogramEcdhe();
        final JWTClaimsSet claims = requestTemporaryKeyJwt(requestCryptogramTemporary, detailResponse);

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEcdhe()));
        final SecretKey temporarySharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret((DefaultSharedSecretClientContext) requestCryptogramTemporary.getSharedSecretClientContext(), sharedSecretResponse);

        // Create request payload, omit device public key
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3.name());
        requestL2.setSharedSecretRequest(sharedSecretRequest);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = getClientEncryptor(detailResponse, temporarySharedSecret, temporaryKeyId);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(requestL2));

        // Create activation with missing devicePublicKey
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> {
            final CreateActivationRequest request = new CreateActivationRequest();
            request.setApplicationKey(applicationKey);
            request.setUserId(USER_ID);
            request.setProtocolVersion(VERSION);
            request.setTemporaryKeyId(temporaryKeyId);
            request.setNonce(encryptedRequest.getNonce());
            request.setTimestamp(encryptedRequest.getTimestamp());
            request.setEncryptedData(encryptedRequest.getEncryptedData());
            tested.createActivation(request);
        });

        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void testPrepareActivationWithCommitOnKeyExchange() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.NONE, null, null);
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
    }

    @Test
    void testPrepareActivationTransferTypeMove() throws Exception {
        // parent activation
        final GetApplicationDetailResponse detailResponse1 = createApplication();
        final PrepareActivationResponse activationResponse1 = prepareActivation(detailResponse1, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.NONE, null, null);
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse1.getActivationId()));

        final String parentActivationId = activationResponse1.getActivationId();

        // child activation
        final GetApplicationDetailResponse detailResponse2 = createApplication();
        final InitActivationResponse initActivationResponse2 = initChildActivation(detailResponse2.getApplicationId(), parentActivationId);
        final PrepareActivationResponse activationResponse2 = prepareActivation(detailResponse2, initActivationResponse2, null);
        final GetActivationStatusResponse activationStatusResponse2 = getActivationStatusResponse(activationResponse2.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, activationStatusResponse2.getActivationStatus());
        assertEquals(parentActivationId, activationStatusResponse2.getParentActivationId());
        assertEquals(ActivationTransferType.MOVE, activationStatusResponse2.getTransferType());

        // parent activation should be removed
        assertEquals(ActivationStatus.REMOVED, getActivationStatus(activationResponse1.getActivationId()));
    }

    @Test
    void testPrepareActivationWithCommitOnKeyExchangeWithOtpValid() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.NONE, "1234", "1234");
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
    }

    @Test
    void testPrepareActivationWithCommitOnKeyExchangeWithOtpInvalid() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        assertThrows(GenericServiceException.class, () ->
                prepareActivation(detailResponse, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.NONE, "1234", "4321"));
    }

    @Test
    void testPrepareActivationWithCommitOnKeyExchangeWithOtpMissing() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        assertThrows(GenericServiceException.class, () ->
                prepareActivation(detailResponse, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.NONE, "1234", null));
    }

    @Test
    void testPrepareActivationWithCommitOnKeyExchangeWithOtpEmpty() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        assertThrows(GenericServiceException.class, () ->
                prepareActivation(detailResponse, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.NONE, "1234", ""));
    }

    @Test
    void testPrepareActivationWithCommitAfterKeyExchange() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, null, null);
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationResponse.getActivationId()));
        commitActivation(activationResponse.getActivationId(), null);
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
    }

    @Test
    void testPrepareActivationWithCommitAfterKeyExchangeWithOtp() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, "1234", null);
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationResponse.getActivationId()));
        commitActivation(activationResponse.getActivationId(), "1234");
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
    }

    @Test
    void testPrepareActivationWithCommitAfterKeyExchangeWithOtpInvalid() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, "1234", null);
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationResponse.getActivationId()));
        assertThrows(GenericServiceException.class, () ->
            commitActivation(activationResponse.getActivationId(), "4321"));
    }

    @Test
    void testPrepareActivationWithCommitAfterKeyExchangeWithOtpEmpty() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, "1234", null);
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationResponse.getActivationId()));
        assertThrows(GenericServiceException.class, () ->
                commitActivation(activationResponse.getActivationId(), ""));
    }

    @Test
    void testPrepareActivationWithCommitAfterKeyExchangeWithOtpMissing() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, "1234", null);
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationResponse.getActivationId()));
        assertThrows(GenericServiceException.class, () ->
                commitActivation(activationResponse.getActivationId(), null));
    }

    @Test
    void testPrepareActivationWithOtpValidOnKeyExchange() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, null, ActivationOtpValidation.ON_KEY_EXCHANGE, "1234", "1234");
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
    }

    @Test
    void testPrepareActivationWithOtpValidOnCommit() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        PrepareActivationResponse activationResponse = prepareActivation(detailResponse, null, ActivationOtpValidation.ON_COMMIT, "1234", null);
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationResponse.getActivationId()));
        commitActivation(activationResponse.getActivationId(), "1234");
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
    }

    @Test
    void testPrepareActivationWithCommitAfterKeyExchangeWithConfirmation() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, null, null);
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationResponse.getActivationId()));
        assertTrue(isConfirmationPending(activationResponse.getActivationId()));
        confirmActivation(activationResponse.getActivationId());
        assertFalse(isConfirmationPending(activationResponse.getActivationId()));
        commitActivation(activationResponse.getActivationId(), null);
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
        assertFalse(isConfirmationPending(activationResponse.getActivationId()));
    }

    @Test
    void testPrepareActivationWithOtpMissing() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        assertThrows(GenericServiceException.class, () ->
                prepareActivation(detailResponse, null, ActivationOtpValidation.ON_KEY_EXCHANGE, null, null));
    }

    @Test
    void testPrepareActivationWithOtpEmpty() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        assertThrows(GenericServiceException.class, () ->
                prepareActivation(detailResponse, null, ActivationOtpValidation.ON_KEY_EXCHANGE, "", ""));
    }

    @Test
    void testPrepareActivationWithOtpPresentWrongStage() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        assertThrows(GenericServiceException.class, () ->
                prepareActivation(detailResponse, null, ActivationOtpValidation.ON_COMMIT, "1234", "1234"));
    }

    @Test
    void testPrepareActivationInvalidCombinationOtpValidationCommitPhase() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Test exception for invalid parameters
        assertThrows(GenericServiceException.class, () ->
                prepareActivation(detailResponse, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.ON_COMMIT, "1234", null));
    }

    private RequestCryptogram generateRequestCryptogramEcdhe() throws Exception {
        return SHARED_SECRET_ECDHE.generateRequestCryptogram();
    }

    private RequestCryptogram generateRequestCryptogramHybrid() throws Exception {
        return SHARED_SECRET_HYBRID_ML_L3.generateRequestCryptogram();
    }

    private String generateEcPublicKey() throws Exception {
        final KeyPair keyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P384);
        final byte[] publicKeyBytes = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private String generateMldDsaPublicKey() throws Exception {
        final KeyPair keyPair = PQC_DSA.generateKeyPair();
        final byte[] publicKeyBytes = KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private void confirmActivation(String activationId) throws Exception {
        final ConfirmActivationRequest confirmActivationRequest = new ConfirmActivationRequest();
        confirmActivationRequest.setActivationId(activationId);
        activationServiceBehavior.confirmActivation(confirmActivationRequest);
    }

    private void commitActivation(String activationId, String otp) throws Exception {
        final CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationId(activationId);
        commitActivationRequest.setActivationOtp(otp);
        activationServiceBehavior.commitActivation(commitActivationRequest);
    }

    private ActivationLayer2Response decryptResponse(CreateActivationResponse response, ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor) throws Exception {
        final AeadEncryptedResponse encryptedResponse = new AeadEncryptedResponse(response.getEncryptedData(), response.getTimestamp());
        final byte[] decryptedActivationResponsePayload = clientEncryptor.decryptResponse(encryptedResponse);
        return OBJECT_MAPPER.readValue(decryptedActivationResponsePayload, ActivationLayer2Response.class);
    }

    private ActivationLayer2Response decryptResponse(PrepareActivationResponse response, ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor) throws Exception {
        final AeadEncryptedResponse encryptedResponse = new AeadEncryptedResponse(response.getEncryptedData(), response.getTimestamp());
        final byte[] decryptedActivationResponsePayload = clientEncryptor.decryptResponse(encryptedResponse);
        return OBJECT_MAPPER.readValue(decryptedActivationResponsePayload, ActivationLayer2Response.class);
    }

    private ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> getClientEncryptor(GetApplicationDetailResponse applicationDetail,
                                                    SecretKey temporarySharedSecret, String temporaryKeyId) throws Exception {

        // Set parameters
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final String applicationSecret = applicationDetail.getVersions().get(0).getApplicationSecret();

        // Encrypt payload
        return ENCRYPTOR_FACTORY.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(VERSION, applicationKey, null, temporaryKeyId),
                new AeadSecrets(temporarySharedSecret.getEncoded(), applicationSecret));
    }

    private InitActivationResponse initActivation(String applicationId) throws Exception {
       return initActivation(applicationId, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, null);
    }

    private InitActivationResponse initActivation(String applicationId, CommitPhase commitPhase, ActivationOtpValidation activationOtpValidation, String otp) throws Exception {
        final InitActivationRequest request = new InitActivationRequest();
        request.setProtocol(ActivationProtocol.POWERAUTH);
        request.setApplicationId(applicationId);
        request.setUserId(USER_ID);
        request.setCommitPhase(commitPhase);
        request.setActivationOtpValidation(activationOtpValidation);
        request.setActivationOtp(otp);
        return activationInitServiceBehavior.initActivation(request);
    }

    private InitActivationResponse initChildActivation(String applicationId, String parentActivationId) throws Exception {
        final InitActivationRequest request = new InitActivationRequest();
        request.setProtocol(ActivationProtocol.POWERAUTH);
        request.setApplicationId(applicationId);
        request.setUserId(USER_ID);
        request.setCommitPhase(CommitPhase.ON_KEY_EXCHANGE);
        request.setParentActivationId(parentActivationId);
        request.setTransferType(ActivationTransferType.MOVE);
        return activationInitServiceBehavior.initActivation(request);
    }

    private PrepareActivationResponse prepareActivation(GetApplicationDetailResponse applicationDetail, CommitPhase commitPhase, ActivationOtpValidation otpValidation, String otp, String otpToUse) throws Exception {
        final InitActivationResponse initActivationResponse = initActivation(applicationDetail.getApplicationId(), commitPhase, otpValidation, otp);
        return prepareActivation(applicationDetail, initActivationResponse, otpToUse);
    }

    private PrepareActivationResponse prepareActivation(GetApplicationDetailResponse applicationDetail, InitActivationResponse initActivationResponse, String otpToUse) throws Exception {
        final String activationId = initActivationResponse.getActivationId();

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));

        // Generate request for ECDHE
        final RequestCryptogram requestCryptogramActivation = generateRequestCryptogramEcdhe();
        final String ecPublicKey = generateEcPublicKey();
        final SharedSecretRequest sharedSecretRequest = new SharedSecretRequest();
        sharedSecretRequest.setAlgorithm(SharedSecretAlgorithm.EC_P384.toString());
        sharedSecretRequest.setEcdhe(((DefaultSharedSecretRequest)requestCryptogramActivation.getSharedSecretRequest()).getEncapsulationKeys().get(0));
        final DevicePublicKeys devicePublicKeys = new DevicePublicKeys();
        devicePublicKeys.setEcdsa(ecPublicKey);

        // Request temporary key
        final RequestCryptogram requestCryptogramTemporary = generateRequestCryptogramEcdhe();
        final JWTClaimsSet claims = requestTemporaryKeyJwt(requestCryptogramTemporary, applicationDetail);

        final String temporaryKeyId = claims.getSubject();
        final Object claim = claims.getClaim("sharedSecretResponse");
        final SharedSecretResponse serverResponse = OBJECT_MAPPER.convertValue(claim, SharedSecretResponse.class);
        final DefaultSharedSecretResponse sharedSecretResponse = new DefaultSharedSecretResponse();
        sharedSecretResponse.setEncapsulatedKeys(List.of(serverResponse.getEcdhe()));
        final SecretKey temporarySharedSecret = SHARED_SECRET_ECDHE.computeSharedSecret((DefaultSharedSecretClientContext) requestCryptogramTemporary.getSharedSecretClientContext(), sharedSecretResponse);

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setSharedSecretRequest(sharedSecretRequest);
        requestL2.setDevicePublicKeys(devicePublicKeys);
        requestL2.setActivationOtp(otpToUse);
        final ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> clientEncryptor = getClientEncryptor(applicationDetail, temporarySharedSecret, temporaryKeyId);
        final AeadEncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(OBJECT_MAPPER.writeValueAsBytes(requestL2));

        // Prepare activation
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setProtocolVersion(VERSION);
        request.setApplicationKey(applicationKey);
        request.setTemporaryKeyId(temporaryKeyId);
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setTimestamp(encryptedRequest.getTimestamp());
        return tested.prepareActivation(request);
    }

    private GetApplicationDetailResponse createApplication() throws Exception {
        final String testId = UUID.randomUUID().toString();
        final CreateApplicationRequest createApplicationRequest = new CreateApplicationRequest();
        createApplicationRequest.setApplicationId(testId);
        final CreateApplicationResponse createApplicationResponse = applicationServiceBehavior.createApplication(createApplicationRequest);

        final GetApplicationDetailRequest detailRequest = new GetApplicationDetailRequest();
        detailRequest.setApplicationId(createApplicationResponse.getApplicationId());
        return applicationDetailServiceBehavior.getApplicationDetail(detailRequest);
    }

    private ActivationStatus getActivationStatus(final String activationId) throws Exception {
        return getActivationStatusResponse(activationId).getActivationStatus();
    }

    private GetActivationStatusResponse getActivationStatusResponse(final String activationId) throws Exception {
        final GetActivationStatusRequest statusRequest = new GetActivationStatusRequest();
        statusRequest.setActivationId(activationId);
        return activationStatusServiceBehavior.getActivationStatus(statusRequest);
    }

    private boolean isConfirmationPending(String activationId) throws Exception {
        final GetActivationStatusRequest statusRequest = new GetActivationStatusRequest();
        statusRequest.setActivationId(activationId);
        final GetActivationStatusResponse statusResponse = activationStatusServiceBehavior.getActivationStatus(statusRequest);
        return statusResponse.isConfirmationPending();
    }

    private JWTClaimsSet requestTemporaryKeyJwt(final RequestCryptogram requestCryptogram, final GetApplicationDetailResponse detailResponse) throws Exception {
        final JWSObjectJSON jws = temporaryKeyTestService.fetchTemporaryKey(requestCryptogram, detailResponse.getVersions().get(0));
        return JWTClaimsSet.parse(jws.getPayload().toJSONObject());
    }

}
