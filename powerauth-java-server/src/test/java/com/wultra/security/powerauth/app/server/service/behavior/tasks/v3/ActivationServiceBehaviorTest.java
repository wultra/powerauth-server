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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import tools.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationInitServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.v3.ActivationLayer2Request;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.request.CommitActivationRequest;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.v3.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.request.v3.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.request.v3.PrepareActivationRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.client.model.response.v3.CreateActivationResponse;
import com.wultra.security.powerauth.client.model.response.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.client.model.response.v3.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.model.response.v3.PrepareActivationResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ClientEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for {@link ActivationServiceBehavior} (V3).
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
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
    private final ObjectMapper objectMapper;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final String version = "3.2";
    private final String userId = UUID.randomUUID().toString();

    @Autowired
    ActivationServiceBehaviorTest(ApplicationServiceBehavior applicationServiceBehavior, ApplicationDetailServiceBehavior applicationDetailServiceBehavior, ActivationServiceBehavior activationServiceBehavior, ActivationStatusServiceBehavior activationStatusServiceBehavior, ActivationInitServiceBehavior activationInitServiceBehavior, ObjectMapper objectMapper) {
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.applicationDetailServiceBehavior = applicationDetailServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
        this.activationStatusServiceBehavior = activationStatusServiceBehavior;
        this.activationInitServiceBehavior = activationInitServiceBehavior;
        this.objectMapper = objectMapper;
    }

    @Test
    void testPrepareActivationWithValidPayload() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Initiate activation of a user
        final InitActivationResponse initActivationResponse = initActivation(detailResponse.getApplicationId());
        final String activationId = initActivationResponse.getActivationId();

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));

        // Generate public key for a client device
        final String publicKey = generatePublicKey();

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setDevicePublicKey(publicKey);
        final EciesEncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setProtocolVersion(version);
        request.setApplicationKey(applicationKey);
        request.setMac(encryptedRequest.getMac());
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        request.setTimestamp(encryptedRequest.getTimestamp());
        tested.prepareActivation(request);

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

        // Create request payload, omit device public key
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        final EciesEncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation with missing devicePublicKey
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();

        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setProtocolVersion(version);
        request.setApplicationKey(applicationKey);
        request.setMac(encryptedRequest.getMac());
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        request.setTimestamp(encryptedRequest.getTimestamp());

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> tested.prepareActivation(request));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));
    }

    @Test
    void testCreateActivationWithValidPayload() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Generate public key for a client device
        final String publicKey = generatePublicKey();

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setDevicePublicKey(publicKey);
        final EciesEncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Create activation
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final CreateActivationRequest request = new CreateActivationRequest();
        request.setApplicationKey(applicationKey);
        request.setUserId(userId);
        request.setProtocolVersion(version);
        request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        request.setNonce(encryptedRequest.getNonce());
        request.setTimestamp(encryptedRequest.getTimestamp());
        request.setMac(encryptedRequest.getMac());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        final CreateActivationResponse response = tested.createActivation(request);

        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(response.getActivationId()));
    }

    @Test
    void testCreateActivationWithInvalidPayload() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Create request payload, omit device public key
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        final EciesEncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Create activation with missing devicePublicKey
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> {
            final CreateActivationRequest request = new CreateActivationRequest();
            request.setApplicationKey(applicationKey);
            request.setUserId(userId);
            request.setProtocolVersion(version);
            request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
            request.setNonce(encryptedRequest.getNonce());
            request.setTimestamp(encryptedRequest.getTimestamp());
            request.setMac(encryptedRequest.getMac());
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

    private String generatePublicKey() throws Exception {
        final KeyGenerator keyGenerator = new KeyGenerator();
        final KeyPair keyPair = keyGenerator.generateKeyPair(EcCurve.P256);
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(EcCurve.P256, keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private void commitActivation(String activationId, String otp) throws Exception {
        final CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationId(activationId);
        commitActivationRequest.setActivationOtp(otp);
        activationServiceBehavior.commitActivation(commitActivationRequest);
    }

    private EciesEncryptedRequest buildPrepareActivationPayload(
            final ActivationLayer2Request requestL2,
            final GetApplicationDetailResponse applicationDetail) throws Exception {

        // Set parameters
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode(applicationDetail.getMasterPublicKey()));
        final String applicationSecret = applicationDetail.getVersions().get(0).getApplicationSecret();

        // Encrypt payload
        final ClientEncryptor<EciesEncryptedRequest, EciesEncryptedResponse> clientEncryptor = new EncryptorFactory().getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(version, applicationKey, null, null),
                new ClientEciesSecrets(masterPublicKey, applicationSecret));
        return clientEncryptor.encryptRequest(objectMapper.writeValueAsBytes(requestL2));
    }

    private InitActivationResponse initActivation(String applicationId) throws Exception {
       return initActivation(applicationId, CommitPhase.ON_COMMIT, ActivationOtpValidation.NONE, null);
    }

    private InitActivationResponse initActivation(String applicationId, CommitPhase commitPhase, ActivationOtpValidation activationOtpValidation, String otp) throws Exception {
        final InitActivationRequest request = new InitActivationRequest();
        request.setProtocol(ActivationProtocol.POWERAUTH);
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setCommitPhase(commitPhase);
        request.setActivationOtpValidation(activationOtpValidation);
        request.setActivationOtp(otp);
        return activationInitServiceBehavior.initActivation(request);
    }

    private InitActivationResponse initChildActivation(String applicationId, String parentActivationId) throws Exception {
        final InitActivationRequest request = new InitActivationRequest();
        request.setProtocol(ActivationProtocol.POWERAUTH);
        request.setApplicationId(applicationId);
        request.setUserId(userId);
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

        // Generate public key for a client device
        final String publicKey = generatePublicKey();

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setDevicePublicKey(publicKey);
        requestL2.setActivationOtp(otpToUse);
        final EciesEncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, applicationDetail);

        // Prepare activation
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setProtocolVersion(version);
        request.setApplicationKey(applicationKey);
        request.setMac(encryptedRequest.getMac());
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
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
}
