/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.app.server.service.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ActivationServiceBehavior}.
 *
 * @author Jan Pesek, janpesek@outlook.com
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */

@SpringBootTest
@Transactional
@ActiveProfiles("test")
class ActivationServiceBehaviorTest {

    @Autowired
    private ActivationServiceBehavior tested;

    private final ApplicationServiceBehavior applicationServiceBehavior;
    private final RecoveryServiceBehavior recoveryServiceBehavior;
    private final ActivationServiceBehavior activationServiceBehavior;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String version = "3.2";
    private final String userId = UUID.randomUUID().toString();

    @Autowired
    public ActivationServiceBehaviorTest(ApplicationServiceBehavior applicationServiceBehavior, RecoveryServiceBehavior recoveryServiceBehavior, ActivationServiceBehavior activationServiceBehavior) {
        this.applicationServiceBehavior = applicationServiceBehavior;
        this.recoveryServiceBehavior = recoveryServiceBehavior;
        this.activationServiceBehavior = activationServiceBehavior;
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
        final EncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setGenerateRecoveryCodes(false);
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
        final EncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation with missing devicePublicKey
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();

        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setGenerateRecoveryCodes(false);
        request.setProtocolVersion(version);
        request.setApplicationKey(applicationKey);
        request.setMac(encryptedRequest.getMac());
        request.setNonce(encryptedRequest.getNonce());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        request.setTimestamp(encryptedRequest.getTimestamp());

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> {
            tested.prepareActivation(request);
        });
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
        final EncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Create activation
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final CreateActivationRequest request = new CreateActivationRequest();
        request.setApplicationKey(applicationKey);
        request.setUserId(userId);
        request.setProtocolVersion(version);
        request.setGenerateRecoveryCodes(false);
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
        final EncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, detailResponse);

        // Create activation with missing devicePublicKey
        final String applicationKey = detailResponse.getVersions().get(0).getApplicationKey();
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> {
            final CreateActivationRequest request = new CreateActivationRequest();
            request.setApplicationKey(applicationKey);
            request.setUserId(userId);
            request.setProtocolVersion(version);
            request.setGenerateRecoveryCodes(false);
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
    void testCreateActivationUsingRecoveryCode() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Create activation with recovery code
        final ActivationLayer2Response responsePayload = createActivationAndGetResponsePayload(detailResponse);

        // Generate public key for a new client device
        final String publicKeyBytes = generatePublicKey();

        // Build createActivation request payload
        final ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();
        activationLayer2Request.setDevicePublicKey(publicKeyBytes);

        // Create activation using recovery code
        final String recoveryCode = responsePayload.getActivationRecovery().getRecoveryCode();
        final String puk = responsePayload.getActivationRecovery().getPuk();
        final RecoveryCodeActivationRequest recoveryCodeActivationRequest =
                buildRecoveryCodeActivationRequest(recoveryCode, puk, activationLayer2Request, detailResponse);

        // Create activation
        final RecoveryCodeActivationResponse recoveryCodeActivationResponse = tested.createActivationUsingRecoveryCode(recoveryCodeActivationRequest);

        // Check new activation was created
        assertNotEquals(responsePayload.getActivationId(), recoveryCodeActivationResponse.getActivationId());

        // Check used recovery code is revoked
        final RecoveryCodeStatus recoveryCodeStatus = getRecoveryCodeStatus(userId, responsePayload.getActivationId(), detailResponse.getApplicationId());
        assertEquals(RecoveryCodeStatus.REVOKED, recoveryCodeStatus);
    }

    @Test
    void testCreateActivationUsingRecoveryCodeWithInvalidPayload() throws Exception {
        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Create activation with recovery code
        final ActivationLayer2Response responsePayload = createActivationAndGetResponsePayload(detailResponse);

        // Build createActivation request payload, now omit device public key
        final ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();

        // Create activation using recovery code
        final RecoveryCodeActivationRequest recoveryCodeActivationRequest = buildRecoveryCodeActivationRequest(responsePayload.getActivationRecovery().getRecoveryCode(),
                responsePayload.getActivationRecovery().getPuk(), activationLayer2Request, detailResponse);

        // Create activation with missing devicePublicKey
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () ->
                tested.createActivationUsingRecoveryCode(recoveryCodeActivationRequest));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void testPrepareActivationWithCommitOnKeyExchange() throws Exception {
        final GetApplicationDetailResponse detailResponse = createApplication();
        final PrepareActivationResponse activationResponse = prepareActivation(detailResponse, CommitPhase.ON_KEY_EXCHANGE, ActivationOtpValidation.NONE, null, null);
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationResponse.getActivationId()));
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

    private ActivationLayer2Response createActivationAndGetResponsePayload(GetApplicationDetailResponse applicationDetail) throws Exception {
        final String applicationId = applicationDetail.getApplicationId();

        // Set recovery config
        enableRecoveryCodesGeneration(applicationId);
        assertTrue(isRecoveryCodeGenerationEnabled(applicationId));

        // Generate public key for a client device
        final String publicKeyBytes = generatePublicKey();

        // Build createActivation request payload
        final ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();
        activationLayer2Request.setDevicePublicKey(publicKeyBytes);

        // Encrypt createActivation request payload
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(applicationDetail.getMasterPublicKey()));
        final String applicationSecret = applicationDetail.getVersions().get(0).getApplicationSecret();

        final ClientEncryptor clientEncryptor = new EncryptorFactory().getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(version, applicationKey, null, null),
                new ClientEncryptorSecrets(masterPublicKey, applicationSecret));
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(objectMapper.writeValueAsBytes(activationLayer2Request));

        // Create activation
        final CreateActivationRequest request = new CreateActivationRequest();
        request.setApplicationKey(applicationKey);
        request.setUserId(userId);
        request.setProtocolVersion(version);
        request.setGenerateRecoveryCodes(true);
        request.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        request.setNonce(encryptedRequest.getNonce());
        request.setTimestamp(encryptedRequest.getTimestamp());
        request.setMac(encryptedRequest.getMac());
        request.setEncryptedData(encryptedRequest.getEncryptedData());
        final CreateActivationResponse createActivationResponse = tested.createActivation(request);

        final String activationId = createActivationResponse.getActivationId();
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationId));

        // Commit activation
        commitActivation(activationId, null);
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationId));

        // Decrypt createActivation response payload
        final ActivationLayer2Response responsePayload = decryptPayload(createActivationResponse, clientEncryptor);

        // Check recovery was created
        assertNotNull(responsePayload.getActivationRecovery());

        // Check recovery code is active
        assertEquals(RecoveryCodeStatus.ACTIVE, getRecoveryCodeStatus(userId, activationId, applicationDetail.getApplicationId()));

        return responsePayload;
    }

    private void enableRecoveryCodesGeneration(String applicationId) throws Exception {
        final UpdateRecoveryConfigRequest updateRecoveryConfigRequest = new UpdateRecoveryConfigRequest();
        updateRecoveryConfigRequest.setApplicationId(applicationId);
        updateRecoveryConfigRequest.setActivationRecoveryEnabled(true);
        recoveryServiceBehavior.updateRecoveryConfig(updateRecoveryConfigRequest);
    }

    private boolean isRecoveryCodeGenerationEnabled(String applicationId) throws Exception {
        final GetRecoveryConfigRequest getRecoveryConfigRequest = new GetRecoveryConfigRequest();
        getRecoveryConfigRequest.setApplicationId(applicationId);
        final GetRecoveryConfigResponse recoveryConfigResponse = recoveryServiceBehavior.getRecoveryConfig(getRecoveryConfigRequest);
        return recoveryConfigResponse.isActivationRecoveryEnabled();
    }

    private String generatePublicKey() throws Exception {
        final KeyGenerator keyGenerator = new KeyGenerator();
        final KeyPair keyPair = keyGenerator.generateKeyPair();
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private void commitActivation(String activationId, String otp) throws Exception {
        final CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationId(activationId);
        commitActivationRequest.setActivationOtp(otp);
        activationServiceBehavior.commitActivation(commitActivationRequest);
    }

    private ActivationLayer2Response decryptPayload(CreateActivationResponse response, ClientEncryptor clientEncryptor) throws Exception {
        final EncryptedResponse encryptedResponse = new EncryptedResponse(response.getEncryptedData(), response.getMac(), response.getNonce(), response.getTimestamp());
        final byte[] decryptedActivationResponsePayload = clientEncryptor.decryptResponse(encryptedResponse);
        return objectMapper.readValue(decryptedActivationResponsePayload, ActivationLayer2Response.class);
    }

    private RecoveryCodeStatus getRecoveryCodeStatus(String userId, String activationId, String applicationId) throws Exception {
        final LookupRecoveryCodesRequest lookupRecoveryCodesRequest = new LookupRecoveryCodesRequest();
        lookupRecoveryCodesRequest.setUserId(userId);
        lookupRecoveryCodesRequest.setActivationId(activationId);
        lookupRecoveryCodesRequest.setApplicationId(applicationId);
        final LookupRecoveryCodesResponse lookupRecoveryCodesResponse = recoveryServiceBehavior.lookupRecoveryCodes(lookupRecoveryCodesRequest);
        return lookupRecoveryCodesResponse.getRecoveryCodes().get(0).getStatus();
    }

    private EncryptedRequest buildPrepareActivationPayload(
            final ActivationLayer2Request requestL2,
            final GetApplicationDetailResponse applicationDetail) throws Exception {

        // Set parameters
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(applicationDetail.getMasterPublicKey()));
        final String applicationSecret = applicationDetail.getVersions().get(0).getApplicationSecret();

        // Encrypt payload
        final ClientEncryptor clientEncryptor = new EncryptorFactory().getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(version, applicationKey, null, null),
                new ClientEncryptorSecrets(masterPublicKey, applicationSecret));
        return clientEncryptor.encryptRequest(objectMapper.writeValueAsBytes(requestL2));
    }

    private RecoveryCodeActivationRequest buildRecoveryCodeActivationRequest(String recoveryCode, String puk, ActivationLayer2Request payload, GetApplicationDetailResponse detailResponse) throws Exception {
        final EncryptedRequest encryptedRequest = buildPrepareActivationPayload(payload, detailResponse);

        final RecoveryCodeActivationRequest recoveryCodeActivationRequest = new RecoveryCodeActivationRequest();
        recoveryCodeActivationRequest.setRecoveryCode(recoveryCode);
        recoveryCodeActivationRequest.setPuk(puk);
        recoveryCodeActivationRequest.setApplicationKey(detailResponse.getVersions().get(0).getApplicationKey());
        recoveryCodeActivationRequest.setProtocolVersion(version);
        recoveryCodeActivationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        recoveryCodeActivationRequest.setMac(encryptedRequest.getMac());
        recoveryCodeActivationRequest.setNonce(encryptedRequest.getNonce());
        recoveryCodeActivationRequest.setTimestamp(encryptedRequest.getTimestamp());
        recoveryCodeActivationRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());

        return recoveryCodeActivationRequest;
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
        return tested.initActivation(request);
    }

    private PrepareActivationResponse prepareActivation(GetApplicationDetailResponse applicationDetail, CommitPhase commitPhase, ActivationOtpValidation otpValidation, String otp, String otpToUse) throws Exception {
        // Initiate activation of a user
        final InitActivationResponse initActivationResponse = initActivation(applicationDetail.getApplicationId(), commitPhase, otpValidation, otp);

        final String activationId = initActivationResponse.getActivationId();

        assertEquals(ActivationStatus.CREATED, getActivationStatus(activationId));

        // Generate public key for a client device
        final String publicKey = generatePublicKey();

        // Create request payload
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setDevicePublicKey(publicKey);
        requestL2.setActivationOtp(otpToUse);
        final EncryptedRequest encryptedRequest = buildPrepareActivationPayload(requestL2, applicationDetail);

        // Prepare activation
        final String activationCode = initActivationResponse.getActivationCode();
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setGenerateRecoveryCodes(false);
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
        return applicationServiceBehavior.getApplicationDetail(detailRequest);
    }

    private ActivationStatus getActivationStatus(String activationId) throws Exception {
        final GetActivationStatusRequest statusRequest = new GetActivationStatusRequest();
        statusRequest.setActivationId(activationId);
        final GetActivationStatusResponse statusResponse = activationServiceBehavior.getActivationStatus(statusRequest);

        return statusResponse.getActivationStatus();
    }

}
