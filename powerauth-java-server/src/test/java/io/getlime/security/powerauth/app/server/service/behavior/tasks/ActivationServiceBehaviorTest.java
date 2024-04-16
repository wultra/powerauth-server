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
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.service.PowerAuthService;
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

    @Autowired
    private PowerAuthService powerAuthService;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String version = "3.2";
    private final String userId = UUID.randomUUID().toString();

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
        tested.prepareActivation(activationCode, applicationKey, false, encryptedRequest, version, keyConvertor);

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
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () ->
                tested.prepareActivation(activationCode, applicationKey, false, encryptedRequest, version, keyConvertor));
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
        final CreateActivationResponse response =
                tested.createActivation(userId, null, false, null, applicationKey, encryptedRequest, null, version, keyConvertor);

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
        final GenericServiceException exception = assertThrows(GenericServiceException.class, () ->
                tested.createActivation(userId, null, false, null, applicationKey, encryptedRequest, null, version, keyConvertor));
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
        final RecoveryCodeActivationResponse recoveryCodeActivationResponse = tested.createActivationUsingRecoveryCode(recoveryCodeActivationRequest, keyConvertor);

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
                tested.createActivationUsingRecoveryCode(recoveryCodeActivationRequest, keyConvertor));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
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
                new EncryptorParameters(version, applicationKey, null),
                new ClientEncryptorSecrets(masterPublicKey, applicationSecret));
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(objectMapper.writeValueAsBytes(activationLayer2Request));

        // Create activation
        final CreateActivationResponse createActivationResponse =
                tested.createActivation(userId, null, true, null, applicationKey, encryptedRequest, null, version, keyConvertor);

        final String activationId = createActivationResponse.getActivationId();
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationId));

        // Commit activation
        commitActivation(activationId);
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
        powerAuthService.updateRecoveryConfig(updateRecoveryConfigRequest);
    }

    private boolean isRecoveryCodeGenerationEnabled(String applicationId) throws Exception {
        final GetRecoveryConfigRequest getRecoveryConfigRequest = new GetRecoveryConfigRequest();
        getRecoveryConfigRequest.setApplicationId(applicationId);
        final GetRecoveryConfigResponse recoveryConfigResponse = powerAuthService.getRecoveryConfig(getRecoveryConfigRequest);
        return recoveryConfigResponse.isActivationRecoveryEnabled();
    }

    private String generatePublicKey() throws Exception {
        final KeyGenerator keyGenerator = new KeyGenerator();
        final KeyPair keyPair = keyGenerator.generateKeyPair();
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private void commitActivation(String activationId) throws Exception {
        final CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationId(activationId);
        powerAuthService.commitActivation(commitActivationRequest);
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
        final LookupRecoveryCodesResponse lookupRecoveryCodesResponse = powerAuthService.lookupRecoveryCodes(lookupRecoveryCodesRequest);
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
                new EncryptorParameters(version, applicationKey, null),
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
        return tested.initActivation(ActivationProtocol.POWERAUTH, applicationId, userId, null, null, null, null, null, keyConvertor);
    }

    private GetApplicationDetailResponse createApplication() throws Exception {
        final String testId = UUID.randomUUID().toString();
        final CreateApplicationRequest createApplicationRequest = new CreateApplicationRequest();
        createApplicationRequest.setApplicationId(testId);
        final CreateApplicationResponse createApplicationResponse = powerAuthService.createApplication(createApplicationRequest);

        final GetApplicationDetailRequest detailRequest = new GetApplicationDetailRequest();
        detailRequest.setApplicationId(createApplicationResponse.getApplicationId());
        return powerAuthService.getApplicationDetail(detailRequest);
    }

    private ActivationStatus getActivationStatus(String activationId) throws Exception {
        final GetActivationStatusRequest statusRequest = new GetActivationStatusRequest();
        statusRequest.setActivationId(activationId);
        final GetActivationStatusResponse statusResponse = powerAuthService.getActivationStatus(statusRequest);

        return statusResponse.getActivationStatus();
    }

}
