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
import com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.service.PowerAuthService;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.app.server.service.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.*;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.EciesUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link ActivationServiceBehavior}.
 *
 * @author Jan Pesek, janpesek@outlook.com
 */
@SpringBootTest
@Transactional
public class ActivationServiceBehaviorTest {

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
        final EciesPayload correctEciesPayload = buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation
        assertDoesNotThrow(() -> tested.prepareActivation(
                initActivationResponse.getActivationCode(), detailResponse.getVersions().get(0).getApplicationKey(),
                false, correctEciesPayload, version, keyConvertor));

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
        final EciesPayload invalidEciesPayload = buildPrepareActivationPayload(requestL2, detailResponse);

        // Prepare activation with missing devicePublicKey
        GenericServiceException exception = assertThrows(
                GenericServiceException.class,
                () -> tested.prepareActivation(initActivationResponse.getActivationCode(),
                        detailResponse.getVersions().get(0).getApplicationKey(),
                        false, invalidEciesPayload, version, keyConvertor));
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
        final EciesPayload correctEciesPayload = buildPrepareActivationPayload(requestL2, detailResponse);

        // Create activation
        CreateActivationResponse response = assertDoesNotThrow(
                () -> tested.createActivation(UUID.randomUUID().toString(), null, false,
                        null, detailResponse.getVersions().get(0).getApplicationKey(), correctEciesPayload,
                        null, version, keyConvertor));

        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(response.getActivationId()));
    }

    @Test
    void testCreateActivationWithInvalidPayload() throws Exception {

        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Create request payload, omit device public key
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        final EciesPayload invalidEciesPayload = buildPrepareActivationPayload(requestL2, detailResponse);

        // Create activation with missing devicePublicKey
        GenericServiceException exception = assertThrows(
                GenericServiceException.class,
                () -> tested.createActivation(UUID.randomUUID().toString(), null, false,
                        null, detailResponse.getVersions().get(0).getApplicationKey(), invalidEciesPayload,
                        null, version, keyConvertor));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void testCreateActivationUsingRecoveryCode() throws Exception {

        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Create activation with recovery code
        ActivationLayer2Response responsePayload = createActivationAndGetResponsePayload(detailResponse);

        // Generate public key for a new client device
        String publicKeyBytes = generatePublicKey();

        // Build createActivation request payload
        ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();
        activationLayer2Request.setDevicePublicKey(publicKeyBytes);

        // Create activation using recovery code
        RecoveryCodeActivationRequest recoveryCodeActivationRequest = buildRecoveryCodeActivationRequest(responsePayload.getActivationRecovery().getRecoveryCode(),
                responsePayload.getActivationRecovery().getPuk(), activationLayer2Request, detailResponse);

        // Create activation
        RecoveryCodeActivationResponse recoveryCodeActivationResponse = assertDoesNotThrow(
                () -> tested.createActivationUsingRecoveryCode(recoveryCodeActivationRequest, keyConvertor));

        // Check new activation was created
        assertNotEquals(responsePayload.getActivationId(), recoveryCodeActivationResponse.getActivationId());

        // Check used recovery code is revoked
        assertEquals(RecoveryCodeStatus.REVOKED, getRecoveryCodeStatus(userId, responsePayload.getActivationId(), detailResponse.getApplicationId()));
    }

    @Test
    void testCreateActivationUsingRecoveryCodeWithInvalidPayload() throws Exception {

        // Create application
        final GetApplicationDetailResponse detailResponse = createApplication();

        // Create activation with recovery code
        ActivationLayer2Response responsePayload = createActivationAndGetResponsePayload(detailResponse);

        // Build createActivation request payload, now omit device public key
        ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();

        // Create activation using recovery code
        RecoveryCodeActivationRequest recoveryCodeActivationRequest = buildRecoveryCodeActivationRequest(responsePayload.getActivationRecovery().getRecoveryCode(),
                responsePayload.getActivationRecovery().getPuk(), activationLayer2Request, detailResponse);

        // Create activation with missing devicePublicKey
        GenericServiceException exception = assertThrows(
                GenericServiceException.class,
                () -> tested.createActivationUsingRecoveryCode(recoveryCodeActivationRequest, keyConvertor));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    private ActivationLayer2Response createActivationAndGetResponsePayload(GetApplicationDetailResponse applicationDetail) throws Exception {

        final String applicationId = applicationDetail.getApplicationId();

        // Set recovery config
        enableRecoveryCodesGeneration(applicationId);
        assertTrue(isRecoveryCodeGenerationEnabled(applicationId));

        // Generate public key for a client device
        String publicKeyBytes = generatePublicKey();

        // Build createActivation request payload
        ActivationLayer2Request activationLayer2Request = new ActivationLayer2Request();
        activationLayer2Request.setDevicePublicKey(publicKeyBytes);

        // Encrypt createActivation request payload
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final EciesParameters eciesParameters = buildEciesParameters(applicationKey);
        final ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(applicationDetail.getMasterPublicKey()));
        final EciesEncryptor eciesEncryptor = new EciesFactory().getEciesEncryptorForApplication(masterPublicKey,
                applicationDetail.getVersions().get(0).getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                EciesSharedInfo1.ACTIVATION_LAYER_2, eciesParameters);
        EciesPayload createActivationRequestPayload = eciesEncryptor.encrypt(objectMapper.writeValueAsBytes(activationLayer2Request), eciesParameters);

        // Create activation
        CreateActivationResponse createActivationResponse = tested.createActivation(userId, null, true,
                null, applicationKey, createActivationRequestPayload,
                null, version, keyConvertor);
        final String activationId = createActivationResponse.getActivationId();
        assertEquals(ActivationStatus.PENDING_COMMIT, getActivationStatus(activationId));

        // Commit activation
        commitActivation(activationId);
        assertEquals(ActivationStatus.ACTIVE, getActivationStatus(activationId));

        // Decrypt createActivation response payload
        ActivationLayer2Response responsePayload = decryptPayload(createActivationResponse, createActivationRequestPayload, eciesEncryptor.getEnvelopeKey(), applicationDetail.getVersions().get(0).getApplicationSecret());

        // Check recovery was created
        assertNotNull(responsePayload.getActivationRecovery());

        // Check recovery code is active
        assertEquals(RecoveryCodeStatus.ACTIVE, getRecoveryCodeStatus(userId, activationId, applicationDetail.getApplicationId()));

        return responsePayload;
    }

    private void enableRecoveryCodesGeneration(String applicationId) throws Exception {
        UpdateRecoveryConfigRequest updateRecoveryConfigRequest = new UpdateRecoveryConfigRequest();
        updateRecoveryConfigRequest.setApplicationId(applicationId);
        updateRecoveryConfigRequest.setActivationRecoveryEnabled(true);
        powerAuthService.updateRecoveryConfig(updateRecoveryConfigRequest);
    }

    private boolean isRecoveryCodeGenerationEnabled(String applicationId) throws Exception {
        GetRecoveryConfigRequest getRecoveryConfigRequest = new GetRecoveryConfigRequest();
        getRecoveryConfigRequest.setApplicationId(applicationId);
        GetRecoveryConfigResponse recoveryConfigResponse = powerAuthService.getRecoveryConfig(getRecoveryConfigRequest);
        return recoveryConfigResponse.isActivationRecoveryEnabled();
    }

    private String generatePublicKey() throws Exception {
        final KeyGenerator keyGenerator = new KeyGenerator();
        final KeyPair keyPair = keyGenerator.generateKeyPair();
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(keyPair.getPublic());
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    private void commitActivation(String activationId) throws Exception {
        CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationId(activationId);
        powerAuthService.commitActivation(commitActivationRequest);
    }

    private ActivationLayer2Response decryptPayload(CreateActivationResponse response, EciesPayload activationRequestPayload, EciesEnvelopeKey envelopeKey, String applicationSecret) throws Exception {
        EciesCryptogram eciesCryptogram = EciesCryptogram.builder()
                .encryptedData(Base64.getDecoder().decode(response.getEncryptedData()))
                .ephemeralPublicKey(activationRequestPayload.getCryptogram().getEphemeralPublicKey())
                .mac(Base64.getDecoder().decode(response.getMac())).build();

        EciesParameters eciesParameters = EciesParameters.builder()
                .nonce(Base64.getDecoder().decode(response.getNonce()))
                .associatedData(activationRequestPayload.getParameters().getAssociatedData())
                .timestamp(response.getTimestamp()).build();

        EciesPayload payloadDecrypt = new EciesPayload(eciesCryptogram, eciesParameters);
        EciesDecryptor decryptor = new EciesFactory().getEciesDecryptor(EciesScope.APPLICATION_SCOPE, envelopeKey, applicationSecret.getBytes(StandardCharsets.UTF_8), null, eciesParameters, activationRequestPayload.getCryptogram().getEphemeralPublicKey());

        final byte[] decryptedActivationResponsePayload = decryptor.decrypt(payloadDecrypt);

        ActivationLayer2Response responsePayload;
        responsePayload = objectMapper.readValue(decryptedActivationResponsePayload, ActivationLayer2Response.class);

        return responsePayload;
    }

    private RecoveryCodeStatus getRecoveryCodeStatus(String userId, String activationId, String applicationId) throws Exception {
        LookupRecoveryCodesRequest lookupRecoveryCodesRequest = new LookupRecoveryCodesRequest();
        lookupRecoveryCodesRequest.setUserId(userId);
        lookupRecoveryCodesRequest.setActivationId(activationId);
        lookupRecoveryCodesRequest.setApplicationId(applicationId);
        LookupRecoveryCodesResponse lookupRecoveryCodesResponse = powerAuthService.lookupRecoveryCodes(lookupRecoveryCodesRequest);
        return lookupRecoveryCodesResponse.getRecoveryCodes().get(0).getStatus();
    }

    private EciesParameters buildEciesParameters(String applicationKey) throws Exception {
        final byte[] associatedData = EciesUtils.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, version, applicationKey, null);
        final Long timestamp = new Date().getTime();
        final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
        return EciesParameters.builder().nonce(nonceBytes).associatedData(associatedData).timestamp(timestamp).build();
    }

    private EciesPayload buildPrepareActivationPayload(ActivationLayer2Request requestL2,
                                                       GetApplicationDetailResponse applicationDetail) throws Exception {

        // Set parameters
        final String applicationKey = applicationDetail.getVersions().get(0).getApplicationKey();
        final EciesParameters eciesParameters = buildEciesParameters(applicationKey);

        final ECPublicKey masterPublicKey = (ECPublicKey) keyConvertor.convertBytesToPublicKey(
                Base64.getDecoder().decode(applicationDetail.getMasterPublicKey()));

        // Encrypt payload
        final EciesEncryptor eciesEncryptor = new EciesFactory().getEciesEncryptorForApplication(masterPublicKey,
                applicationDetail.getVersions().get(0).getApplicationSecret().getBytes(StandardCharsets.UTF_8),
                EciesSharedInfo1.ACTIVATION_LAYER_2, eciesParameters);
        return eciesEncryptor.encrypt(new ObjectMapper().writeValueAsBytes(requestL2), eciesParameters);
    }

    private RecoveryCodeActivationRequest buildRecoveryCodeActivationRequest(String recoveryCode, String puk, ActivationLayer2Request payload, GetApplicationDetailResponse detailResponse) throws Exception {
        EciesPayload eciesPayload = buildPrepareActivationPayload(payload, detailResponse);

        RecoveryCodeActivationRequest recoveryCodeActivationRequest = new RecoveryCodeActivationRequest();
        recoveryCodeActivationRequest.setRecoveryCode(recoveryCode);
        recoveryCodeActivationRequest.setPuk(puk);
        recoveryCodeActivationRequest.setApplicationKey(detailResponse.getVersions().get(0).getApplicationKey());
        recoveryCodeActivationRequest.setProtocolVersion(version);
        recoveryCodeActivationRequest.setEncryptedData(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEncryptedData()));
        recoveryCodeActivationRequest.setMac(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getMac()));
        recoveryCodeActivationRequest.setNonce(Base64.getEncoder().encodeToString(eciesPayload.getParameters().getNonce()));
        recoveryCodeActivationRequest.setTimestamp(eciesPayload.getParameters().getTimestamp());
        recoveryCodeActivationRequest.setEphemeralPublicKey(Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEphemeralPublicKey()));

        return recoveryCodeActivationRequest;
    }

    private InitActivationResponse initActivation(String applicationId) throws Exception {
        return tested.initActivation(
                applicationId, userId,
                null, null, null,null,null,
                keyConvertor);
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
        GetActivationStatusResponse statusResponse = powerAuthService.getActivationStatus(statusRequest);

        return statusResponse.getActivationStatus();
    }

}
