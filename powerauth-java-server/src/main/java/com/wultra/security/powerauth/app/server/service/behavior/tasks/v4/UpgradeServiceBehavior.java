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
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.v4.EncryptionServiceAead;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.request.v4.SharedSecretRequestPayload;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.model.response.v4.SharedSecretResponsePayload;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.entity.v4.request.DevicePublicKeys;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.request.v4.ConfirmUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.v4.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.response.v4.ConfirmUpgradeResponse;
import com.wultra.security.powerauth.client.model.response.v4.StartUpgradeResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Base64;

/**
 * Behavior class implementing the activation upgrade process.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class UpgradeServiceBehavior {

    private final ActivationQueryService activationQueryService;
    private final LocalizationProvider localizationProvider;
    private final ActivationContextValidator activationValidator;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final EncryptionServiceAead encryptionService;
    private final SharedSecretServiceBehavior sharedSecretServiceBehavior;

    // Helper classes
    private final ObjectMapper objectMapper;
    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    /**
     * Start upgrade of activation to version 3.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws GenericServiceException In case upgrade fails.
     */
    @Transactional
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String protocolVersion = request.getProtocolVersion();

            // Build and validate encrypted request
            final AeadEncryptedRequest encryptedRequest = new AeadEncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEncryptedData(),
                    request.getNonce(),
                    request.getTimestamp()
            );

            // Lookup the activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            activationValidator.validateVersion(activation.getVersion(), 3, activationId, localizationProvider);

            // Decrypt request data to obtain shared secret request, device public keys and enable biometry flag
            final EncryptionContext context = new EncryptionContext(protocolVersion, applicationKey, null, EncryptorId.UPGRADE_START);
            final DecryptionResult decryptionResult = encryptionService.decryptRequest(encryptedRequest, context);
            final SharedSecretRequestPayload payload = parseRequestPayload(decryptionResult.getDecryptedData(), activation.getActivationId());

            // Invalid request in case activation is upgraded or older version
            if (activation.getVersion() != 3) {
                logger.info("Activation version is invalid during upgrade start, activation ID: {}, version: {}", activationId, activation.getVersion());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Verify request payload
            final SharedSecretRequest sharedSecretRequest = payload.getSharedSecretRequest();
            if (sharedSecretRequest == null) {
                logger.warn("Shared secret request is missing during upgrade start, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final DevicePublicKeys devicePublicKeys = payload.getDevicePublicKeys();
            if (devicePublicKeys == null) {
                logger.warn("Device public keys are missing during upgrade start, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final boolean enableBiometry = payload.isEnableBiometry();

            final SharedSecretRequestPayload requestPayload = new SharedSecretRequestPayload();
            requestPayload.setSharedSecretRequest(sharedSecretRequest);
            requestPayload.setDevicePublicKeys(devicePublicKeys);
            requestPayload.setEnableBiometry(enableBiometry);

            // Generate new counter data for V4 ctd_data column
            final HashBasedCounter hashBasedCounter = new HashBasedCounter(ProtocolVersion.V40.getVersion());
            final byte[] ctrData = hashBasedCounter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

            // Derive shared secret, store device public keys and initial factor keys, enable biometry if requested, store counter data
            final SharedSecretResponsePayload responsePayload = sharedSecretServiceBehavior.deriveSharedSecret(activation, requestPayload, ctrDataBase64);

            // Set activation upgrade confirmation pending
            activation.setUpgradeConfirmationPending(true);

            // Generate and encrypt response
            final byte[] responseBytes = generatedResponsePayload(responsePayload, activationId);
            final AeadEncryptedResponse encryptedResponse = (AeadEncryptedResponse) decryptionResult.getServerEncryptor().encryptResponse(responseBytes);

            final StartUpgradeResponse response = new StartUpgradeResponse();
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setTimestamp(encryptedResponse.getTimestamp());

            return response;
        } catch (EncryptorException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Confirm upgrade of activation to version 4.
     * @param request Confirm upgrade request.
     * @return Confirm upgrade response.
     * @throws GenericServiceException In case upgrade fails.
     */
    @Transactional
    public ConfirmUpgradeResponse confirmUpgrade(ConfirmUpgradeRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();

            // Lookup the activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            activationValidator.validateVersion(activation.getVersion(), 3, activationId, localizationProvider);

            // Lookup the application version and check that it is supported
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(request.getApplicationKey());
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            if (!activation.isUpgradeConfirmationPending()) {
                logger.warn("Activation upgrade is not pending, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Upgrade activation to version 4 and finish upgrade
            activation.setVersion(4);
            activation.setUpgradeConfirmationPending(false);

            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, null, AdditionalInformation.Reason.ACTIVATION_VERSION_CHANGED);

            final ConfirmUpgradeResponse response = new ConfirmUpgradeResponse();
            response.setConfirmed(true);
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Parse the decrypted JSON payload.
     *
     * @param data         Decrypted data.
     * @param activationId Activation identifier.
     * @return Parsed SharedSecretRequestPayload.
     * @throws GenericServiceException Thrown in case of deserialization errors.
     */
    private SharedSecretRequestPayload parseRequestPayload(byte[] data, String activationId) throws GenericServiceException {
        try {
            return objectMapper.readValue(data, SharedSecretRequestPayload.class);
        } catch (IOException ex) {
            logger.warn("Invalid start upgrade request, activation ID: {}", activationId, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    /**
     * Generate response payload as JSON.
     *
     * @param responsePayload Shared secret response payload.
     * @param activationId    Activation identifier.
     * @return Generated response as byte array.
     * @throws GenericServiceException Thrown in case of serialization errors.
     */
    private byte[] generatedResponsePayload(SharedSecretResponsePayload responsePayload, String activationId) throws GenericServiceException {
        try {
            return objectMapper.writeValueAsBytes(responsePayload);
        } catch (IOException ex) {
            logger.warn("Invalid start upgrade response, activation ID: {}", activationId, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

}
