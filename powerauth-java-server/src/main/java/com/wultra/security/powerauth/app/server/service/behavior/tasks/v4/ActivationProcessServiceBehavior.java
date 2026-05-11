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

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.app.server.database.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationRemoveServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationValidationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmValidationService;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.crypto.v4.KeyPairGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.v4.ActivationLayer2Request;
import com.wultra.security.powerauth.app.server.service.model.request.v4.SharedSecretRequestPayload;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.model.response.v4.ActivationLayer2Response;
import com.wultra.security.powerauth.app.server.service.model.response.v4.SharedSecretResponsePayload;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Base64;

/**
 * Service behavior for handling the activation process.
 */
@Service("activationProcessServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class ActivationProcessServiceBehavior {

    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final ActivationValidationServiceBehavior activationValidationServiceBehavior;
    private final SharedSecretServiceBehavior sharedSecretServiceBehavior;
    private final LocalizationProvider localizationProvider;
    private final CallbackUrlBehavior callbackUrlBehavior;
    private final ObjectMapper objectMapper;
    private final ActivationRemoveServiceBehavior activationRemoveServiceBehavior;
    private final AlgorithmValidationService algorithmValidationService;
    private final KeyPairGenerationService keyPairGenerationService;
    private final CryptographyServiceFactory cryptographyServiceFactory;

    public AeadEncryptedResponse processNewActivation(ActivationRecordEntity activation, DecryptionResult decryptionResult, String protocolVersion) throws GenericServiceException {
        try {
            // Decrypt activation data
            final byte[] activationData = decryptionResult.getDecryptedData();

            // Convert JSON data to activation layer 2 request object
            ActivationLayer2Request layer2Request;
            try {
                layer2Request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (JacksonException ex) {
                logger.warn("Invalid activation request, activation ID: {}", activation.getActivationId());
                // Activation failed due to invalid request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            if (layer2Request.getSharedSecretRequest() == null || layer2Request.getSharedSecretRequest().getAlgorithm() == null || layer2Request.getDevicePublicKeys() == null) {
                logger.warn("Invalid encrypted activation request payload, activation ID: {}", activation.getActivationId());
                // Activation failed due to invalid request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Check that cryptography algorithm is allowed
            final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(layer2Request.getSharedSecretRequest().getAlgorithm());

            try {
                algorithmValidationService.validateAlgorithmForApplication(activation.getApplication(), algorithm);
            } catch (GenericServiceException e) {
                // Activation failed due to unsupported algorithm, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.CRYPTOGRAPHY_ALGORITHM_NOT_SUPPORTED);
            }

            activation.setCryptoAlgorithm(algorithm);

            // Validate activation OTP for stage ON_KEY_EXCHANGE
            activationValidationServiceBehavior.validateActivationOtp(CommitPhase.ON_KEY_EXCHANGE, layer2Request.getActivationOtp(), activation, null);

            // Generate new server key pairs
            keyPairGenerationService.generateServerKeyPairs(activation, algorithm);

            // Initialize hash based counter
            final HashBasedCounter counter = new HashBasedCounter(protocolVersion);
            final byte[] ctrData = counter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

            final SharedSecretRequestPayload requestPayload = new SharedSecretRequestPayload();
            requestPayload.setSharedSecretRequest(layer2Request.getSharedSecretRequest());
            requestPayload.setDevicePublicKeys(layer2Request.getDevicePublicKeys());
            requestPayload.setEnableBiometry(false);

            // Set counter data for V4
            activation.setCtrDataV4Base64(ctrDataBase64);

            final SharedSecretResponsePayload responsePayload;
            try {
                responsePayload = sharedSecretServiceBehavior.deriveSharedSecret(activation, requestPayload);
            } catch (GenericServiceException e) {
                // Activation failed due to failed shared secret request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            }

            // Store the activation fingerprint
            final String activationFingerprint = cryptographyServiceFactory.getService(algorithm).generateActivationFingerprint(activation);
            activation.setActivationFingerprint(activationFingerprint);

            // Update and persist the activation record
            changeActivationStatusAndDeleteParent(activation, layer2Request);
            activation.setActivationName(layer2Request.getActivationName());
            activation.setExternalId(layer2Request.getExternalId());
            activation.setExtras(layer2Request.getExtras());
            if (layer2Request.getPlatform() != null) {
                activation.setPlatform(layer2Request.getPlatform().toLowerCase());
            } else {
                activation.setPlatform("unknown");
            }
            activation.setDeviceInfo(layer2Request.getDeviceInfo());
            // PowerAuth protocol version 4.0 uses 0x4 as version in activation status
            activation.setVersion(4);
            // Confirmation pending is tracked for V4
            activation.setConfirmationPending(true);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            final ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setSharedSecretResponse(responsePayload.getSharedSecretResponse());
            layer2Response.setServerPublicKeys(responsePayload.getServerPublicKeys());
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);

            final byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            return (AeadEncryptedResponse) decryptionResult.getServerEncryptor().encryptResponse(responseData);
        } catch (EncryptorException | JacksonException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
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

    private void changeActivationStatusAndDeleteParent(final ActivationRecordEntity activation, final ActivationLayer2Request layer2Request) {
        // If activation OTP is provided and valid, or commit phase is ON_KEY_EXCHANGE, then the status is set directly to "ACTIVE".
        final boolean isActive = StringUtils.hasText(layer2Request.getActivationOtp()) || activation.getCommitPhase() == CommitPhase.ON_KEY_EXCHANGE;
        final ActivationStatus activationStatus = isActive ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;
        activation.setActivationStatus(activationStatus);

        final ActivationRecordEntity parentActivation = activation.getParentActivation();
        if (isActive && parentActivation != null && activation.getTransferType() == ActivationTransferType.MOVE) {
            logger.info("Removing activation ID: {}, because it is parent of moved activation ID: {}", parentActivation.getActivationId(), activation.getActivationId());
            activationRemoveServiceBehavior.removeActivation(parentActivation, null);
        }
    }
}