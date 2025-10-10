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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.app.server.database.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationRemoveServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationValidationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.model.response.v3.ActivationLayer2Response;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Base64;

/**
 * Service behavior for handling the activation process.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("activationProcessServiceBehaviorV3")
@Slf4j
@AllArgsConstructor
public class ActivationProcessServiceBehavior {

    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final ActivationValidationServiceBehavior activationValidationServiceBehavior;
    private final CryptographyServiceFactory cryptographyServiceFactory;
    private final LocalizationProvider localizationProvider;
    private final CallbackUrlBehavior callbackUrlBehavior;
    private final ObjectMapper objectMapper;
    private final ActivationRemoveServiceBehavior activationRemoveServiceBehavior;

    /**
     * Process a new activation which is initialized in the database.
     *
     * @param activation Activation entity.
     * @param decryptionResult Decryption result.
     * @param protocolVersion Protocol version.
     * @return ECIES encrypted response.
     * @throws GenericServiceException In case activation processing fails.
     */
    public EciesEncryptedResponse processNewActivation(ActivationRecordEntity activation, DecryptionResult decryptionResult, String protocolVersion) throws GenericServiceException {
        try {
            // Decrypt activation data
            final byte[] activationData = decryptionResult.getDecryptedData();

            // Convert JSON data to activation layer 2 request object
            com.wultra.security.powerauth.app.server.service.model.request.v3.ActivationLayer2Request layer2Request;
            try {
                layer2Request = objectMapper.readValue(activationData, com.wultra.security.powerauth.app.server.service.model.request.v3.ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, activation ID: {}", activation.getActivationId());
                // Activation failed due to invalid ECIES request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Ensure presence of the devicePublicKey
            final String retrievedDevicePublicKey = layer2Request.getDevicePublicKey();
            if (!StringUtils.hasText(retrievedDevicePublicKey)) {
                logger.warn("Invalid activation request, activation ID: {}", activation.getActivationId());
                // Activation failed due to invalid ECIES request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Validate activation OTP for stage ON_KEY_EXCHANGE
            activationValidationServiceBehavior.validateActivationOtp(CommitPhase.ON_KEY_EXCHANGE, layer2Request.getActivationOtp(), activation, null);

            // Extract the device public key from request
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(retrievedDevicePublicKey);
            BasePublicKey devicePublicKey = null;
            try {
                devicePublicKey = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).convertDevicePublicKey(KeyType.ECDSA_P256, devicePublicKeyBytes);
            } catch (GenericServiceException e) {
                logger.warn("Invalid public key, activation ID: {}", activation.getActivationId());
                logger.debug("Invalid public key, activation ID: {}", activation.getActivationId(), e);
                handleInvalidPublicKey(activation);
            }
            cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).storeDevicePublicKey(activation, devicePublicKey);

            // Initialize hash based counter
            final HashBasedCounter counter = new HashBasedCounter(protocolVersion);
            final byte[] ctrData = counter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

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
            // PowerAuth protocol version 3.0 uses 0x3 as version in activation status
            activation.setVersion(3);
            // Set initial counter data (V3)
            activation.setCtrDataBase64(ctrDataBase64);
            // Activation confirmation is not tracked for V3
            activation.setConfirmationPending(false);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Generate activation layer 2 response
            final ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);
            layer2Response.setServerPublicKey(activation.getServerPublicKeyBase64());
            final byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            return (EciesEncryptedResponse) decryptionResult.getServerEncryptor().encryptResponse(responseData);
        } catch (EncryptorException | JsonProcessingException ex) {
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

    /**
     * Handle case when public key is invalid. Remove provided activation (mark as REMOVED),
     * notify callback listeners, and throw an exception.
     *
     * @param activation Activation to be removed.
     * @throws GenericServiceException Error caused by invalid public key.
     */
    private void handleInvalidPublicKey(ActivationRecordEntity activation) throws GenericServiceException {
        activation.setActivationStatus(ActivationStatus.REMOVED);
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        // Exception must not be rollbacking, otherwise data written to database in this method would be lost
        throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
    }

    private void changeActivationStatusAndDeleteParent(final ActivationRecordEntity activation, final com.wultra.security.powerauth.app.server.service.model.request.v3.ActivationLayer2Request layer2Request) {
        // If activation OTP is provided and valid, or commit phase is ON_KEY_EXCHANGE, then the status is set directly to "ACTIVE".
        final boolean isActive = StringUtils.hasText(layer2Request.getActivationOtp()) || activation.getCommitPhase() == CommitPhase.ON_KEY_EXCHANGE;
        final ActivationStatus activationStatus = isActive ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;
        activation.setActivationStatus(activationStatus);

        final ActivationRecordEntity parentActivation = activation.getParentActivation();
        if (isActive && parentActivation != null && activation.getTransferType() == ActivationTransferType.MOVE) {
            logger.info("Removing activation ID: {}, because is parent of moved activation ID: {}", parentActivation.getActivationId(), activation.getActivationId());
            activationRemoveServiceBehavior.removeActivation(parentActivation, null);
        }
    }
}
