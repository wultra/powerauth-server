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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.converter.ActivationSharedSecretConverter;
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.SharedSecret;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationValidationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import com.wultra.security.powerauth.app.server.service.model.request.v4.ActivationLayer2Request;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.model.response.v4.ActivationLayer2Response;
import com.wultra.security.powerauth.client.model.entity.v4.request.DevicePublicKeys;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.response.ServerPublicKeys;
import com.wultra.security.powerauth.client.model.entity.v4.response.SharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponseHybrid;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretEcdhe;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretHybrid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.PublicKey;
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
    private final CryptographyServiceFactory cryptographyServiceFactory;
    private final LocalizationProvider localizationProvider;
    private final CallbackUrlBehavior callbackUrlBehavior;
    private final ObjectMapper objectMapper;

    private final ActivationSharedSecretConverter activationSharedSecretConverter;
    private final PublicKeysConverter publicKeysConverter;

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new PqcDsaKeyConvertor();
    private final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

    public AeadEncryptedResponse processNewActivation(ActivationRecordEntity activation, DecryptionResult decryptionResult, String protocolVersion) throws GenericServiceException {
        try {
            // Decrypt activation data
            final byte[] activationData = decryptionResult.getDecryptedData();

            // Convert JSON data to activation layer 2 request object
            ActivationLayer2Request layer2Request;
            try {
                layer2Request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, activation ID: {}", activation.getActivationId());
                // Activation failed due to invalid request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Validate activation OTP for stage ON_KEY_EXCHANGE
            activationValidationServiceBehavior.validateActivationOtp(CommitPhase.ON_KEY_EXCHANGE, layer2Request.getActivationOtp(), activation, null);

            // If activation OTP is provided and valid, or commit phase is ON_KEY_EXCHANGE, then the status is set directly to "ACTIVE".
            // TODO - add biometry confirmation for crypto4 to decouple state transition from OTP check
            final boolean isActive = StringUtils.hasText(layer2Request.getActivationOtp()) || activation.getCommitPhase() == CommitPhase.ON_KEY_EXCHANGE;
            final ActivationStatus activationStatus = isActive ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;

            // Initialize hash based counter
            final HashBasedCounter counter = new HashBasedCounter(protocolVersion);
            final byte[] ctrData = counter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

            final ActivationLayer2Response layer2Response = deriveSharedSecret(activation, layer2Request, ctrDataBase64);

            // Update and persist the activation record
            activation.setActivationStatus(activationStatus);
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
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            final byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            return (AeadEncryptedResponse) decryptionResult.getServerEncryptor().encryptResponse(responseData);
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

    private ActivationLayer2Response deriveSharedSecret(ActivationRecordEntity activation, ActivationLayer2Request layer2Request, String ctrDataBase64) throws GenericServiceException, GenericCryptoException, CryptoProviderException {
        final String activationId = activation.getActivationId();
        final SharedSecretRequest sharedSecretRequest = layer2Request.getSharedSecretRequest();
        if (sharedSecretRequest == null) {
            logger.warn("Invalid activation request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(sharedSecretRequest.getAlgorithm());

        final DevicePublicKeys devicePublicKeys = layer2Request.getDevicePublicKeys();
        if (devicePublicKeys == null) {
            logger.warn("Invalid activation request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Ensure presence of the devicePublicKey
        final String ecDevicePublicKey = devicePublicKeys.getEcdsa();
        if (!StringUtils.hasText(ecDevicePublicKey)) {
            logger.warn("Invalid activation request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Extract the device public key from request
        final byte[] ecDevicePublicKeyBytes = Base64.getDecoder().decode(ecDevicePublicKey);
        BasePublicKey ecDevicePublicKeyDsa = null;
        try {
            ecDevicePublicKeyDsa = cryptographyServiceFactory.getService(algorithm).convertDevicePublicKey(KeyType.ECDSA_P384, ecDevicePublicKeyBytes);
        } catch (GenericServiceException e) {
            logger.warn("Invalid public key, activation ID: {}", activation.getActivationId());
            logger.debug("Invalid public key, activation ID: {}", activation.getActivationId(), e);
            handleInvalidPublicKey(activation);
        }
        cryptographyServiceFactory.getService(algorithm).storeDevicePublicKey(activation, ecDevicePublicKeyDsa);

        final ResponseCryptogram responseCryptogram;
        final ActivationLayer2Response activationLayer2Response = new ActivationLayer2Response();
        activationLayer2Response.setActivationId(activationId);
        activationLayer2Response.setCtrData(ctrDataBase64);
        switch (algorithm) {
            case EC_P384 -> {
                final SharedSecretRequestEcdhe sharedSecretRequestEcdhe = new SharedSecretRequestEcdhe();
                sharedSecretRequestEcdhe.setEcClientPublicKey(sharedSecretRequest.getEcdhe());
                responseCryptogram = SHARED_SECRET_ECDHE.generateResponseCryptogram(sharedSecretRequestEcdhe);

                final SharedSecretResponseEcdhe derivedResponse = (SharedSecretResponseEcdhe) responseCryptogram.getSharedSecretResponse();
                final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
                sharedSecretResponse.setEcdhe(derivedResponse.getEcServerPublicKey());
                activationLayer2Response.setSharedSecretResponse(sharedSecretResponse);

                final String serverPublicKeys = activation.getServerPublicKeys();
                final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(serverPublicKeys);
                final PublicKey ecServerPublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                    logger.warn("Missing ECDSA public key in activation request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                final byte[] ecServerPublicKeyRaw = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecServerPublicKey);
                final ServerPublicKeys publicKeysResponse = new ServerPublicKeys();
                publicKeysResponse.setEcdsa(Base64.getEncoder().encodeToString(ecServerPublicKeyRaw));
                activationLayer2Response.setServerPublicKeys(publicKeysResponse);
            }
            case EC_P384_ML_L3 -> {
                final String pqcDevicePublicKey = devicePublicKeys.getMldsa();
                if (!StringUtils.hasText(pqcDevicePublicKey)) {
                    logger.warn("Invalid activation request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
                }

                // Extract the device public key from request
                final byte[] pqcDevicePublicKeyBytes = Base64.getDecoder().decode(pqcDevicePublicKey);
                BasePublicKey pqcDevicePublicKeyDsa = null;
                try {
                    pqcDevicePublicKeyDsa = cryptographyServiceFactory.getService(algorithm).convertDevicePublicKey(KeyType.MLDSA_65, pqcDevicePublicKeyBytes);
                } catch (GenericServiceException e) {
                    logger.warn("Invalid public key, activation ID: {}", activation.getActivationId());
                    logger.debug("Invalid public key, activation ID: {}", activation.getActivationId(), e);
                    handleInvalidPublicKey(activation);
                }
                cryptographyServiceFactory.getService(algorithm).storeDevicePublicKey(activation, pqcDevicePublicKeyDsa);

                final SharedSecretRequestHybrid sharedSecretRequestHybrid = new SharedSecretRequestHybrid();
                sharedSecretRequestHybrid.setEcClientPublicKey(sharedSecretRequest.getEcdhe());
                sharedSecretRequestHybrid.setPqcEncapsulationKey(sharedSecretRequest.getMlkem());
                responseCryptogram = SHARED_SECRET_HYBRID.generateResponseCryptogram(sharedSecretRequestHybrid);

                final SharedSecretResponseHybrid derivedResponse = (SharedSecretResponseHybrid) responseCryptogram.getSharedSecretResponse();
                final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
                sharedSecretResponse.setEcdhe(derivedResponse.getEcServerPublicKey());
                sharedSecretResponse.setMlkem(derivedResponse.getPqcCiphertext());
                activationLayer2Response.setSharedSecretResponse(sharedSecretResponse);

                final String serverPublicKeys = activation.getServerPublicKeys();
                final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(serverPublicKeys);
                final PublicKey ecServerPublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                    logger.warn("Missing ECDSA public key in activation request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                final byte[] ecServerPublicKeyRaw = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecServerPublicKey);
                final PublicKey pqcServerPublicKey = publicKeyRegistry.getPublicKey(KeyType.MLDSA_65).orElseThrow(() -> {
                    logger.warn("Missing MLDSA public key in activation request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                final byte[] pqcServerPublicKeyRaw = KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(pqcServerPublicKey);
                final ServerPublicKeys publicKeysResponse = new ServerPublicKeys();
                publicKeysResponse.setEcdsa(Base64.getEncoder().encodeToString(ecServerPublicKeyRaw));
                publicKeysResponse.setMldsa(Base64.getEncoder().encodeToString(pqcServerPublicKeyRaw));
                activationLayer2Response.setServerPublicKeys(publicKeysResponse);
            }
            default -> {
                logger.warn("Invalid algorithm in activation request, activation ID: {}", activationId);
                // Activation failed due to invalid request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }
        }
        // Store derived shared secret into database
        final byte[] sharedSecretBytes = KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(responseCryptogram.getSecretKey());
        final SharedSecret sharedSecretDb = activationSharedSecretConverter.toDBValue(sharedSecretBytes, activation.getUserId(), activationId);
        activation.setSharedSecret(sharedSecretDb.sharedSecretBase64());
        activation.setSharedSecretEncryption(sharedSecretDb.encryptionMode());
        return activationLayer2Response;
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

}