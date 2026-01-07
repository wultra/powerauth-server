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

import com.wultra.security.powerauth.app.server.converter.ActivationSharedSecretConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.SharedSecretRecord;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.crypto.KeyProvider;
import com.wultra.security.powerauth.app.server.service.crypto.v4.SharedSecretService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import com.wultra.security.powerauth.app.server.service.model.request.v4.SharedSecretRequestPayload;
import com.wultra.security.powerauth.app.server.service.model.response.v4.SharedSecretResponsePayload;
import com.wultra.security.powerauth.client.model.entity.v4.request.DevicePublicKeys;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.response.ServerPublicKeys;
import com.wultra.security.powerauth.client.model.entity.v4.response.SharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.authentication.AuthenticationKeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Service behavior for handling the shared secret derivation.
 */
@Service
@Slf4j
@AllArgsConstructor
public class SharedSecretServiceBehavior {

    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final CryptographyServiceFactory cryptographyServiceFactory;
    private final LocalizationProvider localizationProvider;
    private final CallbackUrlBehavior callbackUrlBehavior;

    private final ActivationSharedSecretConverter activationSharedSecretConverter;
    private final SharedSecretService sharedSecretService;
    private final KeyProvider keyProvider;

    private final AuthenticationKeyFactory authenticationKeyFactory = new AuthenticationKeyFactory();

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    /**
     * Derive shared secret response payload.
     * @param activation Activation.
     * @param requestPayload Shared secret request payload.
     * @return Shared secret response payload.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case of any other cryptography error.
     * @throws GenericServiceException In case shared secret derivation fails.
     */
    public SharedSecretResponsePayload deriveSharedSecret(ActivationRecordEntity activation, SharedSecretRequestPayload requestPayload) throws GenericCryptoException, CryptoProviderException, GenericServiceException {
        final String activationId = activation.getActivationId();
        final SharedSecretRequest sharedSecretRequest = requestPayload.getSharedSecretRequest();
        if (sharedSecretRequest == null) {
            logger.warn("Invalid shared secret request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        sharedSecretService.validateSharedSecretRequest(sharedSecretRequest, activation.getActivationId());
        final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(sharedSecretRequest.getAlgorithm());

        final DevicePublicKeys devicePublicKeys = requestPayload.getDevicePublicKeys();
        if (devicePublicKeys == null) {
            logger.warn("Invalid shared secret request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Ensure the presence of the devicePublicKey
        final String ecDevicePublicKey = devicePublicKeys.getEcdsa();
        if (!StringUtils.hasText(ecDevicePublicKey)) {
            logger.warn("Invalid shared secret request, activation ID: {}", activationId);
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

        final SharedSecretResponsePayload responsePayload = new SharedSecretResponsePayload();

        final PublicKeyRegistry publicKeyRegistry = keyProvider.getServerPublicKeys(activation).orElseThrow(() -> {
            logger.warn("Server public keys are not available, activationId={}", activationId);
            // Activation failed due to invalid request, rollback transaction
            return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        });

        final PublicKey ecServerPublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
            logger.warn("Missing ECDSA public key in shared secret request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        });
        final byte[] ecServerPublicKeyRaw = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecServerPublicKey);
        final ServerPublicKeys publicKeysResponse = new ServerPublicKeys();
        publicKeysResponse.setEcdsa(Base64.getEncoder().encodeToString(ecServerPublicKeyRaw));

        if (algorithm == SharedSecretAlgorithm.EC_P384_ML_L3 || algorithm == SharedSecretAlgorithm.EC_P384_ML_L5) {
            final String pqcDevicePublicKey = devicePublicKeys.getMldsa();
            if (!StringUtils.hasText(pqcDevicePublicKey)) {
                logger.warn("Invalid shared secret request, activation ID: {}", activationId);
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            try {
                final byte[] pqcDevicePublicKeyBytes = Base64.getDecoder().decode(pqcDevicePublicKey);
                final KeyType pqcType = switch (algorithm) {
                    case EC_P384_ML_L3 -> KeyType.MLDSA_65;
                    case EC_P384_ML_L5 -> KeyType.MLDSA_87;
                    default -> throw new IllegalStateException("Unexpected algorithm: " + algorithm);
                };
                final BasePublicKey pqcDevicePublicKeyDsa = cryptographyServiceFactory.getService(algorithm).convertDevicePublicKey(pqcType, pqcDevicePublicKeyBytes);
                cryptographyServiceFactory.getService(algorithm).storeDevicePublicKey(activation, pqcDevicePublicKeyDsa);
            } catch (GenericServiceException e) {
                logger.warn("Invalid public key, activation ID: {}", activation.getActivationId());
                logger.debug("Invalid public key, activation ID: {}", activation.getActivationId(), e);
                handleInvalidPublicKey(activation);
            }
            final PublicKey pqcServerPublicKey = switch (algorithm) {
                case EC_P384_ML_L3 -> publicKeyRegistry.getPublicKey(KeyType.MLDSA_65).orElseThrow(() -> {
                    logger.warn("Missing ML-DSA-65 public key in shared secret request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                case EC_P384_ML_L5 -> publicKeyRegistry.getPublicKey(KeyType.MLDSA_87).orElseThrow(() -> {
                    logger.warn("Missing ML-DSA-87 public key in shared secret request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                default -> throw new IllegalStateException("Unexpected algorithm: " + algorithm);
            };
            final byte[] pqcServerPublicKeyRaw = KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(pqcServerPublicKey);
            publicKeysResponse.setMldsa(Base64.getEncoder().encodeToString(pqcServerPublicKeyRaw));
        }

        final Pair<SharedSecretResponse, ResponseCryptogram> responsePair = sharedSecretService.deriveSharedSecret(sharedSecretRequest);
        final SharedSecretResponse sharedSecretResponse = responsePair.getFirst();
        final ResponseCryptogram responseCryptogram = responsePair.getSecond();
        responsePayload.setServerPublicKeys(publicKeysResponse);
        responsePayload.setSharedSecretResponse(sharedSecretResponse);

        storeActivationSecretKey(activation, responseCryptogram);
        storeInitialFactorKeys(activation, requestPayload.isEnableBiometry(), responseCryptogram);
        return responsePayload;
    }

    /**
     * Store derived activation secret key.
     * @param activation Activation entity.
     * @param responseCryptogram Response cryptogram.
     * @throws GenericServiceException Thrown in case of any cryptography error.
     */
    private void storeActivationSecretKey(ActivationRecordEntity activation, ResponseCryptogram responseCryptogram) throws GenericServiceException {
        final byte[] sharedSecretBytes = KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(responseCryptogram.getSecretKey());
        final SharedSecretRecord sharedSecretDb = activationSharedSecretConverter.toDBValue(sharedSecretBytes, activation.getUserId(), activation.getActivationId());
        activation.setSharedSecret(sharedSecretDb.sharedSecretBase64());
        activation.setSharedSecretEncryption(sharedSecretDb.encryptionAlgorithm());
    }

    /**
     * Set initial factor keys for knowledge and biometry.
     * @param activation Activation entity.
     * @param enableBiometry Whether biometry should be enabled
     * @param responseCryptogram Response cryptogram.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    private void storeInitialFactorKeys(ActivationRecordEntity activation, boolean enableBiometry, ResponseCryptogram responseCryptogram) throws GenericCryptoException {
        // Set knowledge factor key to initial value
        final SecretKey knowledgeFactorKey = authenticationKeyFactory.generateKnowledgeFactorKey(responseCryptogram.getSecretKey());
        final byte[] knowledgeFactorKeyBytes = KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(knowledgeFactorKey);
        activation.setKnowledgeFactorKey(Base64.getEncoder().encodeToString(knowledgeFactorKeyBytes));
        // Set biometry factor key to initial value
        final SecretKey biometryFactorKey = authenticationKeyFactory.generateBiometryFactorKey(responseCryptogram.getSecretKey());
        final byte[] biometryFactorKeyBytes = KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(biometryFactorKey);
        activation.setBiometricFactorKey(Base64.getEncoder().encodeToString(biometryFactorKeyBytes));
        activation.setBiometricFactorEnabled(enableBiometry);
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
