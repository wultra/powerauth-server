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
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.SharedSecret;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
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
    private final PublicKeysConverter publicKeysConverter;
    private final AuthenticationKeyFactory authenticationKeyFactory = new AuthenticationKeyFactory();

    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();
    private final SharedSecretEcdhe SHARED_SECRET_ECDHE = new SharedSecretEcdhe();
    private final SharedSecretHybrid SHARED_SECRET_HYBRID = new SharedSecretHybrid();

    public SharedSecretResponsePayload deriveSharedSecret(ActivationRecordEntity activation, SharedSecretRequestPayload requestPayload, String ctrDataBase64) throws GenericServiceException, GenericCryptoException, CryptoProviderException {
        final String activationId = activation.getActivationId();
        final SharedSecretRequest sharedSecretRequest = requestPayload.getSharedSecretRequest();
        if (sharedSecretRequest == null) {
            logger.warn("Invalid shared secret request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(sharedSecretRequest.getAlgorithm());

        final DevicePublicKeys devicePublicKeys = requestPayload.getDevicePublicKeys();
        if (devicePublicKeys == null) {
            logger.warn("Invalid shared secret request, activation ID: {}", activationId);
            // Activation failed due to invalid request, rollback transaction
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Ensure presence of the devicePublicKey
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

        final ResponseCryptogram responseCryptogram;
        final SharedSecretResponsePayload responsePayload = new SharedSecretResponsePayload();
        // Counter data is stored in V4 ctr_data column
        activation.setCtrDataV4Base64(ctrDataBase64);
        responsePayload.setCtrData(ctrDataBase64);
        switch (algorithm) {
            case EC_P384 -> {
                final SharedSecretRequestEcdhe sharedSecretRequestEcdhe = new SharedSecretRequestEcdhe();
                sharedSecretRequestEcdhe.setEcClientPublicKey(sharedSecretRequest.getEcdhe());
                responseCryptogram = SHARED_SECRET_ECDHE.generateResponseCryptogram(sharedSecretRequestEcdhe);

                final SharedSecretResponseEcdhe derivedResponse = (SharedSecretResponseEcdhe) responseCryptogram.getSharedSecretResponse();
                final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
                sharedSecretResponse.setEcdhe(derivedResponse.getEcServerPublicKey());
                responsePayload.setSharedSecretResponse(sharedSecretResponse);

                final String serverPublicKeys = activation.getServerPublicKeys();
                final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(serverPublicKeys);
                final PublicKey ecServerPublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                    logger.warn("Missing ECDSA public key in shared secret request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                final byte[] ecServerPublicKeyRaw = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecServerPublicKey);
                final ServerPublicKeys publicKeysResponse = new ServerPublicKeys();
                publicKeysResponse.setEcdsa(Base64.getEncoder().encodeToString(ecServerPublicKeyRaw));
                responsePayload.setServerPublicKeys(publicKeysResponse);
            }
            case EC_P384_ML_L3 -> {
                final String pqcDevicePublicKey = devicePublicKeys.getMldsa();
                if (!StringUtils.hasText(pqcDevicePublicKey)) {
                    logger.warn("Invalid shared secret request, activation ID: {}", activationId);
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
                responsePayload.setSharedSecretResponse(sharedSecretResponse);

                final String serverPublicKeys = activation.getServerPublicKeys();
                final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(serverPublicKeys);
                final PublicKey ecServerPublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                    logger.warn("Missing ECDSA public key in shared secret request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                final byte[] ecServerPublicKeyRaw = KEY_CONVERTOR_EC.convertPublicKeyToBytes(EcCurve.P384, ecServerPublicKey);
                final PublicKey pqcServerPublicKey = publicKeyRegistry.getPublicKey(KeyType.MLDSA_65).orElseThrow(() -> {
                    logger.warn("Missing MLDSA public key in shared secret request, activation ID: {}", activationId);
                    // Activation failed due to invalid request, rollback transaction
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                });
                final byte[] pqcServerPublicKeyRaw = KEY_CONVERTOR_PQC_DSA.convertPublicKeyToBytes(pqcServerPublicKey);
                final ServerPublicKeys publicKeysResponse = new ServerPublicKeys();
                publicKeysResponse.setEcdsa(Base64.getEncoder().encodeToString(ecServerPublicKeyRaw));
                publicKeysResponse.setMldsa(Base64.getEncoder().encodeToString(pqcServerPublicKeyRaw));
                responsePayload.setServerPublicKeys(publicKeysResponse);
            }
            default -> {
                logger.warn("Invalid algorithm in shared secret request, activation ID: {}", activationId);
                // Activation failed due to invalid request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }
        }
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
        final SharedSecret sharedSecretDb = activationSharedSecretConverter.toDBValue(sharedSecretBytes, activation.getUserId(), activation.getActivationId());
        activation.setSharedSecret(sharedSecretDb.sharedSecretBase64());
        activation.setSharedSecretEncryption(sharedSecretDb.encryptionMode());
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