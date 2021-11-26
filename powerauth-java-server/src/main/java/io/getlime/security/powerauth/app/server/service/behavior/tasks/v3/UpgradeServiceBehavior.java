/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.v3.CommitUpgradeRequest;
import com.wultra.security.powerauth.client.v3.CommitUpgradeResponse;
import com.wultra.security.powerauth.client.v3.StartUpgradeRequest;
import com.wultra.security.powerauth.client.v3.StartUpgradeResponse;
import io.getlime.security.powerauth.app.server.converter.v3.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.response.UpgradeResponsePayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Behavior class implementing the activation upgrade process.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class UpgradeServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;

    // Helper classes
    private final EciesFactory eciesFactory = new EciesFactory();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final ObjectMapper objectMapper;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(UpgradeServiceBehavior.class);

    @Autowired
    public UpgradeServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider, ServerPrivateKeyConverter serverPrivateKeyConverter, ObjectMapper objectMapper) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
        this.objectMapper = objectMapper;
    }

    /**
     * Start upgrade of activation to version 3.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws GenericServiceException In case upgrade fails.
     */
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws GenericServiceException{
        final String activationId = request.getActivationId();
        final String applicationKey = request.getApplicationKey();
        final String ephemeralPublicKey = request.getEphemeralPublicKey();
        final String encryptedData = request.getEncryptedData();
        final String mac = request.getMac();
        final String nonce = request.getNonce();
        // Verify input data
        if (activationId == null || applicationKey == null || ephemeralPublicKey == null || encryptedData == null || mac == null) {
            logger.warn("Invalid start upgrade request");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }

        byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKey);
        byte[] encryptedDataBytes = BaseEncoding.base64().decode(encryptedData);
        byte[] macBytes = BaseEncoding.base64().decode(mac);
        byte[] nonceBytes = nonce != null ? BaseEncoding.base64().decode(nonce) : null;
        final EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes, nonceBytes);

        // Lookup the activation
        final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // Check if the activation is in correct state and version is 2
        if (!ActivationStatus.ACTIVE.equals(activation.getActivationStatus()) || activation.getVersion() != 2) {
            logger.info("Activation state is invalid, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }

        // Do not verify ctr_data, upgrade response may not be delivered to client, so the client may retry the upgrade

        // Lookup the application version and check that it is supported
        final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(request.getApplicationKey());
        if (applicationVersion == null || !applicationVersion.getSupported()) {
            logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        try {
            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);
            byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(serverPrivateKeyBase64);

            // KEY_SERVER_PRIVATE is used in Crypto version 3.0 for ECIES, note that in version 2.0 KEY_SERVER_MASTER_PRIVATE is used
            final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get ECIES parameters
            byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
            byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
            PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            byte[] transportKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(transportKey);

            // Get decryptor for the application
            final EciesDecryptor decryptor = eciesFactory.getEciesDecryptorForActivation((ECPrivateKey) serverPrivateKey, applicationSecret, transportKeyBytes, EciesSharedInfo1.UPGRADE);

            // Try to decrypt request data, the data must not be empty. Currently only '{}' is sent in request data.
            final byte[] decryptedData = decryptor.decryptRequest(cryptogram);
            if (decryptedData.length == 0) {
                logger.warn("Invalid decrypted request data");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Request is valid, generate hash based counter if it does not exist yet
            final String ctrDataBase64;
            boolean activationShouldBeSaved = false;
            if (activation.getCtrDataBase64() == null) {
                // Initialize hash based counter
                final HashBasedCounter hashBasedCounter = new HashBasedCounter();
                byte[] ctrData = hashBasedCounter.init();
                ctrDataBase64 = BaseEncoding.base64().encode(ctrData);
                activation.setCtrDataBase64(ctrDataBase64);

                // Store activation with generated ctr_data in database
                activationShouldBeSaved = true;
            } else {
                // Hash based counter already exists, use the stored value.
                // Concurrency is handled using @Lock(LockModeType.PESSIMISTIC_WRITE).
                ctrDataBase64 = activation.getCtrDataBase64();
            }

            // Create response payload
            final UpgradeResponsePayload payload = new UpgradeResponsePayload(ctrDataBase64);

            // Encrypt response payload and return it
            final byte[] payloadBytes = objectMapper.writeValueAsBytes(payload);

            final EciesCryptogram cryptogramResponse = decryptor.encryptResponse(payloadBytes);
            final StartUpgradeResponse response = new StartUpgradeResponse();
            response.setEncryptedData(BaseEncoding.base64().encode(cryptogramResponse.getEncryptedData()));
            response.setMac(BaseEncoding.base64().encode(cryptogramResponse.getMac()));

            // Save activation as last step to avoid rollbacks
            if (activationShouldBeSaved) {
                repositoryCatalogue.getActivationRepository().save(activation);
            }

            return response;
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, serialization errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }

    }

    /**
     * Commit upgrade of activation to version 3.
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws GenericServiceException In case upgrade fails.
     */
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws GenericServiceException {
        final String activationId = request.getActivationId();
        final String applicationKey = request.getApplicationKey();

        // Verify input data
        if (activationId == null || applicationKey == null) {
            logger.warn("Invalid commit upgrade request");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }

        // Lookup the activation
        final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // Check if the activation is in correct state and version is 2
        if (!ActivationStatus.ACTIVE.equals(activation.getActivationStatus()) || activation.getVersion() != 2) {
            logger.info("Activation state is invalid, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }

        // Check if the activation hash based counter was generated (upgrade has been started)
        if (activation.getCtrDataBase64() == null) {
            logger.warn("Activation counter data is missing, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }

        // Lookup the application version and check that it is supported
        final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(request.getApplicationKey());
        if (applicationVersion == null || !applicationVersion.getSupported()) {
            logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        // Upgrade activation to version 3
        activation.setVersion(3);

        // Save update activation
        repositoryCatalogue.getActivationRepository().save(activation);

        final CommitUpgradeResponse response = new CommitUpgradeResponse();
        response.setCommitted(true);
        return response;
    }
}
