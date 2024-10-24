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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.request.CommitUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse;
import com.wultra.security.powerauth.client.model.response.StartUpgradeResponse;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.response.UpgradeResponsePayload;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import io.getlime.security.powerauth.app.server.service.replay.ReplayVerificationService;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;

/**
 * Behavior class implementing the activation upgrade process.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class UpgradeServiceBehavior {

    private final ActivationQueryService activationQueryService;
    private final LocalizationProvider localizationProvider;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final ReplayVerificationService replayVerificationService;
    private final ActivationContextValidator activationValidator;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final ActivationRepository activationRepository;

    // Helper classes
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final ObjectMapper objectMapper;
    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final TemporaryKeyBehavior temporaryKeyBehavior;

    /**
     * Start upgrade of activation to version 3.
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws GenericServiceException In case upgrade fails.
     */
    @Transactional
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws GenericServiceException{
        try {
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String protocolVersion = request.getProtocolVersion();
            final String temporaryKeyId = request.getTemporaryKeyId();

            if (activationId == null || applicationKey == null) {
                logger.warn("Invalid request parameters in method startUpgrade");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Build and validate encrypted request
            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );
            if (!encryptorFactory.getRequestResponseValidator(protocolVersion).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid start upgrade request");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
            }

            if (encryptedRequest.getTimestamp() != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_ACTIVATION_SCOPE,
                        new Date(encryptedRequest.getTimestamp()),
                        encryptedRequest.getEphemeralPublicKey(),
                        encryptedRequest.getNonce(),
                        activationId,
                        request.getProtocolVersion());
            }

            // Lookup the activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            activationValidator.validateVersion(activation.getVersion(), 2, activationId, localizationProvider);

            // Do not verify ctr_data, upgrade response may not be delivered to client, so the client may retry the upgrade

            // Lookup the application version and check that it is supported
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(request.getApplicationKey());
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);
            final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);

            // KEY_SERVER_PRIVATE is used in Crypto version 3.0 for ECIES, note that in version 2.0 KEY_SERVER_MASTER_PRIVATE is used
            final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get ECIES parameters
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(transportKey);

            // Get temporary or server key, depending on availability
            final PrivateKey encryptorPrivateKey = (temporaryKeyId != null) ? temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, applicationKey, activationId) : serverPrivateKey;

            // Get server encryptor
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.UPGRADE,
                    new EncryptorParameters(protocolVersion, applicationKey, activationId, temporaryKeyId),
                    new ServerEncryptorSecrets(encryptorPrivateKey, applicationVersion.getApplicationSecret(), transportKeyBytes)
            );

            // Try to decrypt request data, the data must not be empty. Currently only '{}' is sent in request data. Ignore result of decryption.
            serverEncryptor.decryptRequest(encryptedRequest);

            // Request is valid, generate hash based counter if it does not exist yet
            final String ctrDataBase64;
            boolean activationShouldBeSaved = false;
            if (activation.getCtrDataBase64() == null) {
                // Initialize hash based counter
                final HashBasedCounter hashBasedCounter = new HashBasedCounter();
                final byte[] ctrData = hashBasedCounter.init();
                ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);
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

            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(payloadBytes);

            final StartUpgradeResponse response = new StartUpgradeResponse();
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());

            // Save activation as last step to avoid rollbacks
            if (activationShouldBeSaved) {
                activationRepository.save(activation);
            }

            return response;
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EncryptorException ex) {
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
     * Commit upgrade of activation to version 3.
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws GenericServiceException In case upgrade fails.
     */
    @Transactional
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();

            // Verify input data
            if (activationId == null || applicationKey == null) {
                logger.warn("Invalid commit upgrade request");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
            }

            // Lookup the activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            activationValidator.validateVersion(activation.getVersion(), 2, activationId, localizationProvider);

            // Check if the activation hash based counter was generated (upgrade has been started)
            if (activation.getCtrDataBase64() == null) {
                logger.warn("Activation counter data is missing, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Lookup the application version and check that it is supported
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(request.getApplicationKey());
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            // Upgrade activation to version 3
            activation.setVersion(3);

            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, null, AdditionalInformation.Reason.ACTIVATION_VERSION_CHANGED);

            final CommitUpgradeResponse response = new CommitUpgradeResponse();
            response.setCommitted(true);
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

}
