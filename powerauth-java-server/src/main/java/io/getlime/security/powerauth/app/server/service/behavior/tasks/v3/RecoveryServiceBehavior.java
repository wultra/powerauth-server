/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.v3.RecoveryCodeStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.RecoveryPukStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.*;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus;
import io.getlime.security.powerauth.app.server.database.model.*;
import io.getlime.security.powerauth.app.server.database.model.entity.*;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.database.repository.RecoveryCodeRepository;
import io.getlime.security.powerauth.app.server.database.repository.RecoveryConfigRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.ConfirmRecoveryRequestPayload;
import io.getlime.security.powerauth.app.server.service.model.response.ConfirmRecoveryResponsePayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.RecoveryInfo;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.PasswordHash;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * Behavior class implementing processes related to recovery codes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class RecoveryServiceBehavior {

    public static final int PUK_COUNT_MAX = 100;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(RecoveryServiceBehavior.class);

    // Autowired dependencies
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final RepositoryCatalogue repositoryCatalogue;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final RecoveryPrivateKeyConverter recoveryPrivateKeyConverter;

    // Business logic implementation classes
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final EciesFactory eciesFactory = new EciesFactory();

    // Helper classes
    private final ObjectMapper objectMapper;
    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();
    private final RecoveryCodeStatusConverter recoveryCodeStatusConverter = new RecoveryCodeStatusConverter();
    private final RecoveryPukStatusConverter recoveryPukStatusConverter = new RecoveryPukStatusConverter();
    private final RecoveryPukConverter recoveryPukConverter;


    @Autowired
    public RecoveryServiceBehavior(LocalizationProvider localizationProvider,
                                   PowerAuthServiceConfiguration powerAuthServiceConfiguration, RepositoryCatalogue repositoryCatalogue,
                                   ServerPrivateKeyConverter serverPrivateKeyConverter, ActivationServiceBehavior activationServiceBehavior,
                                   RecoveryPrivateKeyConverter recoveryPrivateKeyConverter, ObjectMapper objectMapper, RecoveryPukConverter recoveryPukConverter) {
        this.localizationProvider = localizationProvider;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.repositoryCatalogue = repositoryCatalogue;
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
        this.recoveryPrivateKeyConverter = recoveryPrivateKeyConverter;
        this.objectMapper = objectMapper;
        this.recoveryPukConverter = recoveryPukConverter;
    }

    /**
     * Create recovery code for secure recovery postcard. Recovery code status is set to CREATED.
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws GenericServiceException In case of any error.
     */
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request, KeyConvertor keyConversion) throws GenericServiceException {
        try {
            final Long applicationId = request.getApplicationId();
            final String userId = request.getUserId();
            final long pukCount = request.getPukCount();
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (!applicationOptional.isPresent()) {
                logger.warn("Application does not exist, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Check whether activation recovery and recovery postcard is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationId);
            if (recoveryConfigEntity == null || !recoveryConfigEntity.getActivationRecoveryEnabled()) {
                logger.warn("Activation recovery is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (!recoveryConfigEntity.getRecoveryPostcardEnabled()) {
                logger.warn("Activation recovery using recovery postcard is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            if (recoveryConfigEntity.getRecoveryPostcardPrivateKeyBase64() == null
                    || recoveryConfigEntity.getRemotePostcardPublicKeyBase64() == null) {
                logger.error("Missing key when deriving shared secret key for recovery code, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_RECOVERY_CONFIGURATION);
            }

            // Check whether user has any recovery code related to postcard (no activationId) in state CREATED or ACTIVE,
            // in this case the recovery code needs to be revoked first.
            if ((recoveryConfigEntity.getActivationRecoveryEnabled() == null) || !recoveryConfigEntity.getAllowMultipleRecoveryCodes()) {
                List<RecoveryCodeEntity> existingRecoveryCodes = recoveryCodeRepository.findAllByApplicationIdAndUserId(applicationId, userId);
                for (RecoveryCodeEntity recoveryCodeEntity : existingRecoveryCodes) {
                    if (recoveryCodeEntity.getActivationId() == null
                            && (recoveryCodeEntity.getStatus() == RecoveryCodeStatus.CREATED || recoveryCodeEntity.getStatus() == RecoveryCodeStatus.ACTIVE)) {
                        logger.warn("Create recovery code failed because of existing recovery code, application ID: {}, user ID: {}", applicationId, userId);
                        // Rollback is not required, error occurs before writing to database
                        throw localizationProvider.buildExceptionForCode(ServiceError.RECOVERY_CODE_ALREADY_EXISTS);
                    }
                }
            }

            EncryptionMode encryptionMode = recoveryConfigEntity.getPrivateKeyEncryption();
            String recoveryPrivateKeyBase64 = recoveryConfigEntity.getRecoveryPostcardPrivateKeyBase64();
            final RecoveryPrivateKey recoveryPrivateKeyEncrypted = new RecoveryPrivateKey(encryptionMode, recoveryPrivateKeyBase64);
            String decryptedPrivateKey = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, applicationId);
            final byte[] privateKeyBytes = BaseEncoding.base64().decode(decryptedPrivateKey);
            final PrivateKey privateKey = keyConversion.convertBytesToPrivateKey(privateKeyBytes);
            final byte[] publicKeyBytes = BaseEncoding.base64().decode(recoveryConfigEntity.getRemotePostcardPublicKeyBase64());
            final PublicKey publicKey = keyConversion.convertBytesToPublicKey(publicKeyBytes);

            final SecretKey secretKey = keyGenerator.computeSharedKey(privateKey, publicKey, true);
            String recoveryCode = null;
            Map<Integer, String> puks = null;
            byte[] nonce = null;
            Map<Integer, Long> pukDerivationIndexes = null;

            for (int i = 0; i < powerAuthServiceConfiguration.getGenerateRecoveryCodeIterations(); i++) {
                RecoveryInfo recoveryInfo = identifierGenerator.generateRecoveryCode(secretKey, (int) pukCount, true);
                // Check that recovery code is unique
                boolean recoveryCodeExists = recoveryCodeRepository.getRecoveryCodeCount(applicationId, recoveryInfo.getRecoveryCode()) > 0;
                if (!recoveryCodeExists) {
                    recoveryCode = recoveryInfo.getRecoveryCode();
                    puks = recoveryInfo.getPuks();
                    nonce = recoveryInfo.getSeed().getNonce();
                    pukDerivationIndexes = recoveryInfo.getSeed().getPukDerivationIndexes();
                    break;
                }
            }

            // In case recovery code generation failed, throw an exception
            if (recoveryCode == null || puks == null || puks.size() != request.getPukCount() || nonce == null
                    || pukDerivationIndexes == null
                    || !puks.keySet().equals(pukDerivationIndexes.keySet())) {
                logger.error("Unable to generate recovery code");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_RECOVERY_CODE);
            }

            // Create and persist recovery code entity with PUKs
            final RecoveryCodeEntity recoveryCodeEntity = new RecoveryCodeEntity();
            recoveryCodeEntity.setUserId(userId);
            recoveryCodeEntity.setApplicationId(applicationId);
            // Recovery is related to user, not activation
            recoveryCodeEntity.setActivationId(null);
            recoveryCodeEntity.setFailedAttempts(0L);
            recoveryCodeEntity.setMaxFailedAttempts(powerAuthServiceConfiguration.getRecoveryMaxFailedAttempts());
            recoveryCodeEntity.setRecoveryCode(recoveryCode);
            recoveryCodeEntity.setStatus(RecoveryCodeStatus.CREATED);
            recoveryCodeEntity.setTimestampCreated(new Date());

            for (int i = 1; i <= puks.size(); i++) {
                String puk = puks.get(i);
                RecoveryPukEntity recoveryPukEntity = new RecoveryPukEntity();
                recoveryPukEntity.setPukIndex((long) i);
                String pukHash = PasswordHash.hash(puk.getBytes(StandardCharsets.UTF_8));
                RecoveryPuk recoveryPuk = recoveryPukConverter.toDBValue(pukHash, applicationId, userId, recoveryCode, recoveryPukEntity.getPukIndex());
                recoveryPukEntity.setPuk(recoveryPuk.getPukHash());
                recoveryPukEntity.setPukEncryption(recoveryPuk.getEncryptionMode());
                recoveryPukEntity.setStatus(RecoveryPukStatus.VALID);
                recoveryPukEntity.setRecoveryCode(recoveryCodeEntity);
                recoveryCodeEntity.getRecoveryPuks().add(recoveryPukEntity);
            }

            recoveryCodeRepository.save(recoveryCodeEntity);

            CreateRecoveryCodeResponse response = new CreateRecoveryCodeResponse();
            response.setNonce(BaseEncoding.base64().encode(nonce));
            response.setUserId(userId);
            response.setRecoveryCodeId(recoveryCodeEntity.getId());
            response.setRecoveryCodeMasked(recoveryCodeEntity.getRecoveryCodeMasked());
            response.setStatus(com.wultra.security.powerauth.client.v3.RecoveryCodeStatus.CREATED);
            List<CreateRecoveryCodeResponse.Puks> pukListResponse = response.getPuks();
            for (int i = 1; i <= pukDerivationIndexes.size(); i++) {
                Long pukDerivationIndex = pukDerivationIndexes.get(i);
                CreateRecoveryCodeResponse.Puks pukResponse = new CreateRecoveryCodeResponse.Puks();
                pukResponse.setPukIndex(i);
                pukResponse.setPukDerivationIndex(pukDerivationIndex);
                pukResponse.setStatus(com.wultra.security.powerauth.client.v3.RecoveryPukStatus.VALID);
                pukListResponse.add(pukResponse);
            }
            return response;
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Confirm recovery code received via recovery postcard.
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws GenericServiceException In case of any error.
     */
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request, KeyConvertor keyConversion) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();
            final String nonce = request.getNonce();

            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            // Lookup the activation
            final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithoutLock(activationId);
            if (activation == null) {
                logger.warn("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Check whether activation recovery is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(activation.getApplication().getId());
            if (recoveryConfigEntity == null || !recoveryConfigEntity.getActivationRecoveryEnabled()) {
                logger.warn("Activation recovery is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Check if the activation is in ACTIVE state
            if (!io.getlime.security.powerauth.app.server.database.model.ActivationStatus.ACTIVE.equals(activation.getActivationStatus())) {
                logger.warn("Activation is not ACTIVE, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);
            final byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(serverPrivateKeyBase64);
            final PrivateKey serverPrivateKey = keyConversion.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get application secret and transport key used in sharedInfo2 parameter of ECIES
            final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(applicationKey);
            final byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
            final byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConversion.convertSharedSecretKeyToBytes(transportKey);

            // Get decryptor for the activation
            final EciesDecryptor decryptor = eciesFactory.getEciesDecryptorForActivation((ECPrivateKey) serverPrivateKey,
                    applicationSecret, transportKeyBytes, EciesSharedInfo1.CONFIRM_RECOVERY_CODE);

            // Decrypt request data
            final byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKey);
            final byte[] encryptedDataBytes = BaseEncoding.base64().decode(encryptedData);
            final byte[] macBytes = BaseEncoding.base64().decode(mac);
            final byte[] nonceBytes = nonce != null ? BaseEncoding.base64().decode(nonce) : null;
            final EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes, nonceBytes);
            final byte[] decryptedData = decryptor.decryptRequest(cryptogram);

            // Convert JSON data to confirm recovery request object
            final ConfirmRecoveryRequestPayload requestPayload = objectMapper.readValue(decryptedData, ConfirmRecoveryRequestPayload.class);

            // Validate recovery code
            final String recoveryCode = requestPayload.getRecoveryCode();
            if (recoveryCode == null || recoveryCode.isEmpty()) {
                logger.warn("Missing recovery code in confirm recovery, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (!identifierGenerator.validateActivationCode(recoveryCode)) {
                logger.warn("Invalid recovery code in confirm recovery, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Find recovery code entity
            final RecoveryCodeEntity recoveryCodeEntity = recoveryCodeRepository.findByApplicationIdAndRecoveryCode(applicationVersion.getApplication().getId(), recoveryCode);
            if (recoveryCodeEntity == null) {
                logger.warn("Recovery code does not exist in confirm recovery, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.RECOVERY_CODE_NOT_FOUND);
            }

            // Check that user ID from activation matches user ID from recovery entity
            if (!recoveryCodeEntity.getUserId().equals(activation.getUserId())) {
                logger.warn("User ID from activation does not match user ID from recovery code in confirm recovery, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final boolean inCreatedState = RecoveryCodeStatus.CREATED.equals(recoveryCodeEntity.getStatus());
            final boolean alreadyConfirmed = RecoveryCodeStatus.ACTIVE.equals(recoveryCodeEntity.getStatus());

            // Check recovery code status
            if (!inCreatedState && !alreadyConfirmed) {
                logger.warn("Recovery code is not in CREATED or ACTIVE state in confirm recovery, recovery code ID: {}", recoveryCodeEntity.getId());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Prepare response payload before writing to database to avoid rollbacks
            final ConfirmRecoveryResponsePayload responsePayload = new ConfirmRecoveryResponsePayload(alreadyConfirmed);

            // Convert response payload
            final byte[] responseBytes = objectMapper.writeValueAsBytes(responsePayload);

            // Encrypt response using previously created ECIES decryptor
            final EciesCryptogram eciesResponse = decryptor.encryptResponse(responseBytes);
            final String encryptedDataResponse = BaseEncoding.base64().encode(eciesResponse.getEncryptedData());
            final String macResponse = BaseEncoding.base64().encode(eciesResponse.getMac());

            // Return response
            final ConfirmRecoveryCodeResponse response = new ConfirmRecoveryCodeResponse();
            response.setActivationId(activationId);
            response.setUserId(recoveryCodeEntity.getUserId());
            response.setEncryptedData(encryptedDataResponse);
            response.setMac(macResponse);

            // Confirm recovery code and persist it
            if (inCreatedState) {
                recoveryCodeEntity.setStatus(RecoveryCodeStatus.ACTIVE);
                recoveryCodeEntity.setTimestampLastChange(new Date());
                recoveryCodeRepository.save(recoveryCodeEntity);
            }

            return response;

        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException | IOException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
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
     * Lookup recovery codes matching search criteria.
     * @param request Lookup recovery codes request.
     * @return Lookup recovery codes response.
     * @throws GenericServiceException In case of any error.
     */
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws GenericServiceException {
        final Long applicationId = request.getApplicationId();
        final String activationId = request.getActivationId();
        final String userId = request.getUserId();
        final RecoveryCodeStatus recoveryCodeStatus = recoveryCodeStatusConverter.convertTo(request.getRecoveryCodeStatus());
        final RecoveryPukStatus recoveryPukStatus = recoveryPukStatusConverter.convertTo(request.getRecoveryPukStatus());

        final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();

        final List<RecoveryCodeEntity> recoveryCodesEntities;
        if (applicationId != null && activationId != null) {
            if (userId != null) {
                // Application ID, user ID and activation ID are specified
                recoveryCodesEntities = recoveryCodeRepository.findAllRecoveryCodes(applicationId, userId, activationId);
            } else {
                // Application ID and activation ID are specified
                recoveryCodesEntities = recoveryCodeRepository.findAllByApplicationIdAndActivationId(applicationId, activationId);
            }
        } else if (applicationId != null && userId != null){
            // Application ID and user ID are specified
            recoveryCodesEntities = recoveryCodeRepository.findAllByApplicationIdAndUserId(applicationId, userId);
        } else if (userId != null) {
            // User ID is specified
            recoveryCodesEntities = recoveryCodeRepository.findAllByUserId(userId);
        }  else if (activationId != null) {
            // Activation ID is specified
            recoveryCodesEntities = recoveryCodeRepository.findAllByActivationId(activationId);
        } else {
            // Only application ID is specified, such request is not allowed
            logger.warn("Invalid request for lookup of recovery codes");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Filter recovery codes by recovery code status
        final Set<RecoveryCodeEntity> recoveryCodesToRemove = new LinkedHashSet<>();
        if (recoveryCodeStatus != null) {
            for (RecoveryCodeEntity recoveryCodeEntity : recoveryCodesEntities) {
                if (!recoveryCodeStatus.equals(recoveryCodeEntity.getStatus())) {
                    recoveryCodesToRemove.add(recoveryCodeEntity);
                }
            }
        }

        // Filter recovery PUKs by recovery PUK status, remove recovery codes with no remaining PUKs
        if (recoveryPukStatus != null) {
            for (RecoveryCodeEntity recoveryCodeEntity : recoveryCodesEntities) {
                final Set<RecoveryPukEntity> recoveryPuksToRemove = new LinkedHashSet<>();
                for (RecoveryPukEntity recoveryPukEntity : recoveryCodeEntity.getRecoveryPuks()) {
                    if (!recoveryPukStatus.equals(recoveryPukEntity.getStatus())) {
                        recoveryPuksToRemove.add(recoveryPukEntity);
                    }
                }
                recoveryCodeEntity.getRecoveryPuks().removeAll(recoveryPuksToRemove);
                // Check whether recovery code has any PUKs left, if not, remove it
                if (recoveryCodeEntity.getRecoveryPuks().isEmpty()) {
                    recoveryCodesToRemove.add(recoveryCodeEntity);
                }
            }
        }

        // Remove filtered out recovery codes
        recoveryCodesEntities.removeAll(recoveryCodesToRemove);

        LookupRecoveryCodesResponse response = new LookupRecoveryCodesResponse();
        List<LookupRecoveryCodesResponse.RecoveryCodes> recoveryCodes = response.getRecoveryCodes();
        for (RecoveryCodeEntity recoveryCodeEntity: recoveryCodesEntities) {
            LookupRecoveryCodesResponse.RecoveryCodes recoveryCode = new LookupRecoveryCodesResponse.RecoveryCodes();
            recoveryCode.setRecoveryCodeId(recoveryCodeEntity.getId());
            recoveryCode.setRecoveryCodeMasked(recoveryCodeEntity.getRecoveryCodeMasked());
            recoveryCode.setApplicationId(recoveryCodeEntity.getApplicationId());
            recoveryCode.setUserId(recoveryCodeEntity.getUserId());
            recoveryCode.setActivationId(recoveryCodeEntity.getActivationId());
            recoveryCode.setStatus(recoveryCodeStatusConverter.convertFrom(recoveryCodeEntity.getStatus()));
            for (RecoveryPukEntity recoveryPukEntity: recoveryCodeEntity.getRecoveryPuks()) {
                LookupRecoveryCodesResponse.RecoveryCodes.Puks puk = new LookupRecoveryCodesResponse.RecoveryCodes.Puks();
                puk.setStatus(recoveryPukStatusConverter.convertFrom(recoveryPukEntity.getStatus()));
                puk.setPukIndex(recoveryPukEntity.getPukIndex());
                recoveryCode.getPuks().add(puk);
            }
            recoveryCodes.add(recoveryCode);
        }
        return response;
    }

    /**
     * Revoke recovery codes.
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     * @throws GenericServiceException In case of any error.
     */
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws GenericServiceException {
        final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();

        final List<Long> recoveryCodeIds = request.getRecoveryCodeIds();
        for (Long recoveryCodeId : recoveryCodeIds) {
            if (recoveryCodeId == null || recoveryCodeId < 0L) {
                logger.warn("Invalid revoke recovery codes request");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
        }

        int revokedCount = 0;
        for (Long recoveryCodeId : recoveryCodeIds) {
            Optional<RecoveryCodeEntity> recoveryCodeOptional = recoveryCodeRepository.findById(recoveryCodeId);
            if (!recoveryCodeOptional.isPresent()) {
                // Silently ignore invalid recovery code IDs
                continue;
            }
            RecoveryCodeEntity recoveryCode = recoveryCodeOptional.get();
            if (!RecoveryCodeStatus.REVOKED.equals(recoveryCode.getStatus())) {
                // Revoke recovery code and update status in database
                recoveryCode.setStatus(RecoveryCodeStatus.REVOKED);
                recoveryCode.setTimestampLastChange(new Date());
                // Change status of PUKs with status VALID to INVALID
                for (RecoveryPukEntity puk : recoveryCode.getRecoveryPuks()) {
                    if (RecoveryPukStatus.VALID.equals(puk.getStatus())) {
                        puk.setStatus(RecoveryPukStatus.INVALID);
                        puk.setTimestampLastChange(new Date());
                    }
                }
                recoveryCodeRepository.save(recoveryCode);
                revokedCount++;
            }
        }

        final RevokeRecoveryCodesResponse response = new RevokeRecoveryCodesResponse();
        // At least one recovery code was revoked
        response.setRevoked(revokedCount > 0);
        return response;
    }

    /**
     * Get recovery configuration.
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws GenericServiceException In case of any error.
     */
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws GenericServiceException {
        long applicationId = request.getApplicationId();
        final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
        final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();
        final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
        if (!applicationOptional.isPresent()) {
            logger.warn("Application does not exist, application ID: {}", applicationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationId);
        if (recoveryConfigEntity == null) {
            // Configuration does not exist yet, create it
            recoveryConfigEntity = new RecoveryConfigEntity();
            recoveryConfigEntity.setApplication(applicationOptional.get());
            recoveryConfigEntity.setActivationRecoveryEnabled(false);
            recoveryConfigEntity.setRecoveryPostcardEnabled(false);
            recoveryConfigEntity.setAllowMultipleRecoveryCodes(false);
            recoveryConfigEntity.setPrivateKeyEncryption(EncryptionMode.NO_ENCRYPTION);
            recoveryConfigRepository.save(recoveryConfigEntity);
        }
        GetRecoveryConfigResponse response = new GetRecoveryConfigResponse();
        response.setApplicationId(applicationId);
        response.setActivationRecoveryEnabled(recoveryConfigEntity.getActivationRecoveryEnabled());
        response.setRecoveryPostcardEnabled(recoveryConfigEntity.getRecoveryPostcardEnabled());
        response.setAllowMultipleRecoveryCodes(recoveryConfigEntity.getAllowMultipleRecoveryCodes());
        response.setPostcardPublicKey(recoveryConfigEntity.getRecoveryPostcardPublicKeyBase64());
        response.setRemotePostcardPublicKey(recoveryConfigEntity.getRemotePostcardPublicKeyBase64());
        return response;
    }

    /**
     * Update recovery configuration.
     * @param request Update recovery configuration request.
     * @param keyConversion Key convertor.
     * @return Update recovery configuration response.
     * @throws GenericServiceException In case of any error.
     */
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request, KeyConvertor keyConversion) throws GenericServiceException {
        try {
            long applicationId = request.getApplicationId();
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();
            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (!applicationOptional.isPresent()) {
                logger.warn("Application does not exist, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationId);
            if (recoveryConfigEntity == null) {
                // Configuration does not exist yet, create it
                recoveryConfigEntity = new RecoveryConfigEntity();
                recoveryConfigEntity.setApplication(applicationOptional.get());
                recoveryConfigEntity.setPrivateKeyEncryption(EncryptionMode.NO_ENCRYPTION);
            }
            if (request.isRecoveryPostcardEnabled() && recoveryConfigEntity.getRecoveryPostcardPrivateKeyBase64() == null) {
                // Private key does not exist, generate key pair and persist it
                KeyGenerator keyGen = new KeyGenerator();
                KeyPair kp = keyGen.generateKeyPair();
                PrivateKey privateKey = kp.getPrivate();
                PublicKey publicKey = kp.getPublic();
                byte[] privateKeyBytes = keyConversion.convertPrivateKeyToBytes(privateKey);
                byte[] publicKeyBytes = keyConversion.convertPublicKeyToBytes(publicKey);
                String publicKeyBase64 = BaseEncoding.base64().encode(publicKeyBytes);

                RecoveryPrivateKey recoveryPrivateKey = recoveryPrivateKeyConverter.toDBValue(privateKeyBytes, applicationId);
                recoveryConfigEntity.setRecoveryPostcardPrivateKeyBase64(recoveryPrivateKey.getRecoveryPrivateKeyBase64());
                recoveryConfigEntity.setPrivateKeyEncryption(recoveryPrivateKey.getEncryptionMode());
                recoveryConfigEntity.setRecoveryPostcardPublicKeyBase64(publicKeyBase64);
            }
            recoveryConfigEntity.setActivationRecoveryEnabled(request.isActivationRecoveryEnabled());
            recoveryConfigEntity.setRecoveryPostcardEnabled(request.isRecoveryPostcardEnabled());
            recoveryConfigEntity.setAllowMultipleRecoveryCodes(request.isAllowMultipleRecoveryCodes());
            if (request.getRemotePostcardPublicKey() != null) {
                recoveryConfigEntity.setRemotePostcardPublicKeyBase64(request.getRemotePostcardPublicKey());
                if (request.getRemotePostcardPublicKey().isEmpty()) {
                    // Empty value is used to remove the remote postcard public key
                    recoveryConfigEntity.setRemotePostcardPublicKeyBase64(null);
                }
            }
            recoveryConfigRepository.save(recoveryConfigEntity);
            UpdateRecoveryConfigResponse response = new UpdateRecoveryConfigResponse();
            response.setUpdated(true);
            return response;
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }
}
