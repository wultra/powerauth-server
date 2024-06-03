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
import com.wultra.security.powerauth.client.model.entity.RecoveryCode;
import com.wultra.security.powerauth.client.model.entity.RecoveryCodePuk;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.*;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPuk;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.*;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.enumeration.RecoveryCodeStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.RecoveryPukStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.database.repository.RecoveryCodeRepository;
import io.getlime.security.powerauth.app.server.database.repository.RecoveryConfigRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.ConfirmRecoveryRequestPayload;
import io.getlime.security.powerauth.app.server.service.model.response.ConfirmRecoveryResponsePayload;
import io.getlime.security.powerauth.app.server.service.replay.ReplayVerificationService;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.RecoveryInfo;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.PasswordHash;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * Behavior class implementing processes related to recovery codes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class RecoveryServiceBehavior {

    public static final int PUK_COUNT_MAX = 100;

    // Autowired dependencies
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final RepositoryCatalogue repositoryCatalogue;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final RecoveryPrivateKeyConverter recoveryPrivateKeyConverter;
    private final ReplayVerificationService replayVerificationService;
    private final ActivationContextValidator activationValidator;

    // Business logic implementation classes
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();

    // Helper classes
    private final ObjectMapper objectMapper;
    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();
    private final RecoveryCodeStatusConverter recoveryCodeStatusConverter = new RecoveryCodeStatusConverter();
    private final RecoveryPukStatusConverter recoveryPukStatusConverter = new RecoveryPukStatusConverter();
    private final RecoveryPukConverter recoveryPukConverter;


    @Autowired
    public RecoveryServiceBehavior(LocalizationProvider localizationProvider,
                                   PowerAuthServiceConfiguration powerAuthServiceConfiguration, RepositoryCatalogue repositoryCatalogue,
                                   ServerPrivateKeyConverter serverPrivateKeyConverter, RecoveryPrivateKeyConverter recoveryPrivateKeyConverter,
                                   ReplayVerificationService replayVerificationService, ActivationContextValidator activationValidator, ObjectMapper objectMapper, RecoveryPukConverter recoveryPukConverter) {
        this.localizationProvider = localizationProvider;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.repositoryCatalogue = repositoryCatalogue;
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
        this.recoveryPrivateKeyConverter = recoveryPrivateKeyConverter;
        this.replayVerificationService = replayVerificationService;
        this.activationValidator = activationValidator;
        this.objectMapper = objectMapper;
        this.recoveryPukConverter = recoveryPukConverter;
    }

    /**
     * Create recovery code for secure recovery postcard. Recovery code status is set to CREATED.
     * @param request Create recovery code request.
     * @return Create recovery code response.
     * @throws GenericServiceException In case of any error.
     */
    @Transactional
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String userId = request.getUserId();
            final long pukCount = request.getPukCount();

            if (applicationId == null || userId == null || pukCount < 1 || pukCount > RecoveryServiceBehavior.PUK_COUNT_MAX) {
                logger.warn("Invalid request parameters in method createRecoveryCode");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (applicationOptional.isEmpty()) {
                logger.warn("Application does not exist, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ApplicationEntity applicationEntity = applicationOptional.get();

            // Check whether activation recovery and recovery postcard is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationEntity.getId());
            if (recoveryConfigEntity == null || !recoveryConfigEntity.isActivationRecoveryEnabled()) {
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
            if (!recoveryConfigEntity.getAllowMultipleRecoveryCodes()) {
                List<RecoveryCodeEntity> existingRecoveryCodes = recoveryCodeRepository.findAllByApplicationIdAndUserId(applicationEntity.getId(), userId);
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
            String decryptedPrivateKey = recoveryPrivateKeyConverter.fromDBValue(recoveryPrivateKeyEncrypted, applicationEntity.getRid());
            final byte[] privateKeyBytes = Base64.getDecoder().decode(decryptedPrivateKey);
            final PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(privateKeyBytes);
            final byte[] publicKeyBytes = Base64.getDecoder().decode(recoveryConfigEntity.getRemotePostcardPublicKeyBase64());
            final PublicKey publicKey = keyConvertor.convertBytesToPublicKey(publicKeyBytes);

            final SecretKey secretKey = keyGenerator.computeSharedKey(privateKey, publicKey, true);
            String recoveryCode = null;
            Map<Integer, String> puks = null;
            byte[] nonce = null;
            Map<Integer, Long> pukDerivationIndexes = null;

            for (int i = 0; i < powerAuthServiceConfiguration.getGenerateRecoveryCodeIterations(); i++) {
                RecoveryInfo recoveryInfo = identifierGenerator.generateRecoveryCode(secretKey, (int) pukCount, true);
                // Check that recovery code is unique
                boolean recoveryCodeExists = recoveryCodeRepository.recoveryCodeCount(applicationEntity.getId(), recoveryInfo.getRecoveryCode()) > 0;
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
            recoveryCodeEntity.setApplication(applicationEntity);
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
                RecoveryPuk recoveryPuk = recoveryPukConverter.toDBValue(pukHash, applicationEntity.getRid(), userId, recoveryCode, recoveryPukEntity.getPukIndex());
                recoveryPukEntity.setPuk(recoveryPuk.pukHash());
                recoveryPukEntity.setPukEncryption(recoveryPuk.encryptionMode());
                recoveryPukEntity.setStatus(RecoveryPukStatus.VALID);
                recoveryPukEntity.setRecoveryCode(recoveryCodeEntity);
                recoveryCodeEntity.getRecoveryPuks().add(recoveryPukEntity);
            }

            recoveryCodeRepository.save(recoveryCodeEntity);

            CreateRecoveryCodeResponse response = new CreateRecoveryCodeResponse();
            response.setNonce(Base64.getEncoder().encodeToString(nonce));
            response.setUserId(userId);
            response.setRecoveryCodeId(recoveryCodeEntity.getId());
            response.setRecoveryCodeMasked(recoveryCodeEntity.getRecoveryCodeMasked());
            response.setStatus(com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus.CREATED);
            List<RecoveryCodePuk> pukListResponse = response.getPuks();
            for (int i = 1; i <= pukDerivationIndexes.size(); i++) {
                Long pukDerivationIndex = pukDerivationIndexes.get(i);
                RecoveryCodePuk pukResponse = new RecoveryCodePuk();
                pukResponse.setPukIndex(i);
                pukResponse.setPukDerivationIndex(pukDerivationIndex);
                pukResponse.setStatus(com.wultra.security.powerauth.client.model.enumeration.RecoveryPukStatus.VALID);
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
     * Confirm recovery code received via recovery postcard.
     * @param request Confirm recovery code request.
     * @return Confirm recovery code response.
     * @throws GenericServiceException In case of any error.
     */
    @Transactional
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();

            if (activationId == null || applicationKey == null) {
                logger.warn("Invalid request parameters in method confirmRecoveryCode");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            // Lookup the activation
            final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithoutLock(activationId);
            if (activation == null) {
                logger.warn("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Build and validate encrypted request
            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );
            if (!encryptorFactory.getRequestResponseValidator(request.getProtocolVersion()).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid encrypted request: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Check whether activation recovery is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(activation.getApplication().getId());
            if (recoveryConfigEntity == null || !recoveryConfigEntity.isActivationRecoveryEnabled()) {
                logger.warn("Activation recovery is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);
            final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
            final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get application secret and transport key used in sharedInfo2 parameter of ECIES
            final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(applicationKey);

            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(transportKey);

            // Check ECIES request for replay attacks and persist unique value from request
            if (encryptedRequest.getTimestamp() != null) {
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_ACTIVATION_SCOPE,
                        new Date(request.getTimestamp()),
                        encryptedRequest.getEphemeralPublicKey(),
                        encryptedRequest.getNonce(),
                        activationId,
                        request.getProtocolVersion());
            }

            // Get server decryptor
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.CONFIRM_RECOVERY_CODE,
                    new EncryptorParameters(request.getProtocolVersion(), applicationKey, activationId),
                    new ServerEncryptorSecrets(serverPrivateKey, applicationVersion.getApplicationSecret(), transportKeyBytes)
            );
            // Decrypt request data
            final byte[] decryptedData = serverEncryptor.decryptRequest(encryptedRequest);

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

            // Encrypt response using server encryptor
            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(responseBytes);

            // Return response
            final ConfirmRecoveryCodeResponse response = new ConfirmRecoveryCodeResponse();
            response.setActivationId(activationId);
            response.setUserId(recoveryCodeEntity.getUserId());
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());

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
        } catch (EncryptorException | IOException ex) {
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
     * Lookup recovery codes matching search criteria.
     * @param request Lookup recovery codes request.
     * @return Lookup recovery codes response.
     * @throws GenericServiceException In case of any error.
     */
    @Transactional(readOnly = true)
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String userId = request.getUserId();
            final String activationId = request.getActivationId();

            if (applicationId == null && userId == null && activationId == null) {
                logger.warn("Invalid request parameters in method lookupRecoveryCodes");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final RecoveryCodeStatus recoveryCodeStatus = recoveryCodeStatusConverter.convertTo(request.getRecoveryCodeStatus());
            final RecoveryPukStatus recoveryPukStatus = recoveryPukStatusConverter.convertTo(request.getRecoveryPukStatus());

            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();

            // If an application was specified, validate it exists
            if (applicationId != null) {
                final Optional<ApplicationEntity> applicationEntityOptional = applicationRepository.findById(applicationId);
                if (applicationEntityOptional.isEmpty()) {
                    // Only application ID is specified, such request is not allowed
                    logger.warn("Invalid application specified for lookup of recovery codes: {}", applicationId);
                    // Rollback is not required, database is not used for writing
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                }
            }

            final List<RecoveryCodeEntity> recoveryCodesEntities;
            if (applicationId != null && activationId != null) {
                if (userId != null) {
                    // Application ID, user ID and activation ID are specified
                    recoveryCodesEntities = recoveryCodeRepository.findAllRecoveryCodes(applicationId, userId, activationId);
                } else {
                    // Application ID and activation ID are specified
                    recoveryCodesEntities = recoveryCodeRepository.findAllByApplicationIdAndActivationId(applicationId, activationId);
                }
            } else if (applicationId != null && userId != null) {
                // Application ID and user ID are specified
                recoveryCodesEntities = recoveryCodeRepository.findAllByApplicationIdAndUserId(applicationId, userId);
            } else if (userId != null) {
                // User ID is specified
                recoveryCodesEntities = recoveryCodeRepository.findAllByUserId(userId);
            } else if (activationId != null) {
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
            List<RecoveryCode> recoveryCodes = response.getRecoveryCodes();
            for (RecoveryCodeEntity recoveryCodeEntity : recoveryCodesEntities) {
                RecoveryCode recoveryCode = new RecoveryCode();
                recoveryCode.setRecoveryCodeId(recoveryCodeEntity.getId());
                recoveryCode.setRecoveryCodeMasked(recoveryCodeEntity.getRecoveryCodeMasked());
                recoveryCode.setApplicationId(recoveryCodeEntity.getApplication().getId());
                recoveryCode.setUserId(recoveryCodeEntity.getUserId());
                recoveryCode.setActivationId(recoveryCodeEntity.getActivationId());
                recoveryCode.setStatus(recoveryCodeStatusConverter.convertFrom(recoveryCodeEntity.getStatus()));
                for (RecoveryPukEntity recoveryPukEntity : recoveryCodeEntity.getRecoveryPuks()) {
                    RecoveryCodePuk puk = new RecoveryCodePuk();
                    puk.setStatus(recoveryPukStatusConverter.convertFrom(recoveryPukEntity.getStatus()));
                    puk.setPukIndex(recoveryPukEntity.getPukIndex());
                    recoveryCode.getPuks().add(puk);
                }
                recoveryCodes.add(recoveryCode);
            }
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
     * Revoke recovery codes.
     * @param request Revoke recovery codes request.
     * @return Revoke recovery codes response.
     * @throws GenericServiceException In case of any error.
     */
    @Transactional
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws GenericServiceException {
        try {
            if (request.getRecoveryCodeIds() == null || request.getRecoveryCodeIds().isEmpty()) {
                logger.warn("Invalid request parameters in method revokeRecoveryCodes");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

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
                if (recoveryCodeOptional.isEmpty()) {
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
     * Get recovery configuration.
     * @param request Get recovery configuration request.
     * @return Get recovery configuration response.
     * @throws GenericServiceException In case of any error.
     */
    @Transactional(readOnly = true)
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws GenericServiceException {
        try {
            String applicationId = request.getApplicationId();

            if (applicationId == null) {
                logger.warn("Invalid request parameter applicationId in method getRecoveryConfig");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();
            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (applicationOptional.isEmpty()) {
                logger.warn("Application does not exist, application ID: {}", applicationId);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ApplicationEntity applicationEntity = applicationOptional.get();
            RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationEntity.getId());
            if (recoveryConfigEntity == null) {
                // Configuration does not exist yet, create it
                recoveryConfigEntity = new RecoveryConfigEntity();
                recoveryConfigEntity.setApplication(applicationEntity);
                recoveryConfigEntity.setActivationRecoveryEnabled(false);
                recoveryConfigEntity.setRecoveryPostcardEnabled(false);
                recoveryConfigEntity.setAllowMultipleRecoveryCodes(false);
                recoveryConfigEntity.setPrivateKeyEncryption(EncryptionMode.NO_ENCRYPTION);
                recoveryConfigRepository.save(recoveryConfigEntity);
            }
            GetRecoveryConfigResponse response = new GetRecoveryConfigResponse();
            response.setApplicationId(applicationId);
            response.setActivationRecoveryEnabled(recoveryConfigEntity.isActivationRecoveryEnabled());
            response.setRecoveryPostcardEnabled(recoveryConfigEntity.getRecoveryPostcardEnabled());
            response.setAllowMultipleRecoveryCodes(Optional.ofNullable(recoveryConfigEntity.getAllowMultipleRecoveryCodes()).orElse(false));
            response.setPostcardPublicKey(recoveryConfigEntity.getRecoveryPostcardPublicKeyBase64());
            response.setRemotePostcardPublicKey(recoveryConfigEntity.getRemotePostcardPublicKeyBase64());
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
     * Update recovery configuration.
     * @param request Update recovery configuration request.
     * @return Update recovery configuration response.
     * @throws GenericServiceException In case of any error.
     */
    @Transactional
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws GenericServiceException {
        try {
            String applicationId = request.getApplicationId();
            if (applicationId == null) {
                logger.warn("Invalid request parameter applicationId in method updateRecoveryConfig");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();
            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (applicationOptional.isEmpty()) {
                logger.warn("Application does not exist, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ApplicationEntity applicationEntity = applicationOptional.get();
            RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationEntity.getId());
            if (recoveryConfigEntity == null) {
                // Configuration does not exist yet, create it
                recoveryConfigEntity = new RecoveryConfigEntity();
                recoveryConfigEntity.setApplication(applicationEntity);
                recoveryConfigEntity.setPrivateKeyEncryption(EncryptionMode.NO_ENCRYPTION);
            }
            if (request.isRecoveryPostcardEnabled() && recoveryConfigEntity.getRecoveryPostcardPrivateKeyBase64() == null) {
                // Private key does not exist, generate key pair and persist it
                KeyGenerator keyGen = new KeyGenerator();
                KeyPair kp = keyGen.generateKeyPair();
                PrivateKey privateKey = kp.getPrivate();
                PublicKey publicKey = kp.getPublic();
                byte[] privateKeyBytes = keyConvertor.convertPrivateKeyToBytes(privateKey);
                byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);
                String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);

                RecoveryPrivateKey recoveryPrivateKey = recoveryPrivateKeyConverter.toDBValue(privateKeyBytes, applicationEntity.getRid());
                recoveryConfigEntity.setRecoveryPostcardPrivateKeyBase64(recoveryPrivateKey.recoveryPrivateKeyBase64());
                recoveryConfigEntity.setPrivateKeyEncryption(recoveryPrivateKey.encryptionMode());
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
