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
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthPageableConfiguration;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.*;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPuk;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.*;
import io.getlime.security.powerauth.app.server.database.model.enumeration.*;
import io.getlime.security.powerauth.app.server.database.repository.*;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.exceptions.RollbackingServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ActivationRecovery;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.app.server.service.model.response.ActivationLayer2Response;
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
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.model.RecoveryInfo;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.PasswordHash;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Behavior class implementing processes related with activations. Used to move the
 * implementation outside of the main service implementation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class ActivationServiceBehavior {

    /**
     * Current PowerAuth protocol major version. Activations created with lower version will be upgraded to this version.
     */
    private static final byte POWERAUTH_PROTOCOL_VERSION = 0x3;

    // Minimum date for SQL timestamps: 01/01/1970 @ 12:00am (UTC)
    private static final Date MIN_TIMESTAMP = new Date(1L);

    // Maximum date for SQL timestamps: 01/01/9999 @ 12:00am (UTC)
    private static final Date MAX_TIMESTAMP = new Date(253370764800000L);

    private final RepositoryCatalogue repositoryCatalogue;

    private CallbackUrlBehavior callbackUrlBehavior;
    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private TemporaryKeyBehavior temporaryKeyBehavior;

    private LocalizationProvider localizationProvider;

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final PowerAuthPageableConfiguration powerAuthPageableConfiguration;

    private final ReplayVerificationService replayVerificationService;

    private final ActivationContextValidator activationValidator;

    private final ActivationQueryService activationQueryService;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final ActivationOtpValidationConverter activationOtpValidationConverter = new ActivationOtpValidationConverter();
    private final ActivationCommitPhaseConverter activationCommitPhaseConverter = new ActivationCommitPhaseConverter();
    private ServerPrivateKeyConverter serverPrivateKeyConverter;
    private RecoveryPukConverter recoveryPukConverter;

    // Helper classes
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final ObjectMapper objectMapper;
    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    @Autowired
    public ActivationServiceBehavior(RepositoryCatalogue repositoryCatalogue, PowerAuthServiceConfiguration powerAuthServiceConfiguration, PowerAuthPageableConfiguration powerAuthPageableConfiguration, ReplayVerificationService eciesReplayPersistenceService, ActivationContextValidator activationValidator, ActivationQueryService activationQueryService, ObjectMapper objectMapper) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.powerAuthPageableConfiguration = powerAuthPageableConfiguration;
        this.replayVerificationService = eciesReplayPersistenceService;
        this.activationValidator = activationValidator;
        this.activationQueryService = activationQueryService;
        this.objectMapper = objectMapper;
    }

    @Autowired
    public void setCallbackUrlBehavior(CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    @Autowired
    public void setTemporaryKeyBehavior(TemporaryKeyBehavior temporaryKeyBehavior) {
        this.temporaryKeyBehavior = temporaryKeyBehavior;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    @Autowired
    public void setActivationHistoryServiceBehavior(ActivationHistoryServiceBehavior activationHistoryServiceBehavior) {
        this.activationHistoryServiceBehavior = activationHistoryServiceBehavior;
    }

    @Autowired
    public void setServerPrivateKeyConverter(ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    @Autowired
    public void setRecoveryPukConverter(RecoveryPukConverter recoveryPukConverter) {
        this.recoveryPukConverter = recoveryPukConverter;
    }

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();

    /**
     * Deactivate the activation in CREATED or PENDING_COMMIT if it's activation expiration timestamp
     * is below the given timestamp.
     *
     * @param timestamp  Timestamp to check activations against.
     * @param activation Activation to check.
     */
    private void deactivatePendingActivation(Date timestamp, ActivationRecordEntity activation, boolean isActivationLocked) throws GenericServiceException {
        if ((activation.getActivationStatus() == ActivationStatus.CREATED || activation.getActivationStatus() == ActivationStatus.PENDING_COMMIT) && (timestamp.getTime() > activation.getTimestampActivationExpire().getTime())) {
            logger.info("Deactivating pending activation, activation ID: {}", activation.getActivationId());
            if (!isActivationLocked) {
                // Make sure activation is locked until the end of transaction in case it was not locked yet
                final String activationId = activation.getActivationId();
                activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                    logger.info("Activation not found, activation ID: {}", activationId);
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
                });
            }
            removeActivationInternal(activation, null, true);
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

    /**
     * Validate activation in prepare or create activation step: it should be in CREATED state, it should be linked to correct
     * application and the activation code should have valid length.
     *
     * @param activation Activation used in prepare activation step.
     * @param application Application used in prepare activation step.
     * @param rollbackInCaseOfError Whether transaction should be rolled back in case of validation error.
     * @throws GenericServiceException In case activation state is invalid.
     */
    private void validateCreatedActivation(ActivationRecordEntity activation, ApplicationEntity application, boolean rollbackInCaseOfError) throws GenericServiceException {
        // If there is no such activation or application does not match the activation application, fail validation
        if (activation == null
                || !ActivationStatus.CREATED.equals(activation.getActivationStatus())
                || !Objects.equals(activation.getApplication().getRid(), application.getRid())) {
            logger.info("Activation state is invalid, activation ID: {}", activation != null ? activation.getActivationId() : "unknown");
            if (rollbackInCaseOfError) {
                // Rollback is used during createActivation and createActivationUsingRecoveryCode, because activation has just been initialized and it is invalid
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            } else {
                // Regular exception is used during prepareActivation
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
        }

        // Make sure activation code has 23 characters
        if (activation.getActivationCode().length() != 23) {
            logger.warn("Activation code is invalid, activation ID: {}", activation.getActivationId());
            if (rollbackInCaseOfError) {
                // Rollback is used during createActivation and createActivationUsingRecoveryCode, because activation has just been initialized and it is invalid
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            } else {
                // Regular exception is used during prepareActivation
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
        }
    }

    /**
     * Fetch a paginated list of activations for a given application ID and user ID.
     *
     * @param request Request for activation list.
     * @return A {@link GetActivationListForUserResponse} object that includes the list of matching activations. Each
     *         activation is represented as an {@link Activation} object. The response also includes the user ID associated
     *         with the activations.
     */
    @Transactional
    public GetActivationListForUserResponse getActivationList(GetActivationListForUserRequest request) throws GenericServiceException {
        try {
            final String userId = request.getUserId();
            final String applicationId = request.getApplicationId();
            final Set<ActivationProtocol> protocols = request.getProtocols();
            final int pageNumber = request.getPageNumber() != null ? request.getPageNumber() : powerAuthPageableConfiguration.defaultPageNumber();
            final int pageSize = request.getPageSize() != null ? request.getPageSize() : powerAuthPageableConfiguration.defaultPageSize();
            final Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("timestampCreated").descending());
            final Set<ActivationStatus> activationStatuses = convert(request.getActivationStatuses());

            if (userId == null) {
                logger.warn("Invalid request parameter userId in method getActivationListForUser");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Generate timestamp in advance
            final Date timestamp = new Date();

            final List<ActivationRecordEntity> activationsList;
            if (applicationId == null) {
                activationsList = activationQueryService.findByUserIdAndActivationStatusIn(userId, activationStatuses, pageable);
            } else {
                activationsList = activationQueryService.findByApplicationIdAndUserIdAndActivationStatusIn(applicationId, userId, activationStatuses, pageable);
            }

            final GetActivationListForUserResponse response = new GetActivationListForUserResponse();
            response.setUserId(userId);
            if (activationsList != null) {
                for (ActivationRecordEntity activation : activationsList) {

                    deactivatePendingActivation(timestamp, activation, false);

                    if (!protocols.contains(convert(activation.getProtocol()))) { // skip authenticators that were not required
                        continue;
                    }

                    // Map between database object and service objects
                    final Activation activationServiceItem = new Activation();
                    activationServiceItem.setActivationId(activation.getActivationId());
                    activationServiceItem.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    activationServiceItem.setBlockedReason(activation.getBlockedReason());
                    activationServiceItem.setExternalId(activation.getExternalId());
                    activationServiceItem.setActivationName(activation.getActivationName());
                    activationServiceItem.setExtras(activation.getExtras());
                    activationServiceItem.setProtocol(convert(activation.getProtocol()));
                    activationServiceItem.setPlatform(activation.getPlatform());
                    activationServiceItem.setDeviceInfo(activation.getDeviceInfo());
                    activationServiceItem.getActivationFlags().addAll(activation.getFlags());
                    activationServiceItem.setTimestampCreated(activation.getTimestampCreated());
                    activationServiceItem.setTimestampLastUsed(activation.getTimestampLastUsed());
                    activationServiceItem.setTimestampLastChange(activation.getTimestampLastChange());
                    activationServiceItem.setUserId(activation.getUserId());
                    activationServiceItem.setApplicationId(activation.getApplication().getId());
                    // Unknown version is converted to 0 in service
                    activationServiceItem.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                    activationServiceItem.setFailedAttempts(activation.getFailedAttempts());
                    activationServiceItem.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                    activationServiceItem.setDevicePublicKeyBase64(activation.getDevicePublicKeyBase64());
                    response.getActivations().add(activationServiceItem);
                }
            }
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    private static ActivationProtocol convert(final io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationProtocol source) {
        if (source == null) {
            return null;
        }
        return switch(source) {
            case FIDO2 -> ActivationProtocol.FIDO2;
            case POWERAUTH -> ActivationProtocol.POWERAUTH;
        };
    }

    private Set<ActivationStatus> convert(final Set<com.wultra.security.powerauth.client.model.enumeration.ActivationStatus> source) {
        if (CollectionUtils.isEmpty(source)) {
            return Set.of(ActivationStatus.values());
        } else {
            return source.stream()
                    .map(activationStatusConverter::convert)
                    .collect(Collectors.toSet());
        }
    }

    /**
     * Lookup activations using various query parameters.
     *
     * @param request Activation lookup request.
     * @return Response with list of matching activations.
     */
    @Transactional
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws GenericServiceException {
        try {
            List<String> userIds = request.getUserIds();
            List<String> applicationIds = request.getApplicationIds();
            Date timestampLastUsedBefore;
            if (request.getTimestampLastUsedBefore() != null) {
                timestampLastUsedBefore = request.getTimestampLastUsedBefore();
            } else {
                timestampLastUsedBefore = MAX_TIMESTAMP;
            }
            Date timestampLastUsedAfter;
            if (request.getTimestampLastUsedAfter() != null) {
                timestampLastUsedAfter = request.getTimestampLastUsedAfter();
            } else {
                timestampLastUsedAfter = MIN_TIMESTAMP;
            }
            ActivationStatus activationStatus = null;
            if (request.getActivationStatus() != null) {
                activationStatus = activationStatusConverter.convert(request.getActivationStatus());
            }

            if (userIds == null || userIds.isEmpty()) {
                logger.warn("Invalid request parameter userIds in method lookupActivations");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final List<String> activationFlags = request.getActivationFlags();

            final LookupActivationsResponse response = new LookupActivationsResponse();
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            if (applicationIds != null && applicationIds.isEmpty()) {
                // Make sure application ID list is null in case no application ID is specified
                applicationIds = null;
            }
            final List<ActivationStatus> statuses = new ArrayList<>();
            if (activationStatus == null) {
                // In case activation status is not specified, consider all statuses
                statuses.addAll(Arrays.asList(ActivationStatus.values()));
            } else {
                statuses.add(activationStatus);
            }
            final List<ActivationRecordEntity> activationsList = activationQueryService.lookupActivations(userIds, applicationIds, timestampLastUsedBefore, timestampLastUsedAfter, statuses);
            if (activationsList.isEmpty()) {
                return response;
            }

            final List<ActivationRecordEntity> filteredActivationList = new ArrayList<>();
            // Filter activation by activation flags in case they are specified
            if (activationFlags != null && !activationFlags.isEmpty()) {
                final List<ActivationRecordEntity> activationsWithFlags = activationsList.stream()
                        .filter(activation -> new HashSet<>(activation.getFlags()).containsAll(activationFlags))
                        .toList();
                filteredActivationList.addAll(activationsWithFlags);
            } else {
                filteredActivationList.addAll(activationsList);
            }

            for (ActivationRecordEntity activation : filteredActivationList) {
                // Map between database object and service objects
                final Activation activationServiceItem = new Activation();
                activationServiceItem.setActivationId(activation.getActivationId());
                activationServiceItem.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                activationServiceItem.setBlockedReason(activation.getBlockedReason());
                activationServiceItem.setExternalId(activation.getExternalId());
                activationServiceItem.setActivationName(activation.getActivationName());
                activationServiceItem.setExtras(activation.getExtras());
                activationServiceItem.setProtocol(convert(activation.getProtocol()));
                activationServiceItem.setPlatform(activation.getPlatform());
                activationServiceItem.setDeviceInfo(activation.getDeviceInfo());
                activationServiceItem.getActivationFlags().addAll(activation.getFlags());
                activationServiceItem.setTimestampCreated(activation.getTimestampCreated());
                activationServiceItem.setTimestampLastUsed(activation.getTimestampLastUsed());
                activationServiceItem.setTimestampLastChange(activation.getTimestampLastChange());
                activationServiceItem.setUserId(activation.getUserId());
                activationServiceItem.setApplicationId(activation.getApplication().getId());
                // Unknown version is converted to 0 in service
                activationServiceItem.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                activationServiceItem.setFailedAttempts(activation.getFailedAttempts());
                activationServiceItem.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                activationServiceItem.setDevicePublicKeyBase64(activation.getDevicePublicKeyBase64());
                response.getActivations().add(activationServiceItem);
            }

            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Update status for activations.
     * @param request Request with status update query.
     * @return Response with indication whether status update succeeded.
     */
    @Transactional
    public UpdateStatusForActivationsResponse updateStatusForActivation(UpdateStatusForActivationsRequest request) throws GenericServiceException {
        try {
            if (request.getActivationIds() == null || request.getActivationIds().isEmpty()) {
                logger.warn("Invalid request parameter activationIds in method updateStatusForActivations");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final List<String> activationIds = request.getActivationIds();
            ActivationStatus activationStatus = null;
            if (request.getActivationStatus() != null) {
                activationStatus = activationStatusConverter.convert(request.getActivationStatus());
            }

            final UpdateStatusForActivationsResponse response = new UpdateStatusForActivationsResponse();

            final ActivationStatus finalActivationStatus = activationStatus;
            activationIds.forEach(activationId -> {
                try {
                    final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                        logger.info("Activation not found, activation ID: {}", activationId);
                        return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
                    });
                    if (!activation.getActivationStatus().equals(finalActivationStatus)) {
                        // Update activation status, persist change and notify callback listeners
                        activation.setActivationStatus(finalActivationStatus);
                        activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
                        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
                    }
                } catch (GenericServiceException e) {
                    // Avoid double logging for non-existent activations
                    logger.debug(e.getMessage(), e);
                }
            });

            response.setUpdated(true);

            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Get activation status for given activation ID
     *
     * @param request Activation status request.
     * @return Activation status response
     * @throws GenericServiceException Thrown when cryptography error occurs.
     */
    @Transactional
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String challenge = request.getChallenge();

            if (activationId == null) {
                logger.warn("Invalid request parameter activationId in method getActivationStatus");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Generate timestamp in advance
            final Date timestamp = new Date();

            // Get the repository
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();

            // Prepare key generator
            final KeyGenerator keyGenerator = new KeyGenerator();

            final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);

            // Check if the activation exists
            if (activationOptional.isPresent()) {

                final ActivationRecordEntity activation = activationOptional.get();
                // Deactivate old pending activations first
                deactivatePendingActivation(timestamp, activation, false);

                final ApplicationEntity application = activation.getApplication();
                final String applicationId = application.getId();

                // Handle CREATED activation
                if (activation.getActivationStatus() == ActivationStatus.CREATED) {

                    // Created activations are not able to transfer valid status blob to the client
                    // since both keys were not exchanged yet and transport cannot be secured.
                    final byte[] randomStatusBlob = keyGenerator.generateRandomBytes(32);
                    // Use random nonce in case that challenge was provided.
                    final String randomStatusBlobNonce = challenge == null ? null : Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16));

                    // Activation signature
                    final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
                    if (masterKeyPairEntity == null) {
                        logger.error("Missing key pair for application ID: {}", applicationId);
                        // Rollback is not required, database is not used for writing
                        throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                    }
                    final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
                    final byte[] masterPrivateKeyBytes = Base64.getDecoder().decode(masterPrivateKeyBase64);
                    final byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(
                            activation.getActivationCode(),
                            keyConvertor.convertBytesToPrivateKey(masterPrivateKeyBytes)
                    );

                    // return the data
                    final GetActivationStatusResponse response = new GetActivationStatusResponse();
                    response.setActivationId(activationId);
                    response.setUserId(activation.getUserId());
                    response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    response.setActivationOtpValidation(activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation()));
                    response.setCommitPhase(activationCommitPhaseConverter.convertFrom(activation.getCommitPhase()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setActivationName(activation.getActivationName());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(applicationId);
                    response.setFailedAttempts(activation.getFailedAttempts());
                    response.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                    response.setTimestampCreated(activation.getTimestampCreated());
                    response.setTimestampLastUsed(activation.getTimestampLastUsed());
                    response.setTimestampLastChange(activation.getTimestampLastChange());
                    response.setEncryptedStatusBlob(Base64.getEncoder().encodeToString(randomStatusBlob));
                    response.setEncryptedStatusBlobNonce(randomStatusBlobNonce);
                    response.setActivationCode(activation.getActivationCode());
                    response.setActivationSignature(Base64.getEncoder().encodeToString(activationSignature));
                    response.setDevicePublicKeyFingerprint(null);
                    response.setPlatform(activation.getPlatform());
                    response.setProtocol(convert(activation.getProtocol()));
                    response.setExternalId(activation.getExternalId());
                    response.setDeviceInfo(activation.getDeviceInfo());
                    response.getActivationFlags().addAll(activation.getFlags());
                    response.getApplicationRoles().addAll(application.getRoles());
                    // Unknown version is converted to 0 in service
                    response.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                    return response;
                } else {

                    // Get the server private and device public keys to compute the transport key
                    final String devicePublicKeyBase64 = activation.getDevicePublicKeyBase64();

                    // Get the server public key for the fingerprint
                    final String serverPublicKeyBase64 = activation.getServerPublicKeyBase64();

                    // Decrypt server private key (depending on encryption mode)
                    final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
                    final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
                    final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
                    final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);

                    // If an activation was turned to REMOVED directly from CREATED state,
                    // there is no device public key in the database - we need to handle
                    // that case by defaulting the encryptedStatusBlob to random value...
                    byte[] encryptedStatusBlob = keyGenerator.generateRandomBytes(32);
                    String encryptedStatusBlobNonce = null;

                    // Prepare a value for the device public key fingerprint
                    String activationFingerPrint = null;

                    // There is a device public key available, therefore we can compute
                    // the real encryptedStatusBlob value.
                    if (devicePublicKeyBase64 != null) {

                        final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(serverPrivateKeyBase64));
                        final PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(devicePublicKeyBase64));
                        final PublicKey serverPublicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(serverPublicKeyBase64));

                        final SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                        final SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);

                        final String ctrDataBase64 = activation.getCtrDataBase64();
                        byte[] ctrDataHashForStatusBlob;
                        if (ctrDataBase64 != null) {
                            // In crypto v3 counter data is stored with activation. We have to calculate hash from
                            // the counter value, before it's encoded into the status blob. The value might be replaced
                            // in `encryptedStatusBlob()` function that injects random data, depending on the version
                            // of the status blob encryption.
                            final byte[] ctrData = Base64.getDecoder().decode(ctrDataBase64);
                            ctrDataHashForStatusBlob = powerAuthServerActivation.calculateHashFromHashBasedCounter(ctrData, transportKey);
                        } else {
                            // In crypto v2 counter data is not present, so use an array of zero bytes. This might be
                            // replaced in `encryptedStatusBlob()` function that injects random data automatically,
                            // depending on the version of the status blob encryption.
                            ctrDataHashForStatusBlob = new byte[16];
                        }
                        byte[] statusChallenge;
                        byte[] statusNonce;
                        if (challenge != null) {
                            // If challenge is present, then also generate a new nonce. Protocol V3.1+
                            statusChallenge = Base64.getDecoder().decode(challenge);
                            statusNonce = keyGenerator.generateRandomBytes(16);
                            encryptedStatusBlobNonce = Base64.getEncoder().encodeToString(statusNonce);
                        } else {
                            // Older protocol versions, where IV derivation is not available.
                            statusChallenge = null;
                            statusNonce = null;
                        }

                        // Encrypt the status blob
                        final ActivationStatusBlobInfo statusBlobInfo = new ActivationStatusBlobInfo();
                        statusBlobInfo.setActivationStatus(activation.getActivationStatus().getByte());
                        statusBlobInfo.setCurrentVersion(activation.getVersion().byteValue());
                        statusBlobInfo.setUpgradeVersion(POWERAUTH_PROTOCOL_VERSION);
                        statusBlobInfo.setFailedAttempts(activation.getFailedAttempts().byteValue());
                        statusBlobInfo.setMaxFailedAttempts(activation.getMaxFailedAttempts().byteValue());
                        statusBlobInfo.setCtrLookAhead((byte)powerAuthServiceConfiguration.getSignatureValidationLookahead());
                        statusBlobInfo.setCtrByte(activation.getCounter().byteValue());
                        statusBlobInfo.setCtrDataHash(ctrDataHashForStatusBlob);
                        encryptedStatusBlob = powerAuthServerActivation.encryptedStatusBlob(statusBlobInfo, statusChallenge, statusNonce, transportKey);

                        // Assign the activation fingerprint
                        switch (activation.getVersion()) {
                            case 3 ->
                                    activationFingerPrint = powerAuthServerActivation.computeActivationFingerprint(devicePublicKey, serverPublicKey, activation.getActivationId());
                            default -> {
                                logger.error("Unsupported activation version: {}", activation.getVersion());
                                // Rollback is not required, database is not used for writing
                                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
                            }
                        }
                    }

                    // return the data
                    final GetActivationStatusResponse response = new GetActivationStatusResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    response.setActivationOtpValidation(activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation()));
                    response.setCommitPhase(activationCommitPhaseConverter.convertFrom(activation.getCommitPhase()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setActivationName(activation.getActivationName());
                    response.setUserId(activation.getUserId());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(applicationId);
                    response.setFailedAttempts(activation.getFailedAttempts());
                    response.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                    response.setTimestampCreated(activation.getTimestampCreated());
                    response.setTimestampLastUsed(activation.getTimestampLastUsed());
                    response.setTimestampLastChange(activation.getTimestampLastChange());
                    response.setEncryptedStatusBlob(Base64.getEncoder().encodeToString(encryptedStatusBlob));
                    response.setEncryptedStatusBlobNonce(encryptedStatusBlobNonce);
                    response.setActivationCode(null);
                    response.setActivationSignature(null);
                    response.setDevicePublicKeyFingerprint(activationFingerPrint);
                    response.setPlatform(activation.getPlatform());
                    response.setProtocol(convert(activation.getProtocol()));
                    response.setExternalId(activation.getExternalId());
                    response.setDeviceInfo(activation.getDeviceInfo());
                    response.getActivationFlags().addAll(activation.getFlags());
                    response.getApplicationRoles().addAll(application.getRoles());
                    // Unknown version is converted to 0 in service
                    response.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                    return response;
                }
            } else {

                // Activations that do not exist should return REMOVED state and
                // a random status blob
                final byte[] randomStatusBlob = keyGenerator.generateRandomBytes(32);
                // Use random nonce in case that challenge was provided.
                final String randomStatusBlobNonce = challenge == null ? null : Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16));

                // Generate date
                final Date zeroDate = new Date(0);

                // return the data
                final GetActivationStatusResponse response = new GetActivationStatusResponse();
                response.setActivationId(activationId);
                response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.REMOVED));
                response.setActivationOtpValidation(com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE);
                response.setCommitPhase(com.wultra.security.powerauth.client.model.enumeration.CommitPhase.ON_COMMIT);
                response.setBlockedReason(null);
                response.setActivationName("unknown");
                response.setUserId("unknown");
                response.setApplicationId(null);
                response.setExtras(null);
                response.setPlatform(null);
                response.setProtocol(null);
                response.setExternalId(null);
                response.setDeviceInfo(null);
                response.setTimestampCreated(zeroDate);
                response.setTimestampLastUsed(zeroDate);
                response.setTimestampLastChange(null);
                response.setFailedAttempts(0L);
                response.setMaxFailedAttempts(powerAuthServiceConfiguration.getSignatureMaxFailedAttempts());
                response.setEncryptedStatusBlob(Base64.getEncoder().encodeToString(randomStatusBlob));
                response.setEncryptedStatusBlobNonce(randomStatusBlobNonce);
                response.setActivationCode(null);
                response.setActivationSignature(null);
                response.setDevicePublicKeyFingerprint(null);
                // Use 0 as version when version is undefined
                response.setVersion(0L);
                return response;
            }
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            /// Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
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
     * Init activation with given parameters
     *
     * @param request Init activation request.
     * @return Response with activation initialization data
     * @throws GenericServiceException If invalid values are provided.
     */
    @Transactional
    public InitActivationResponse initActivation(InitActivationRequest request) throws GenericServiceException {
        try {
            final ActivationProtocol protocol = request.getProtocol();
            final String userId = request.getUserId();
            final String applicationId = request.getApplicationId();
            final Long maxFailureCount = request.getMaxFailureCount();
            final Date activationExpireTimestamp = request.getTimestampActivationExpire();
            final String activationOtp = request.getActivationOtp();
            final List<String> flags = request.getFlags();
            com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation activationOtpValidation = request.getActivationOtpValidation();
            final com.wultra.security.powerauth.client.model.enumeration.CommitPhase commitPhase = request.getCommitPhase();

            if (userId == null || userId.isEmpty() || userId.length() > 255) {
                logger.warn("Invalid request parameter userId in method initActivation");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            if (applicationId == null) {
                logger.warn("Application ID not specified");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_APPLICATION_ID);
            }

            // Generate timestamp in advance
            final Date timestamp = new Date();

            // Find application by application key
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final Optional<ApplicationEntity> applicationEntityOptional = applicationRepository.findById(applicationId);
            if (applicationEntityOptional.isEmpty()) {
                logger.warn("Application does not exist: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final ApplicationEntity applicationEntity = applicationEntityOptional.get();

            // Get the repository
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();

            // Get number of max attempts from request or from constants, if not provided
            Long maxAttempt = maxFailureCount;
            if (maxAttempt == null) { // use the default value
                maxAttempt = powerAuthServiceConfiguration.getSignatureMaxFailedAttempts();
            } else if (maxFailureCount <= 0) { // only allow custom values > 0
                logger.warn("Activation cannot be created with the specified properties: maxFailureCount");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_CREATE_FAILED);
            }

            // Get activation expiration date from request or from constants, if not provided
            Date timestampExpiration = activationExpireTimestamp;
            if (timestampExpiration == null) {
                timestampExpiration = new Date(timestamp.getTime() + powerAuthServiceConfiguration.getActivationValidityBeforeActive());
            }

            if (activationOtpValidation == null) {
                activationOtpValidation = com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE;
            }

            validateOtpValidationAndCommitPhase(activationOtpValidation, commitPhase);

            // Generate hash from activation OTP
            final String activationOtpHash = activationOtp == null ? null : PasswordHash.hash(activationOtp.getBytes(StandardCharsets.UTF_8));

            // Fetch the latest master private key
            final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationEntity.getId());
            if (masterKeyPair == null) {
                GenericServiceException ex = localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                // Rollback is not required, error occurs before writing to database
                logger.error("No master key pair found for application ID: {}", applicationId);
                throw ex;
            }
            final byte[] masterPrivateKeyBytes = Base64.getDecoder().decode(masterKeyPair.getMasterKeyPrivateBase64());
            final PrivateKey masterPrivateKey = keyConvertor.convertBytesToPrivateKey(masterPrivateKeyBytes);

            // Generate new activation data, generate a unique activation ID
            String activationId = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationIdIterations(); i++) {
                final String tmpActivationId = powerAuthServerActivation.generateActivationId();
                final Long activationCount = activationRepository.getActivationCount(tmpActivationId);
                if (activationCount == 0) {
                    activationId = tmpActivationId;
                    break;
                } // ... else this activation ID has a collision, reset it and try to find another one
            }
            if (activationId == null) {
                logger.error("Unable to generate activation ID");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_ID);
            }

            // Generate a unique activation code
            String activationCode = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationCodeIterations(); i++) {
                final String tmpActivationCode = powerAuthServerActivation.generateActivationCode();
                final Long activationCount = activationRepository.getActivationCountByActivationCode(applicationId, tmpActivationCode);
                // Check that the temporary short activation ID is unique, otherwise generate a different activation code
                if (activationCount == 0) {
                    activationCode = tmpActivationCode;
                    break;
                }
            }
            if (activationCode == null) {
                logger.error("Unable to generate activation code");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE);
            }


            // Compute activation signature
            final byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(activationCode, masterPrivateKey);

            // Encode the signature
            final String activationSignatureBase64 = Base64.getEncoder().encodeToString(activationSignature);

            // Generate server key pair
            final KeyPair serverKeyPair = powerAuthServerActivation.generateServerKeyPair();
            final byte[] serverKeyPrivateBytes = keyConvertor.convertPrivateKeyToBytes(serverKeyPair.getPrivate());
            final byte[] serverKeyPublicBytes = keyConvertor.convertPublicKeyToBytes(serverKeyPair.getPublic());

            // Store the new activation
            final ActivationRecordEntity activation = new ActivationRecordEntity();
            activation.setActivationId(activationId);
            activation.setActivationCode(activationCode);
            activation.setActivationOtpValidation(activationOtpValidationConverter.convertTo(activationOtpValidation));
            activation.setCommitPhase(activationCommitPhaseConverter.convertTo(commitPhase));
            activation.setActivationOtp(activationOtpHash);
            activation.setExternalId(null);
            activation.setActivationName(null);
            activation.setActivationStatus(ActivationStatus.CREATED);
            activation.setCounter(0L);
            activation.setCtrDataBase64(null);
            activation.setDevicePublicKeyBase64(null);
            activation.setExtras(null);
            activation.setProtocol(convert(protocol));
            activation.setPlatform(null);
            activation.setDeviceInfo(null);
            activation.setFailedAttempts(0L);
            activation.setApplication(masterKeyPair.getApplication());
            activation.setMasterKeyPair(masterKeyPair);
            activation.setMaxFailedAttempts(maxAttempt);
            activation.setServerPublicKeyBase64(Base64.getEncoder().encodeToString(serverKeyPublicBytes));
            activation.setTimestampActivationExpire(timestampExpiration);
            activation.setTimestampCreated(timestamp);
            activation.setTimestampLastUsed(timestamp);
            activation.setTimestampLastChange(null);
            activation.setVersion(null); // Activation version is not known yet
            activation.setUserId(userId);
            if (flags != null) {
                activation.getFlags().addAll(flags);
            }

            // Convert server private key to DB columns serverPrivateKeyEncryption specifying encryption mode and serverPrivateKey with base64-encoded key.
            final ServerPrivateKey serverPrivateKey = serverPrivateKeyConverter.toDBValue(serverKeyPrivateBytes, userId, activationId);
            activation.setServerPrivateKeyEncryption(serverPrivateKey.encryptionMode());
            activation.setServerPrivateKeyBase64(serverPrivateKey.serverPrivateKeyBase64());

            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Return the server response
            final InitActivationResponse response = new InitActivationResponse();
            response.setActivationId(activationId);
            response.setActivationCode(activationCode);
            response.setUserId(userId);
            response.setActivationSignature(activationSignatureBase64);
            response.setApplicationId(activation.getApplication().getId());

            return response;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
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

    private void validateOtpValidationAndCommitPhase(com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation activationOtpValidation, com.wultra.security.powerauth.client.model.enumeration.CommitPhase commitPhase) throws GenericServiceException {
        // Validate combination of activation OTP and OTP validation mode.
        if (activationOtpValidation != com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE && commitPhase != null) {
            logger.warn("Invalid combination of input parameters activationOtpValidation and commitPhase.");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

    }

    private io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationProtocol convert(final ActivationProtocol source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case POWERAUTH -> io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationProtocol.POWERAUTH;
            case FIDO2 -> io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationProtocol.FIDO2;
        };
    }

    /**
     * Prepare activation with given parameters.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param request Request with prepared activation.
     * @return ECIES encrypted activation information.
     * @throws GenericServiceException If invalid values are provided.
     */
    @Transactional
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws GenericServiceException {
        try {
            final String activationCode = request.getActivationCode();
            final String applicationKey = request.getApplicationKey();
            final boolean shouldGenerateRecoveryCodes = request.isGenerateRecoveryCodes();
            final String protocolVersion = request.getProtocolVersion();
            final String temporaryKeyId = request.getTemporaryKeyId();

            // Build encrypted request
            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );

            // Validate encrypted request
            if (!encryptorFactory.getRequestResponseValidator(protocolVersion).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid request parameters in prepareActivation method");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Get current timestamp
            final Date timestamp = new Date();

            // Get required repositories
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            // Find application by application key
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, activation code: {}", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
            final ApplicationEntity application = applicationVersion.getApplication();
            if (application == null) {
                logger.warn("Application does not exist, activation code: {}", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
            final String applicationId = application.getId();

            if (encryptedRequest.getTimestamp() != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_APPLICATION_SCOPE,
                        new Date(encryptedRequest.getTimestamp()),
                        encryptedRequest.getEphemeralPublicKey(),
                        encryptedRequest.getNonce(),
                        null,
                        protocolVersion);
            }

            final PrivateKey privateKey;
            if (temporaryKeyId != null) {
                // Get temporary private key
                privateKey = temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, applicationKey);
            } else {
                // Get master server private key
                final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
                if (masterKeyPairEntity == null) {
                    logger.error("Missing key pair for application ID: {}", applicationId);
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                }

                final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
                privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(masterPrivateKeyBase64));
            }

            // Get server encryptor
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.ACTIVATION_LAYER_2,
                    new EncryptorParameters(protocolVersion, applicationKey, null, temporaryKeyId),
                    new ServerEncryptorSecrets(privateKey, applicationVersion.getApplicationSecret())
            );

            // Decrypt activation data
            final byte[] activationData = serverEncryptor.decryptRequest(encryptedRequest);

            // Convert JSON data to activation layer 2 request object
            final ActivationLayer2Request layer2Request;
            try {
                layer2Request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, activation code: {}", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Ensure presence of the devicePublicKey
            final String retrievedDevicePublicKey = layer2Request.getDevicePublicKey();
            if (!StringUtils.hasText(retrievedDevicePublicKey)) {
                logger.warn("Invalid activation request, activation code: {}", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Fetch the current activation by activation code
            final Set<ActivationStatus> states = Set.of(ActivationStatus.CREATED);
            // Search for activation without lock to avoid potential deadlocks
            ActivationRecordEntity activation = activationQueryService.findActivationByCodeWithoutLock(applicationId, activationCode, states, timestamp).orElseThrow(() -> {
                logger.warn("Activation with activation code: {} could not be obtained. It either does not exist or it already expired.", activationCode);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Search for activation again to acquire PESSIMISTIC_WRITE lock for activation row
            final String activationId = activation.getActivationId();
            activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Make sure to deactivate the activation if it is expired
            deactivatePendingActivation(timestamp, activation, true);

            // Validate that the activation is in correct state for the prepare step
            validateCreatedActivation(activation, application, false);
            // Validate activation OTP
            validateActivationOtp(layer2Request.getActivationOtp(), activation, null);

            // Extract the device public key from request
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(retrievedDevicePublicKey);
            PublicKey devicePublicKey = null;
            try {
                devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                logger.warn("Invalid public key, activation ID: {}", activation.getActivationId());
                logger.debug("Invalid public key, activation ID: {}", activation.getActivationId(), ex);
                handleInvalidPublicKey(activation);
            }

            // Initialize hash based counter
            final HashBasedCounter counter = new HashBasedCounter();
            final byte[] ctrData = counter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

            // If Activation OTP is available or commit phase is ON_KEY_EXCHANGE, then the status is set directly to "ACTIVE".
            final boolean isActive = layer2Request.getActivationOtp() != null || activation.getCommitPhase() == io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase.ON_KEY_EXCHANGE;
            final ActivationStatus activationStatus = isActive ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;

            // Update the activation record
            activation.setActivationStatus(activationStatus);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));
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
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);

            // Create a new recovery code and PUK for new activation if activation recovery is enabled.
            // Perform these operations before writing to database to avoid rollbacks.
            ActivationRecovery activationRecovery = null;
            if (shouldGenerateRecoveryCodes) {
                final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationId);
                if (recoveryConfigEntity != null && recoveryConfigEntity.isActivationRecoveryEnabled()) {
                    activationRecovery = createRecoveryCodeForActivation(activation, isActive);
                }
            }

            // Generate activation layer 2 response
            final ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);
            layer2Response.setServerPublicKey(activation.getServerPublicKeyBase64());
            if (activationRecovery != null) {
                layer2Response.setActivationRecovery(activationRecovery);
            }
            final byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(responseData);

            // Persist activation report and notify listeners
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Generate response object
            final PrepareActivationResponse response = new PrepareActivationResponse();
            response.setActivationId(activation.getActivationId());
            response.setUserId(activation.getUserId());
            response.setApplicationId(applicationId);
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());
            response.setActivationStatus(activationStatusConverter.convert(activationStatus));
            return response;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EncryptorException | JsonProcessingException ex) {
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
     * Create activation with given parameters.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param request Encrypted activation request.
     * @return ECIES encrypted activation information
     * @throws GenericServiceException       In case create activation fails
     */
    @Transactional(rollbackFor = {RuntimeException.class, RollbackingServiceException.class})
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws GenericServiceException {
        try {
            // Get request parameters
            final String userId = request.getUserId();
            final Date activationExpireTimestamp = request.getTimestampActivationExpire();
            final boolean shouldGenerateRecoveryCodes = request.isGenerateRecoveryCodes();
            final Long maxFailureCount = request.getMaxFailureCount();
            final String applicationKey = request.getApplicationKey();
            final String activationOtp = request.getActivationOtp();
            final String protocolVersion = request.getProtocolVersion();
            final String temporaryKeyId = request.getTemporaryKeyId();

            // Build encrypted request
            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );

            // Validate encrypted request
            if (!encryptorFactory.getRequestResponseValidator(protocolVersion).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid request parameters in createActivation method");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            // Get current timestamp
            final Date timestamp = new Date();

            // Get required repositories
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();

            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            // If there is no such activation version or activation version is unsupported, exit
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            final ApplicationEntity application = applicationVersion.getApplication();
            // If there is no such application, exit
            if (application == null) {
                logger.warn("Application is incorrect, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            final String applicationId = application.getId();

            // Prepare activation OTP mode
            final com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation activationOtpValidation = activationOtp != null ? com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.ON_COMMIT : com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE;

            // Create an activation record and obtain the activation database record
            final InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setProtocol(ActivationProtocol.POWERAUTH);
            initRequest.setApplicationId(applicationId);
            initRequest.setUserId(userId);
            initRequest.setMaxFailureCount(maxFailureCount);
            initRequest.setTimestampActivationExpire(activationExpireTimestamp);
            initRequest.setActivationOtp(activationOtp);
            initRequest.setActivationOtpValidation(activationOtpValidation);
            initRequest.setCommitPhase(com.wultra.security.powerauth.client.model.enumeration.CommitPhase.ON_COMMIT);
            final InitActivationResponse initResponse = this.initActivation(initRequest);
            final String activationId = initResponse.getActivationId();
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.warn("Activation not found, activation ID: {}", activationId);
                // The whole transaction is rolled back in case of this unexpected state
                return localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Make sure to deactivate the activation if it is expired
            deactivatePendingActivation(timestamp, activation, true);

            validateCreatedActivation(activation, application, true);

            if (encryptedRequest.getTimestamp() != null) {
                // Check request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_APPLICATION_SCOPE,
                        new Date(encryptedRequest.getTimestamp()),
                        encryptedRequest.getEphemeralPublicKey(),
                        encryptedRequest.getNonce(),
                        null,
                        protocolVersion);
            }

            final PrivateKey privateKey;
            if (temporaryKeyId != null) {
                // Get temporary private key
                privateKey = temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, applicationKey, activationId);
            } else {
                // Get master server private key
                final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
                if (masterKeyPairEntity == null) {
                    logger.error("Missing key pair for application ID: {}", applicationId);
                    // Master key pair is missing, rollback this transaction
                    throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                }
                final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
                privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(masterPrivateKeyBase64));
            }

            // Get server encryptor
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.ACTIVATION_LAYER_2,
                    new EncryptorParameters(protocolVersion, applicationKey, null, temporaryKeyId),
                    new ServerEncryptorSecrets(privateKey, applicationVersion.getApplicationSecret())
            );

            // Decrypt activation data
            final byte[] activationData = serverEncryptor.decryptRequest(encryptedRequest);

            // Convert JSON data to activation layer 2 request object
            ActivationLayer2Request layer2Request;
            try {
                layer2Request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, activation ID: {}", activationId);
                // Activation failed due to invalid ECIES request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Ensure presence of the devicePublicKey
            final String retrievedDevicePublicKey = layer2Request.getDevicePublicKey();
            if (!StringUtils.hasText(retrievedDevicePublicKey)) {
                logger.warn("Invalid activation request, activation ID: {}", activationId);
                // Activation failed due to invalid ECIES request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Extract the device public key from request
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(retrievedDevicePublicKey);
            PublicKey devicePublicKey;
            try {
                devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                logger.warn("Device public key is invalid, activation ID: {}", activationId);
                // Device public key is invalid, rollback this transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Initialize hash based counter
            final HashBasedCounter counter = new HashBasedCounter();
            final byte[] ctrData = counter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

            // Update and persist the activation record
            activation.setActivationStatus(ActivationStatus.PENDING_COMMIT);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));
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
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            final ActivationRecovery activationRecovery = createActivationRecovery(shouldGenerateRecoveryCodes, activation);

            // Generate activation layer 2 response
            final ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);
            layer2Response.setServerPublicKey(activation.getServerPublicKeyBase64());
            if (activationRecovery != null) {
                layer2Response.setActivationRecovery(activationRecovery);
            }
            final byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(responseData);

            // Generate encrypted response
            final CreateActivationResponse response = new CreateActivationResponse();
            response.setActivationId(activation.getActivationId());
            response.setUserId(activation.getUserId());
            response.setApplicationId(applicationId);
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());
            response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            return response;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
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

    // Create a new recovery code and PUK for new activation if activation recovery is enabled
    private ActivationRecovery createActivationRecovery(boolean shouldGenerateRecoveryCodes, ActivationRecordEntity activation) throws GenericServiceException {
        if (shouldGenerateRecoveryCodes) {
            final RecoveryConfigEntity recoveryConfigEntity = repositoryCatalogue.getRecoveryConfigRepository().findByApplicationId(activation.getApplication().getId());
            if (recoveryConfigEntity != null && recoveryConfigEntity.isActivationRecoveryEnabled()) {
                return createRecoveryCodeForActivation(activation, false);
            }
        }
        return null;
    }

    /**
     * Commit activation with given ID.
     *
     * @param request Commit activation request.
     * @return Response with activation commit confirmation.
     * @throws GenericServiceException In case invalid data is provided or activation is not found, in invalid state or already expired.
     */
    @Transactional
    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();
            final String activationOtp = request.getActivationOtp();

            if (activationId == null) {
                logger.warn("Invalid request parameter activationId in method commitActivation");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Find activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Get current timestamp
            final Date timestamp = new Date();

            // Check already deactivated activation
            deactivatePendingActivation(timestamp, activation, true);
            if (activation.getActivationStatus() == ActivationStatus.REMOVED) {
                logger.info("Activation is already REMOVED, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Check whether Activation is in correct state
            if (activation.getActivationStatus() != ActivationStatus.PENDING_COMMIT) {
                logger.info("Activation is not in PENDING_COMMIT state during commit, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Validate activation OTP
            validateActivationOtp(activationOtp, activation, externalUserId);

            // Check the commit phase
            System.out.println("PHASE: " + activation.getCommitPhase());
            if (activation.getCommitPhase() != io.getlime.security.powerauth.app.server.database.model.enumeration.CommitPhase.ON_COMMIT) {
                logger.info("Invalid commit phase during commit for activation ID: {}, commit phase: {}", activationId, activation.getCommitPhase());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Change activation state to ACTIVE
            activation.setActivationStatus(ActivationStatus.ACTIVE);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Update recovery code status in case a related recovery code exists in CREATED state
            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final List<RecoveryCodeEntity> recoveryCodeEntities = recoveryCodeRepository.findAllByApplicationIdAndActivationId(activation.getApplication().getId(), activation.getActivationId());
            for (RecoveryCodeEntity recoveryCodeEntity : recoveryCodeEntities) {
                if (RecoveryCodeStatus.CREATED.equals(recoveryCodeEntity.getStatus())) {
                    recoveryCodeEntity.setStatus(RecoveryCodeStatus.ACTIVE);
                    recoveryCodeEntity.setTimestampLastChange(new Date());
                    recoveryCodeRepository.save(recoveryCodeEntity);
                }
            }

            final CommitActivationResponse response = new CommitActivationResponse();
            response.setActivationId(activationId);
            response.setActivated(true);
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
     * Update name of the given activation.
     *
     * @param request Update request.
     * @return Response with updated activation
     * @throws GenericServiceException In case invalid data is provided or activation is not found, in invalid state or already expired.
     */
    @Transactional
    public UpdateActivationNameResponse updateActivationName(final UpdateActivationNameRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            final List<ActivationStatus> notAllowedStatuses = List.of(ActivationStatus.CREATED, ActivationStatus.REMOVED, ActivationStatus.BLOCKED);
            final ActivationStatus activationStatus = activation.getActivationStatus();
            if (notAllowedStatuses.contains(activationStatus)) {
                logger.info("Activation is in not allowed status {} to update, activation ID: {}", activationStatus, activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            final Date timestamp = new Date();

            activation.setActivationName(request.getActivationName());
            activation.setTimestampLastChange(timestamp);

            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, request.getExternalUserId(), AdditionalInformation.Reason.ACTIVATION_NAME_UPDATED);

            final UpdateActivationNameResponse response = new UpdateActivationNameResponse();
            response.setActivationId(activationId);
            response.setActivationName(activation.getActivationName());
            response.setActivationStatus(activationStatusConverter.convert(activationStatus));
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * Update activation OTP for given activation ID.
     *
     * @param request Update activation OTP request.
     * @return Response with activation UTP update result.
     * @throws GenericServiceException In case invalid data is provided or activation is not found, in invalid state or already expired.
     */
    @Transactional
    public UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();
            final String activationOtp = request.getActivationOtp();

            if (activationId == null) {
                logger.warn("Invalid request parameter activationId in method commitActivation");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Validate provided OTP
            if (activationOtp == null || activationOtp.isEmpty()) {
                logger.warn("Activation OTP not specified in update");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Find activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Get current timestamp
            final Date timestamp = new Date();

            // Check already deactivated activation
            deactivatePendingActivation(timestamp, activation, true);

            // Check activation state
            if (activation.getActivationStatus() != ActivationStatus.PENDING_COMMIT) {
                logger.info("Activation is not in PENDING_COMMIT state during commit, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Check OTP validation mode
            if (activation.getActivationOtpValidation() == ActivationOtpValidation.ON_KEY_EXCHANGE) {
                logger.info("Activation OTP update is not allowed for ON_KEY_EXCHANGE mode. Activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP_MODE);
            }

            final String activationOtpHash;
            try {
                activationOtpHash = PasswordHash.hash(activationOtp.getBytes(StandardCharsets.UTF_8));
            } catch (CryptoProviderException ex) {
                logger.error(ex.getMessage(), ex);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
            }

            // Change activation OTP and set mode to ON_COMMIT
            activation.setActivationOtp(activationOtpHash);
            activation.setActivationOtpValidation(ActivationOtpValidation.ON_COMMIT);

            // Save activation record
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId, AdditionalInformation.Reason.ACTIVATION_OTP_VALUE_UPDATE);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            final UpdateActivationOtpResponse response = new UpdateActivationOtpResponse();
            response.setActivationId(activationId);
            response.setUpdated(true);
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
     * Validate activation OTP against value set in the activation's record.
     *
     * @param confirmationOtp   OTP value to be validated.
     * @param activation        Activation record.
     * @param externalUserId    User ID of user who is performing this validation. Use null value if activation owner caused the change.
     * @throws GenericServiceException In case invalid data is provided or activation OTP is invalid.
     */
    private void validateActivationOtp(String confirmationOtp, ActivationRecordEntity activation, String externalUserId) throws GenericServiceException {

        final String activationId = activation.getActivationId();
        final String expectedOtpHash = activation.getActivationOtp();

        // Check whether activation OTP is specified.
        if (!StringUtils.hasText(confirmationOtp)) {
            return;
        }

        // Check whether hash is present in the database.
        if (expectedOtpHash == null) {
            logger.info("Activation OTP is missing in activation data: {}", activationId);
            // Rollback is not required, database is not used for writing yet.
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
        }

        // Now verify OTP value
        try {
            if (PasswordHash.verify(confirmationOtp.getBytes(StandardCharsets.UTF_8), expectedOtpHash)) {
                // Everything looks fine. Reset the failed attempts counter.
                activation.setFailedAttempts(0L);
                return;
            }
        } catch (IOException e) {
            // This exception typically means that the hash stored in DB is in wrong format. The rest of this method
            // will treat this as an invalid OTP.
            logger.warn("Invalid activation OTP hash: {}", activationId);
        }

        // Confirmation OTP doesn't match value stored in the database.

        // Increase the number of failed attempts and validate the maximum number of failed attempts.
        activation.setFailedAttempts(activation.getFailedAttempts() + 1L);
        final boolean removeActivation = activation.getFailedAttempts() >= activation.getMaxFailedAttempts();

        // If activation should be removed then set its status to REMOVED.
        if (removeActivation) {
            activation.setActivationStatus(ActivationStatus.REMOVED);
        }

        // Save activation state with the reason.
        final String activationSaveReason = removeActivation ? AdditionalInformation.Reason.ACTIVATION_OTP_MAX_FAILED_ATTEMPTS : AdditionalInformation.Reason.ACTIVATION_OTP_FAILED_ATTEMPT;
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId, activationSaveReason);

        // Also notify the listeners in case that the state of the activation was changed.
        if (removeActivation) {
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        }

        // ...and finally throw an exception.
        logger.info("Invalid activation OTP: {}", activationId);
        // Exception must not be rollbacking, otherwise data written to database in this method would be lost.
        throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
    }

    /**
     * Remove activation with given ID.
     *
     * @param request Remove activation request.
     * @return Response with confirmation of removal.
     * @throws GenericServiceException In case activation does not exist.
     */
    @Transactional
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();
            boolean revokeRecoveryCodes = request.isRevokeRecoveryCodes();
            if (activationId == null) {
                logger.warn("Invalid request parameter activationId in method removeActivation");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });
            return removeActivation(activation, externalUserId, revokeRecoveryCodes);
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
     * Remove provided activation.
     *
     * @param activation Activation entity.
     * @param externalUserId User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @param revokeRecoveryCodes Flag that indicates if a recover codes associated with this activation should be also revoked.
     * @return Response with confirmation of removal.
     */
    public RemoveActivationResponse removeActivation(@NotNull ActivationRecordEntity activation, String externalUserId, boolean revokeRecoveryCodes) {
        logger.info("Processing activation removal, activation ID: {}", activation.getActivationId());
        removeActivationInternal(activation, externalUserId, revokeRecoveryCodes);
        final RemoveActivationResponse response = new RemoveActivationResponse();
        response.setActivationId(activation.getActivationId());
        response.setRemoved(true);
        return response;
    }

    /**
     * Block activation with given ID
     *
     * @param request Block activation request.
     * @return Response confirming that activation was blocked
     * @throws GenericServiceException In case activation does not exist.
     */
    @Transactional
    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String reason = request.getReason();
            final String externalUserId = request.getExternalUserId();

            if (request.getActivationId() == null) {
                logger.warn("Invalid request parameter activationId in method blockActivation");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // is activation in correct state?
            if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {
                activation.setActivationStatus(ActivationStatus.BLOCKED);
                activation.setBlockedReason(Objects.requireNonNullElse(reason, AdditionalInformation.Reason.BLOCKED_REASON_NOT_SPECIFIED));
                activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
                callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
            } else if (activation.getActivationStatus() != ActivationStatus.BLOCKED) {
                // In case activation status is not ACTIVE or BLOCKED, throw an exception
                logger.info("Activation cannot be blocked due to invalid status, activation ID: {}, status: {}", activationId, activation.getActivationStatus());
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }
            final BlockActivationResponse response = new BlockActivationResponse();
            response.setActivationId(activationId);
            response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            response.setBlockedReason(activation.getBlockedReason());
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
     * Unblock activation with given ID
     *
     * @param request Request with the activation blocking information.
     * @return Response confirming that activation was unblocked
     * @throws GenericServiceException In case activation does not exist.
     */
    @Transactional
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();

            if (activationId == null) {
                logger.warn("Invalid request parameter activationId in method unblockActivation");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // is activation it in correct state?
            if (activation.getActivationStatus() == ActivationStatus.BLOCKED) {
                // Update and store new activation
                activation.setActivationStatus(ActivationStatus.ACTIVE);
                activation.setBlockedReason(null);
                activation.setFailedAttempts(0L);
                activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
                callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
            } else if (activation.getActivationStatus() != ActivationStatus.ACTIVE) {
                // In case activation status is not BLOCKED or ACTIVE, throw an exception
                logger.info("Activation cannot be unblocked due to invalid status, activation ID: {}, status: {}", activationId, activation.getActivationStatus());
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }
            final UnblockActivationResponse response = new UnblockActivationResponse();
            response.setActivationId(activationId);
            response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
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
     * Create activation using recovery code.
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery code response.
     * @throws GenericServiceException In case of any error.
     */
    @Transactional(rollbackFor = {RuntimeException.class, RollbackingServiceException.class})
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws GenericServiceException {
        try {
            if (request.getRecoveryCode() == null || request.getPuk() == null || request.getApplicationKey() == null) {
                logger.warn("Invalid request parameters in method createActivationUsingRecoveryCode");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Extract request data
            final Boolean shouldGenerateRecoveryCodes = request.getGenerateRecoveryCodes();
            final String recoveryCode = request.getRecoveryCode();
            final String puk = request.getPuk();
            final String applicationKey = request.getApplicationKey();
            final Long maxFailureCount = request.getMaxFailureCount();
            final String activationOtp = request.getActivationOtp();
            final String temporaryKeyId = request.getTemporaryKeyId();

            // Prepare and validate encrypted request
            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );
            final String version = request.getProtocolVersion();
            if (!encryptorFactory.getRequestResponseValidator(version).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid encrypted request, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Prepare repositories
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            // Find application by application key
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ApplicationEntity application = applicationVersion.getApplication();
            if (application == null) {
                logger.warn("Application does not exist, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final String applicationId = application.getId();

            // Check whether activation recovery is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(applicationId);
            if (recoveryConfigEntity == null || !recoveryConfigEntity.isActivationRecoveryEnabled()) {
                logger.warn("Activation recovery is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            if (encryptedRequest.getTimestamp() != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_APPLICATION_SCOPE,
                        new Date(encryptedRequest.getTimestamp()),
                        encryptedRequest.getEphemeralPublicKey(),
                        encryptedRequest.getNonce(),
                        null,
                        version);
            }

            final PrivateKey privateKey;
            if (temporaryKeyId != null) {
                // Get temporary private key
                privateKey = temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, applicationKey);
            } else {
                // Get master server private key
                final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
                if (masterKeyPairEntity == null) {
                    logger.error("Missing key pair for application ID: {}", applicationId);
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                }
                final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
                privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(masterPrivateKeyBase64));
            }

            // Get server encryptor
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.ACTIVATION_LAYER_2,
                    new EncryptorParameters(version, applicationKey, null, temporaryKeyId),
                    new ServerEncryptorSecrets(privateKey, applicationVersion.getApplicationSecret())
            );

            // Decrypt activation data
            final byte[] activationData = serverEncryptor.decryptRequest(encryptedRequest);

            // Convert JSON data to activation layer 2 request object
            ActivationLayer2Request layer2Request;
            try {
                layer2Request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, recovery code: {}", recoveryCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Ensure presence of the devicePublicKey
            final String retrievedDevicePublicKey = layer2Request.getDevicePublicKey();
            if (!StringUtils.hasText(retrievedDevicePublicKey)) {
                logger.warn("Invalid activation request, recovery code: {}", recoveryCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Get recovery code entity
            final RecoveryCodeEntity recoveryCodeEntity = recoveryCodeRepository.findByApplicationIdAndRecoveryCode(applicationId, recoveryCode);
            if (recoveryCodeEntity == null) {
                logger.warn("Recovery code does not exist: {}", recoveryCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (!RecoveryCodeStatus.ACTIVE.equals(recoveryCodeEntity.getStatus())) {
                logger.warn("Recovery code is not in ACTIVE state: {}", recoveryCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Verify recovery PUK
            boolean pukValid = false;
            RecoveryPukEntity pukUsedDuringActivation = null;
            RecoveryPukEntity firstValidPuk = null;
            final List<RecoveryPukEntity> recoveryPukEntities = recoveryCodeEntity.getRecoveryPuks();
            for (RecoveryPukEntity recoveryPukEntity: recoveryPukEntities) {
                if (RecoveryPukStatus.VALID.equals(recoveryPukEntity.getStatus())) {
                    if (firstValidPuk == null) {
                        firstValidPuk = recoveryPukEntity;
                        // First valid PUK found, verify PUK hash
                        final byte[] pukBytes = puk.getBytes(StandardCharsets.UTF_8);
                        final String pukValueFromDB = recoveryPukEntity.getPuk();
                        final EncryptionMode encryptionMode = recoveryPukEntity.getPukEncryption();
                        final RecoveryPuk recoveryPuk = new RecoveryPuk(encryptionMode, pukValueFromDB);
                        final String pukHash = recoveryPukConverter.fromDBValue(recoveryPuk, application.getRid(), recoveryCodeEntity.getUserId(), recoveryCode, recoveryPukEntity.getPukIndex());
                        try {
                            if (PasswordHash.verify(pukBytes, pukHash)) {
                                pukValid = true;
                                pukUsedDuringActivation = recoveryPukEntity;
                                break;
                            }
                        } catch (IOException ex) {
                            logger.warn("Invalid PUK hash for recovery code: {}", recoveryCode);
                            // Rollback is not required, error occurs before writing to database
                            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                        }
                    }
                }
            }
            if (!pukValid) {
                // Log invalid PUK on info level, this may be a common user error
                logger.info("Received invalid recovery PUK for recovery code: {}", recoveryCodeEntity.getRecoveryCodeMasked());
                // Increment failed count
                recoveryCodeEntity.setFailedAttempts(recoveryCodeEntity.getFailedAttempts() + 1);
                recoveryCodeEntity.setTimestampLastChange(new Date());
                if (recoveryCodeEntity.getFailedAttempts() >= recoveryCodeEntity.getMaxFailedAttempts()) {
                    if (firstValidPuk != null) {
                        // In case max failed count is reached and valid PUK exists, block the recovery code and invalidate the PUK
                        recoveryCodeEntity.setStatus(RecoveryCodeStatus.BLOCKED);
                        recoveryCodeEntity.setTimestampLastChange(new Date());
                        firstValidPuk.setStatus(RecoveryPukStatus.INVALID);
                        firstValidPuk.setTimestampLastChange(new Date());
                    }
                }
                recoveryCodeRepository.save(recoveryCodeEntity);
                if (firstValidPuk != null && !RecoveryPukStatus.INVALID.equals(firstValidPuk.getStatus())) {
                    // Provide current recovery PUK index in error response in case PUK in VALID state exists.
                    // Exception must not be rollbacking, otherwise the data saved into DB would be lost.
                    throw localizationProvider.buildActivationRecoveryExceptionForCode(ServiceError.INVALID_RECOVERY_CODE, firstValidPuk.getPukIndex().intValue());
                } else {
                    // Exception must not be rollbacking, otherwise the data saved into DB would be lost.
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_RECOVERY_CODE);
                }
            }

            // Reset failed count, PUK was valid
            recoveryCodeEntity.setFailedAttempts(0L);

            // Change status of PUK which was used for recovery to USED
            pukUsedDuringActivation.setStatus(RecoveryPukStatus.USED);
            pukUsedDuringActivation.setTimestampLastChange(new Date());

            // If recovery code is bound to an existing activation, remove this activation
            // and make sure to inherit activation flags of the original activation
            final List<String> activationFlags = new ArrayList<>();
            final String recoveryCodeEntityActivationId = recoveryCodeEntity.getActivationId();
            if (recoveryCodeEntityActivationId != null) {
                final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(recoveryCodeEntityActivationId).orElseThrow(() -> {
                    logger.info("Activation not found, activation ID: {}", recoveryCodeEntityActivationId);
                    // Exception must not be rollbacking, otherwise the data saved into DB would be lost.
                    return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
                });
                final List<String> originalActivationFlags = activation.getFlags();
                if (originalActivationFlags != null) {
                    activationFlags.addAll(originalActivationFlags);
                }
                removeActivation(activation, null, true);
            }

            // Persist recovery code changes
            recoveryCodeRepository.save(recoveryCodeEntity);

            // Prepare activation OTP mode
            final com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation activationOtpValidation = activationOtp != null ? com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.ON_COMMIT : com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE;

            // Initialize version 3 activation entity.
            // Parameter maxFailureCount can be customized, activationExpireTime is null because activation is committed immediately.
            final InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setProtocol(ActivationProtocol.POWERAUTH);
            initRequest.setApplicationId(applicationId);
            initRequest.setUserId(recoveryCodeEntity.getUserId());
            initRequest.setMaxFailureCount(maxFailureCount);
            initRequest.setActivationOtp(activationOtp);
            initRequest.setActivationOtpValidation(activationOtpValidation);
            initRequest.setFlags(activationFlags);
            final InitActivationResponse initResponse = initActivation(initRequest);
            final String activationId = initResponse.getActivationId();
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Exception must not be rollbacking, otherwise the data saved into DB would be lost.
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Validate created activation
            validateCreatedActivation(activation, application, true);

            // Extract the device public key from request
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(retrievedDevicePublicKey);
            PublicKey devicePublicKey;
            try {
                devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                logger.warn("Device public key is invalid, activation ID: {}", activationId);
                // Device public key is invalid, rollback this transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Initialize hash based counter
            final HashBasedCounter counter = new HashBasedCounter();
            final byte[] ctrData = counter.init();
            final String ctrDataBase64 = Base64.getEncoder().encodeToString(ctrData);

            // Update and persist the activation record, activation is automatically committed in the next step in RESTful integration.
            activation.setActivationStatus(ActivationStatus.PENDING_COMMIT);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(Base64.getEncoder().encodeToString(keyConvertor.convertPublicKeyToBytes(devicePublicKey)));
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
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Activation has been successfully committed, set PUK state to USED and persist the change
            pukUsedDuringActivation.setStatus(RecoveryPukStatus.USED);
            pukUsedDuringActivation.setTimestampLastChange(new Date());
            recoveryCodeRepository.save(recoveryCodeEntity);

            // Create a new recovery code and PUK for new activation
            ActivationRecovery activationRecovery = null;
            if (shouldGenerateRecoveryCodes == null || shouldGenerateRecoveryCodes) {
                activationRecovery = createRecoveryCodeForActivation(activation, false);
            }

            // Generate activation layer 2 response
            final ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);
            layer2Response.setServerPublicKey(activation.getServerPublicKeyBase64());
            layer2Response.setActivationRecovery(activationRecovery);
            final byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(responseData);

            final RecoveryCodeActivationResponse response = new RecoveryCodeActivationResponse();
            response.setActivationId(activation.getActivationId());
            response.setUserId(activation.getUserId());
            response.setApplicationId(applicationId);
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());
            response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            return response;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
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
     * Create recovery code for given activation and set its status to ACTIVE.
     * @param activationEntity Activation entity.
     * @param isActive Make recovery code active from the beginning.
     * @return Activation recovery code and PUK.
     * @throws GenericServiceException In case of any error.
     */
    private ActivationRecovery createRecoveryCodeForActivation(ActivationRecordEntity activationEntity, boolean isActive) throws GenericServiceException {
        final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

        try {
            // Check whether activation recovery is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(activationEntity.getApplication().getId());
            if (recoveryConfigEntity == null || !recoveryConfigEntity.isActivationRecoveryEnabled()) {
                logger.warn("Activation recovery is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            activationValidator.validatePowerAuthProtocol(activationEntity.getProtocol(), localizationProvider);

            // Note: the code below expects that application version for given activation has been verified.
            // We want to avoid checking application version twice (once during activation and second time in this method).
            // It is also expected that the activation is a valid activation which has just been created.
            // Prepare repositories
            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();

            final ApplicationEntity application = activationEntity.getApplication();
            final String activationId = activationEntity.getActivationId();
            final String userId = activationEntity.getUserId();
            final String applicationId = application.getId();

            // Verify activation state
            if (!ActivationStatus.PENDING_COMMIT.equals(activationEntity.getActivationStatus()) && !ActivationStatus.ACTIVE.equals(activationEntity.getActivationStatus())) {
                logger.warn("Create recovery code failed because of invalid activation state, application ID: {}, activation ID: {}, activation state: {}", applicationId, activationId, activationEntity.getActivationStatus());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Check whether user has any recovery code in state CREATED or ACTIVE, in this case the recovery code needs to be revoked first
            final List<RecoveryCodeEntity> existingRecoveryCodes = recoveryCodeRepository.findAllByApplicationIdAndActivationId(applicationId, activationId);
            for (RecoveryCodeEntity recoveryCodeEntity: existingRecoveryCodes) {
                if (recoveryCodeEntity.getStatus() == RecoveryCodeStatus.CREATED || recoveryCodeEntity.getStatus() == RecoveryCodeStatus.ACTIVE) {
                    logger.warn("Create recovery code failed because of existing recovery codes, application ID: {}, activation ID: {}", applicationId, activationId);
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.RECOVERY_CODE_ALREADY_EXISTS);
                }
            }

            // Generate random secret key
            String recoveryCode = null;
            Map<Integer, String> puks = null;

            for (int i = 0; i < powerAuthServiceConfiguration.getGenerateRecoveryCodeIterations(); i++) {
                final RecoveryInfo recoveryInfo = identifierGenerator.generateRecoveryCode();
                // Check that recovery code is unique
                final boolean recoveryCodeExists = recoveryCodeRepository.recoveryCodeCount(applicationId, recoveryInfo.getRecoveryCode()) > 0;
                if (!recoveryCodeExists) {
                    recoveryCode = recoveryInfo.getRecoveryCode();
                    puks = recoveryInfo.getPuks();
                    break;
                }
            }

            // In case recovery code generation failed, throw an exception
            if (recoveryCode == null || puks == null || puks.size() != 1) {
                logger.error("Unable to generate recovery code");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_RECOVERY_CODE);
            }

            // Create and persist recovery code entity with PUK
            final RecoveryCodeEntity recoveryCodeEntity = new RecoveryCodeEntity();
            recoveryCodeEntity.setUserId(userId);
            recoveryCodeEntity.setApplication(application);
            recoveryCodeEntity.setActivationId(activationId);
            recoveryCodeEntity.setFailedAttempts(0L);
            recoveryCodeEntity.setMaxFailedAttempts(powerAuthServiceConfiguration.getRecoveryMaxFailedAttempts());
            recoveryCodeEntity.setRecoveryCode(recoveryCode);
            recoveryCodeEntity.setStatus(isActive ? RecoveryCodeStatus.ACTIVE : RecoveryCodeStatus.CREATED);
            recoveryCodeEntity.setTimestampCreated(new Date());

            // Only one PUK was generated
            final String puk = puks.values().iterator().next();

            final RecoveryPukEntity recoveryPukEntity = new RecoveryPukEntity();
            recoveryPukEntity.setPukIndex(1L);
            final String pukHash = PasswordHash.hash(puk.getBytes(StandardCharsets.UTF_8));
            final RecoveryPuk recoveryPuk = recoveryPukConverter.toDBValue(pukHash, application.getRid(), userId, recoveryCode, recoveryPukEntity.getPukIndex());
            recoveryPukEntity.setPuk(recoveryPuk.pukHash());
            recoveryPukEntity.setPukEncryption(recoveryPuk.encryptionMode());
            recoveryPukEntity.setStatus(RecoveryPukStatus.VALID);
            recoveryPukEntity.setRecoveryCode(recoveryCodeEntity);
            recoveryCodeEntity.getRecoveryPuks().add(recoveryPukEntity);

            recoveryCodeRepository.save(recoveryCodeEntity);

            return new ActivationRecovery(recoveryCode, puk);
        } catch (InvalidKeyException ex) {
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
     * Internal logic for processing activation removal.
     * @param activation Activation entity.
     * @param externalUserId External user identifier.
     * @param revokeRecoveryCodes Whether associated recovery codes should be revoked.
     */
    private void removeActivationInternal(final ActivationRecordEntity activation, final String externalUserId, final boolean revokeRecoveryCodes) {
        activation.setActivationStatus(ActivationStatus.REMOVED);
        // Recovery codes are revoked in case revocation is requested, or always when the activation is in CREATED or PENDING_COMMIT state
        if (revokeRecoveryCodes
                || activation.getActivationStatus() == ActivationStatus.CREATED
                || activation.getActivationStatus() == ActivationStatus.PENDING_COMMIT) {
            revokeRecoveryCodes(activation.getActivationId());
        }
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
    }

    /**
     * Revoke recovery codes for an activation entity.
     * @param activationId Activation identifier.
     */
    private void revokeRecoveryCodes(String activationId) {
        logger.info("Revoking recovery codes for activation ID: {}", activationId);
        final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
        final List<RecoveryCodeEntity> recoveryCodeEntities = recoveryCodeRepository.findAllByActivationId(activationId);
        final Date now = new Date();
        for (RecoveryCodeEntity recoveryCode : recoveryCodeEntities) {
            logger.debug("Revoking recovery code: {} for activation ID: {}", recoveryCode.getRecoveryCode(), activationId);
            // revoke only codes that are not yet revoked, to avoid messing up with timestamp
            if (!RecoveryCodeStatus.REVOKED.equals(recoveryCode.getStatus())) {
                recoveryCode.setStatus(RecoveryCodeStatus.REVOKED);
                recoveryCode.setTimestampLastChange(now);
                // Change status of PUKs with status VALID to INVALID
                for (RecoveryPukEntity puk : recoveryCode.getRecoveryPuks()) {
                    if (RecoveryPukStatus.VALID.equals(puk.getStatus())) {
                        puk.setStatus(RecoveryPukStatus.INVALID);
                        puk.setTimestampLastChange(now);
                    }
                }
                recoveryCodeRepository.save(recoveryCode);
            }
        }
    }

    public List<Activation> findByExternalId(String applicationId, String externalId) throws GenericServiceException {
        final Date timestamp = new Date();
        final List<ActivationRecordEntity> activationsList = activationQueryService.findByExternalId(applicationId, externalId);

        final List<Activation> result = new ArrayList<>();

        if (activationsList != null) {
            for (ActivationRecordEntity activation : activationsList) {

                deactivatePendingActivation(timestamp, activation, false);

                // Map between database object and service objects
                final Activation activationServiceItem = new Activation();
                activationServiceItem.setActivationId(activation.getActivationId());
                activationServiceItem.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                activationServiceItem.setBlockedReason(activation.getBlockedReason());
                activationServiceItem.setExternalId(activation.getExternalId());
                activationServiceItem.setActivationName(activation.getActivationName());
                activationServiceItem.setExtras(activation.getExtras());
                activationServiceItem.setProtocol(convert(activation.getProtocol()));
                activationServiceItem.setPlatform(activation.getPlatform());
                activationServiceItem.setDeviceInfo(activation.getDeviceInfo());
                activationServiceItem.getActivationFlags().addAll(activation.getFlags());
                activationServiceItem.setTimestampCreated(activation.getTimestampCreated());
                activationServiceItem.setTimestampLastUsed(activation.getTimestampLastUsed());
                activationServiceItem.setTimestampLastChange(activation.getTimestampLastChange());
                activationServiceItem.setUserId(activation.getUserId());
                activationServiceItem.setApplicationId(activation.getApplication().getId());
                // Unknown version is converted to 0 in service
                activationServiceItem.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                activationServiceItem.setFailedAttempts(activation.getFailedAttempts());
                activationServiceItem.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                activationServiceItem.setDevicePublicKeyBase64(activation.getDevicePublicKeyBase64());
                result.add(activationServiceItem);
            }
        }
        return result;
    }

    @Transactional
    public void expireActivations() {
        final Date currentTimestamp = new Date();
        final Date lookBackTimestamp = new Date(currentTimestamp.getTime() - powerAuthServiceConfiguration.getActivationsCleanupLookBackInMilliseconds());
        logger.debug("Running scheduled task for expiring activations");
        final Set<ActivationStatus> activationStatuses = Set.of(ActivationStatus.CREATED, ActivationStatus.PENDING_COMMIT);
        try (final Stream<ActivationRecordEntity> abandonedActivations = activationQueryService.findAbandonedActivations(activationStatuses, lookBackTimestamp, currentTimestamp)) {
            abandonedActivations.forEach(activation -> {
                logger.info("Removing abandoned activation with ID: {}", activation.getActivationId());
                try {
                    deactivatePendingActivation(currentTimestamp, activation, false);
                } catch (GenericServiceException e) {
                    logger.error("Activation expiration failed, activation ID: {}", activation.getActivationId());
                }
            });
        }
    }

}
