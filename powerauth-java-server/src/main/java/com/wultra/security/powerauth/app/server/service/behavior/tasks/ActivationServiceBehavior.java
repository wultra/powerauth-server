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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthPageableConfiguration;
import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.ActivationCommitPhaseConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationOtpValidationConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.PasswordHash;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
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
@AllArgsConstructor
public class ActivationServiceBehavior {

    /**
     * Current PowerAuth protocol major version. Activations created with lower version will be upgraded to this version.
     */
    private static final byte POWERAUTH_PROTOCOL_VERSION = 0x3;

    // Minimum date for SQL timestamps: 01/01/1970 @ 12:00am (UTC)
    private static final Date MIN_TIMESTAMP = new Date(1L);

    // Maximum date for SQL timestamps: 01/01/9999 @ 12:00am (UTC)
    private static final Date MAX_TIMESTAMP = new Date(253370764800000L);

    private final CallbackUrlBehavior callbackUrlBehavior;
    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final ActivationValidationServiceBehavior activationValidationServiceBehavior;
    private final ActivationRemoveServiceBehavior activationRemoveServiceBehavior;

    private final LocalizationProvider localizationProvider;

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final PowerAuthPageableConfiguration powerAuthPageableConfiguration;

    private final ActivationQueryService activationQueryService;

    private final CryptographyServiceFactory cryptographyServiceFactory;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final ActivationOtpValidationConverter activationOtpValidationConverter = new ActivationOtpValidationConverter();
    private final ActivationCommitPhaseConverter activationCommitPhaseConverter = new ActivationCommitPhaseConverter();

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();

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

                    activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, false);

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

    private static ActivationProtocol convert(final com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol source) {
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

            final List<String> activationFlags = request.getActivationFlags();

            final LookupActivationsResponse response = new LookupActivationsResponse();
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
            final List<String> activationIds = request.getActivationIds();
            ActivationStatus activationStatus = activationStatusConverter.convert(request.getActivationStatus());

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

            // Generate timestamp in advance
            final Date timestamp = new Date();

            // Prepare key generator
            final KeyGenerator keyGenerator = new KeyGenerator();

            final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);

            // Check if the activation exists
            if (activationOptional.isPresent()) {

                final ActivationRecordEntity activation = activationOptional.get();
                // Deactivate old pending activations first
                activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, false);

                final ApplicationEntity application = activation.getApplication();
                final String applicationId = application.getId();

                // Handle CREATED activation
                if (activation.getActivationStatus() == ActivationStatus.CREATED) {

                    // Created activations are not able to transfer valid status blob to the client
                    // since both keys were not exchanged yet and transport cannot be secured.
                    final byte[] randomStatusBlob = keyGenerator.generateRandomBytes(32);
                    // Use random nonce in case that challenge was provided.
                    final String randomStatusBlobNonce = challenge == null ? null : Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16));

                    final byte[] activationSignature = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256)
                            .generateSignatureForApplication(
                                    KeyType.ECDSA_P256,
                                    activation.getActivationCode().getBytes(StandardCharsets.UTF_8),
                                    application
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

                        // TODO - v4 support
                        final SecretKey masterSecretKey = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).deriveSharedSecretKey(activation);
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
                                    activationFingerPrint = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).generateActivationFingerprint(activation);
                            default -> {
                                // TODO - v4 support
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

            // Find activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Get current timestamp
            final Date timestamp = new Date();

            // Check already deactivated activation
            activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, true);
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

            // Validate activation OTP for stage ON_COMMIT
            activationValidationServiceBehavior.validateActivationOtp(CommitPhase.ON_COMMIT, activationOtp, activation, externalUserId);

            // Check the commit phase
            if (activation.getCommitPhase() != CommitPhase.ON_COMMIT) {
                logger.info("Invalid commit phase during commit for activation ID: {}, commit phase: {}", activationId, activation.getCommitPhase());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Change activation state to ACTIVE
            activation.setActivationStatus(ActivationStatus.ACTIVE);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

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

            // Find activation
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Get current timestamp
            final Date timestamp = new Date();

            // Check already deactivated activation
            activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, true);

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
            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });
            return removeActivation(activation, externalUserId);
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
     * @return Response with confirmation of removal.
     */
    public RemoveActivationResponse removeActivation(@NotNull ActivationRecordEntity activation, String externalUserId) {
        logger.info("Processing activation removal, activation ID: {}", activation.getActivationId());
        activationRemoveServiceBehavior.removeActivation(activation, externalUserId);
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

    public List<Activation> findByExternalId(String applicationId, String externalId) throws GenericServiceException {
        final Date timestamp = new Date();
        final List<ActivationRecordEntity> activationsList = activationQueryService.findByExternalId(applicationId, externalId);

        final List<Activation> result = new ArrayList<>();

        if (activationsList != null) {
            for (ActivationRecordEntity activation : activationsList) {

                activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, false);

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
                    activationRemoveServiceBehavior.deactivatePendingActivation(currentTimestamp, activation, false);
                } catch (GenericServiceException e) {
                    logger.error("Activation expiration failed, activation ID: {}", activation.getActivationId());
                }
            });
        }
    }

}
