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
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.app.server.database.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.ConfirmActivationRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.util.PasswordHash;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

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
    private final ActivationRepository activationRepository;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

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
                    activationServiceItem.setAdditionalData(activation.getAdditionalData());
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
                activationServiceItem.setAdditionalData(activation.getAdditionalData());
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
     * Confirm activation with given ID.
     *
     * @param request Confirm activation request.
     * @throws GenericServiceException In case invalid data is provided or activation is not found, in invalid state or already expired.
     */
    @Transactional
    public void confirmActivation(ConfirmActivationRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();

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

            // Check whether activation is in correct state for confirmation:
            // - PENDING_COMMIT for activation without autocommit
            // - ACTIVE for activation with autocommit
            if (activation.getActivationStatus() != ActivationStatus.PENDING_COMMIT && activation.getActivationStatus() != ActivationStatus.ACTIVE) {
                logger.info("Activation is in invalid state during confirmation, activation ID: {}, activation state: {}", activationId, activation.getActivationStatus());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Check whether activation was not confirmed before
            if (!activation.isConfirmationPending()) {
                logger.info("Activation is already confirmed, activation ID: {}, activation state: {}", activationId, activation.getActivationStatus());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Enable the biometric factor in case it was enabled in mobile SDK
            activation.setBiometricFactorEnabled(request.isEnableBiometry());

            activation.setConfirmationPending(false);
            activationRepository.save(activation);

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

            changeActivationStatusToActiveAndDeleteParent(activation);
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

    private void changeActivationStatusToActiveAndDeleteParent(final ActivationRecordEntity activation) {
        activation.setActivationStatus(ActivationStatus.ACTIVE);

        final ActivationRecordEntity parentActivation = activation.getParentActivation();
        if (parentActivation != null && activation.getTransferType() == ActivationTransferType.MOVE) {
            logger.info("Deleting activation ID: {}, because is parent of moved activation ID :{}", parentActivation.getActivationId(), activation.getActivationId());
            activationRemoveServiceBehavior.removeActivation(parentActivation, null);
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
