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

import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.request.CreateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.GetCallbackUrlListRequest;
import com.wultra.security.powerauth.client.model.request.RemoveCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.UpdateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthCallbacksConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.*;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlType;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlRepository;
import io.getlime.security.powerauth.app.server.service.callbacks.CallbackUrlAuthenticationCryptor;
import io.getlime.security.powerauth.app.server.service.callbacks.CallbackUrlRestClientManager;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptableString;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlConvertor;
import io.getlime.security.powerauth.app.server.service.callbacks.CallbackUrlEventQueueService;
import io.getlime.security.powerauth.app.server.service.util.TransactionUtils;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.RejectedExecutionException;
import java.util.stream.Collectors;

/**
 * Class that manages the service logic related to callback URL management.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class CallbackUrlBehavior {

    private final CallbackUrlRepository callbackUrlRepository;
    private final ApplicationRepository applicationRepository;
    private final CallbackUrlEventRepository callbackUrlEventRepository;
    private final CallbackUrlEventQueueService callbackUrlEventQueueService;
    private final PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;
    private LocalizationProvider localizationProvider;
    private final CallbackUrlAuthenticationCryptor callbackUrlAuthenticationCryptor;
    private final CallbackUrlRestClientManager callbackUrlRestClientManager;

    /**
     * Creates a new callback URL record for application with given ID.
     * @param request Instance specifying parameters of the callback URL.
     * @return Newly created callback URL record.
     * @throws GenericServiceException Thrown when callback URL in request is malformed.
     */
    @Transactional
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws GenericServiceException {
        try {
            if (request.getName() == null) {
                logger.warn("Invalid request parameter name in method createCallbackUrl");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Check the URL format
            try {
                new URL(request.getCallbackUrl());
            } catch (MalformedURLException e) {
                logger.warn("Invalid callback URL: {}", request.getCallbackUrl());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_URL_FORMAT);
            }

            final String applicationId = request.getApplicationId();
            final Optional<ApplicationEntity> applicationEntityOptional = applicationRepository.findById(applicationId);

            if (applicationEntityOptional.isEmpty()) {
                logger.warn("Invalid callback URL application ID: {}", request.getApplicationId());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            final CallbackUrlEntity entity = new CallbackUrlEntity();
            entity.setId(UUID.randomUUID().toString());
            entity.setApplication(applicationEntityOptional.get());
            entity.setName(request.getName());
            entity.setType(CallbackUrlType.valueOf(request.getType()));
            entity.setCallbackUrl(request.getCallbackUrl());
            entity.setAttributes(request.getAttributes());
            final EncryptableString encrypted = callbackUrlAuthenticationCryptor.encrypt(request.getAuthentication(), entity.getApplication().getId());
            entity.setAuthentication(encrypted.encryptedData());
            entity.setEncryptionMode(encrypted.encryptionMode());
            callbackUrlRepository.save(entity);
            final CreateCallbackUrlResponse response = new CreateCallbackUrlResponse();
            response.setId(entity.getId());
            response.setApplicationId(entity.getApplication().getId());
            response.setName(entity.getName());
            response.setCallbackUrl(entity.getCallbackUrl());
            if (entity.getAttributes() != null) {
                response.getAttributes().addAll(entity.getAttributes());
            }
            response.setAuthentication(callbackUrlAuthenticationCryptor.decryptToPublic(entity));
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
     * Update a callback URL record for application with given ID.
     * @param request Instance specifying parameters of the callback URL.
     * @return Update callback URL record.
     * @throws GenericServiceException Thrown when callback URL in request is malformed or callback URL could not be found.
     */
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws GenericServiceException {
        try {
            if (request.getId() == null || request.getApplicationId() == null || request.getName() == null || request.getAttributes() == null) {
                logger.warn("Invalid request in method updateCallbackUrl");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final CallbackUrlEntity entity = callbackUrlRepository.findById(request.getId())
                    .filter(it -> it.getApplication().getId().equals(request.getApplicationId()))
                    .orElseThrow(() -> {
                        // Rollback is not required, error occurs before writing to database
                        logger.warn("Invalid callback ID: {}", request.getId());
                        return localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                    });

            // Check the URL format
            try {
                new URL(request.getCallbackUrl());
            } catch (MalformedURLException e) {
                logger.warn("Invalid callback URL: {}", request.getCallbackUrl());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_URL_FORMAT);
            }

            callbackUrlRestClientManager.evictRestClientFromCache(entity);

            entity.setName(request.getName());
            entity.setCallbackUrl(request.getCallbackUrl());
            entity.setAttributes(request.getAttributes());
            // Retain existing passwords in case new password is not set
            final HttpAuthenticationPrivate authRequest = request.getAuthentication();
            final CallbackUrlAuthentication authExisting = callbackUrlAuthenticationCryptor.decrypt(entity);
            if (authRequest != null) {
                if (authRequest.getCertificate() != null && authExisting.getCertificate() != null) {
                    if (authExisting.getCertificate().getKeyStorePassword() != null && authRequest.getCertificate().getKeyStorePassword() == null) {
                        authRequest.getCertificate().setKeyStorePassword(authExisting.getCertificate().getKeyStorePassword());
                    }
                    if (authExisting.getCertificate().getKeyPassword() != null && authRequest.getCertificate().getKeyPassword() == null) {
                        authRequest.getCertificate().setKeyPassword(authExisting.getCertificate().getKeyPassword());
                    }
                    if (authExisting.getCertificate().getTrustStorePassword() != null && authRequest.getCertificate().getTrustStorePassword() == null) {
                        authRequest.getCertificate().setTrustStorePassword(authExisting.getCertificate().getTrustStorePassword());
                    }
                }
                if (authRequest.getHttpBasic() != null && authExisting.getHttpBasic() != null) {
                    if (authExisting.getHttpBasic().getPassword() != null && authRequest.getHttpBasic().getPassword() == null) {
                        authRequest.getHttpBasic().setPassword(authExisting.getHttpBasic().getPassword());
                    }
                }
                if (authRequest.getOAuth2() != null && authExisting.getOAuth2() != null && authExisting.getOAuth2().getClientSecret() != null && authRequest.getOAuth2().getClientSecret() == null) {
                    authRequest.getOAuth2().setClientSecret(authExisting.getOAuth2().getClientSecret());
                }
            }
            final EncryptableString encrypted = callbackUrlAuthenticationCryptor.encrypt(authRequest, entity.getApplication().getId());
            entity.setAuthentication(encrypted.encryptedData());
            entity.setEncryptionMode(encrypted.encryptionMode());
            callbackUrlRepository.save(entity);

            final UpdateCallbackUrlResponse response = new UpdateCallbackUrlResponse();
            response.setId(entity.getId());
            response.setApplicationId(entity.getApplication().getId());
            response.setName(entity.getName());
            response.setType(entity.getType().toString());
            response.setCallbackUrl(entity.getCallbackUrl());
            if (entity.getAttributes() != null) {
                response.getAttributes().addAll(entity.getAttributes());
            }
            response.setAuthentication(callbackUrlAuthenticationCryptor.decryptToPublic(entity));
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
     * Get the list of all current callback URLs for given application.
     * @param request Request with application ID to fetch the callback URL agains.
     * @return List of all current callback URLs.
     */
    @Transactional(readOnly = true)
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws GenericServiceException {
        try {
            final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdOrderByName(request.getApplicationId());
            final GetCallbackUrlListResponse response = new GetCallbackUrlListResponse();
            for (CallbackUrlEntity callbackUrl : callbackUrlEntities) {
                final CallbackUrl item = new CallbackUrl();
                item.setId(callbackUrl.getId());
                item.setApplicationId(callbackUrl.getApplication().getId());
                item.setName(callbackUrl.getName());
                item.setType(callbackUrl.getType().toString());
                item.setCallbackUrl(callbackUrl.getCallbackUrl());
                if (callbackUrl.getAttributes() != null) {
                    item.getAttributes().addAll(callbackUrl.getAttributes());
                }
                item.setAuthentication(callbackUrlAuthenticationCryptor.decryptToPublic(callbackUrl));
                response.getCallbackUrlList().add(item);
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
     * Remove callback URL with given ID.
     * @param request Request specifying the callback URL to be removed.
     * @return Information about removal status.
     */
    @Transactional
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws GenericServiceException {
        try {
            final RemoveCallbackUrlResponse response = new RemoveCallbackUrlResponse();
            response.setId(request.getId());
            final Optional<CallbackUrlEntity> callbackUrlEntityOptional = callbackUrlRepository.findById(request.getId());
            if (callbackUrlEntityOptional.isPresent()) {
                final CallbackUrlEntity callbackEntity = callbackUrlEntityOptional.get();
                callbackUrlRestClientManager.evictRestClientFromCache(callbackEntity);
                callbackUrlRepository.delete(callbackEntity);
                response.setRemoved(true);
            } else {
                response.setRemoved(false);
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
     * Tries to asynchronously notify all activation status callbacks that are registered for given application.
     * @param activation Activation to be notified about.
     */
    public void notifyCallbackListenersOnActivationChange(ActivationRecordEntity activation) {
        try {
            if (activation != null && activation.getApplication() != null) {
                final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdAndTypeOrderByName(activation.getApplication().getId(), CallbackUrlType.ACTIVATION_STATUS_CHANGE);
                for (CallbackUrlEntity callbackUrlEntity : callbackUrlEntities) {
                    final Map<String, Object> callbackData = prepareCallbackDataActivation(callbackUrlEntity, activation);
                    notifyCallbackUrl(callbackUrlEntity, callbackData);
                }
            }
        } catch (RestClientException | GenericServiceException ex) {
            // Log the error in case Rest client initialization failed
            logger.error(ex.getMessage(), ex);
        }
    }

    /**
     * Prepare callback data for given callback URL entity and activation entity.
     * @param callbackUrlEntity Callback URL entity.
     * @param activation Activation entity.
     * @return Callback data to send.
     */
    private Map<String, Object> prepareCallbackDataActivation(CallbackUrlEntity callbackUrlEntity, ActivationRecordEntity activation) {
        final Map<String, Object> callbackData = new HashMap<>();
        callbackData.put("type", "ACTIVATION");
        callbackData.put("activationId", activation.getActivationId());
        if (callbackUrlEntity.getAttributes().contains("userId")) {
            callbackData.put("userId", activation.getUserId());
        }
        if (callbackUrlEntity.getAttributes().contains("activationName")) {
            callbackData.put("activationName", activation.getActivationName());
        }
        if (callbackUrlEntity.getAttributes().contains("deviceInfo")) {
            callbackData.put("deviceInfo", activation.getDeviceInfo());
        }
        if (callbackUrlEntity.getAttributes().contains("platform")) {
            callbackData.put("platform", activation.getPlatform());
        }
        if (callbackUrlEntity.getAttributes().contains("protocol")) {
            callbackData.put("protocol", activation.getProtocol());
        }
        if (callbackUrlEntity.getAttributes().contains("activationFlags")) {
            callbackData.put("activationFlags", activation.getFlags());
        }
        if (callbackUrlEntity.getAttributes().contains("activationStatus")) {
            callbackData.put("activationStatus", activation.getActivationStatus());
        }
        if (callbackUrlEntity.getAttributes().contains("blockedReason")) {
            callbackData.put("blockedReason", activation.getBlockedReason());
        }
        if (callbackUrlEntity.getAttributes().contains("applicationId")) {
            callbackData.put("applicationId", activation.getApplication().getId());
        }
        return callbackData;
    }


    /**
     * Tries to asynchronously notify all operation callbacks that are registered for given application.
     * @param operation Operation to be notified about.
     */
    public void notifyCallbackListenersOnOperationChange(OperationEntity operation) {
        try {
            if (operation != null && operation.getApplications() != null && !operation.getApplications().isEmpty()) {
                for (ApplicationEntity application : operation.getApplications()) {
                    final Iterable<CallbackUrlEntity> callbackUrlEntities = application.getCallbacks()
                            .stream()
                            .filter(callbackUrlEntity -> CallbackUrlType.OPERATION_STATUS_CHANGE == callbackUrlEntity.getType())
                            .toList();

                    for (CallbackUrlEntity callbackUrlEntity : callbackUrlEntities) {
                        final Map<String, Object> callbackData = prepareCallbackDataOperation(callbackUrlEntity, operation);
                        notifyCallbackUrl(callbackUrlEntity, callbackData);
                    }
                }
            }
        } catch (RestClientException | GenericServiceException ex) {
            // Log the error in case Rest client initialization failed
            logger.error(ex.getMessage(), ex);
        }
    }

    /**
     * Prepare callback data for given callback URL entity and Operation entity.
     * @param callbackUrlEntity Callback URL entity.
     * @param operation Operation entity.
     * @return Callback data to send.
     */
    private Map<String, Object> prepareCallbackDataOperation(CallbackUrlEntity callbackUrlEntity, OperationEntity operation) {
        final Map<String, Object> callbackData = new HashMap<>();
        callbackData.put("type", "OPERATION");
        callbackData.put("operationId", operation.getId());
        if (callbackUrlEntity.getAttributes().contains("userId")) {
            callbackData.put("userId", operation.getUserId());
        }
        if (callbackUrlEntity.getAttributes().contains("applications")) {
            final List<String> appIds = operation.getApplications()
                    .stream().map(ApplicationEntity::getId)
                    .collect(Collectors.toList());
            callbackData.put("applications", appIds);
        }
        if (callbackUrlEntity.getAttributes().contains("operationType")) {
            callbackData.put("operationType", operation.getOperationType());
        }
        if (callbackUrlEntity.getAttributes().contains("parameters")) {
            callbackData.put("parameters", operation.getParameters());
        }
        if (callbackUrlEntity.getAttributes().contains("additionalData")) {
            callbackData.put("additionalData", OperationServiceBehavior.extendAdditionalDataWithDevice(operation.getAdditionalData()));
        }
        if (callbackUrlEntity.getCallbackUrl().contains("activationFlag")) {
            callbackData.put("activationFlag", operation.getActivationFlag());
        }
        if (callbackUrlEntity.getAttributes().contains("status")) {
            callbackData.put("status", operation.getStatus());
        }
        if (callbackUrlEntity.getAttributes().contains("data")) {
            callbackData.put("data", operation.getData());
        }
        if (callbackUrlEntity.getAttributes().contains("failureCount")) {
            callbackData.put("failureCount", operation.getFailureCount());
        }
        if (callbackUrlEntity.getAttributes().contains("maxFailureCount")) {
            callbackData.put("maxFailureCount", operation.getMaxFailureCount());
        }
        if (callbackUrlEntity.getAttributes().contains("signatureType")) {
            callbackData.put("signatureType", operation.getSignatureType());
        }
        if (callbackUrlEntity.getAttributes().contains("externalId")) {
            callbackData.put("externalId", operation.getExternalId());
        }
        if (callbackUrlEntity.getAttributes().contains("timestampCreated")) {
            callbackData.put("timestampCreated", operation.getTimestampCreated());
        }
        if (callbackUrlEntity.getAttributes().contains("timestampExpires")) {
            callbackData.put("timestampExpires", operation.getTimestampExpires());
        }
        if (callbackUrlEntity.getAttributes().contains("timestampFinalized")) {
            callbackData.put("timestampFinalized", operation.getTimestampFinalized());
        }
        return callbackData;
    }

    // Private methods

    /**
     * Notify callback URL.
     * @param callbackUrlEntity Callback URL entity.
     * @param callbackData Callback data.
     * @throws RestClientException Thrown when HTTP request fails.
     * @throws GenericServiceException Thrown when callback configuration is wrong.
     */
    private void notifyCallbackUrl(CallbackUrlEntity callbackUrlEntity, Map<String, Object> callbackData) throws RestClientException, GenericServiceException {
        if (!isMaxAttemptsPositive(callbackUrlEntity)) {
            logger.info("Callback URL is configured with non-positive max attempts: callbackUrlId={}", callbackUrlEntity.getId());
            return;
        }

        final LocalDateTime timestampNow = LocalDateTime.now();

        final CallbackUrlEventEntity callbackUrlEventEntity = new CallbackUrlEventEntity();
        callbackUrlEventEntity.setIdempotencyKey(UUID.randomUUID().toString());
        callbackUrlEventEntity.setCallbackUrlEntity(callbackUrlEntity);
        callbackUrlEventEntity.setCallbackData(callbackData);
        callbackUrlEventEntity.setTimestampCreated(timestampNow);
        callbackUrlEventEntity.setTimestampLastCall(timestampNow);
        callbackUrlEventEntity.setAttempts(0);
        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.PROCESSING);
        final CallbackUrlEventEntity savedEventEntity = callbackUrlEventRepository.save(callbackUrlEventEntity);

        final CallbackUrlEvent callbackUrlEvent = CallbackUrlConvertor.convert(savedEventEntity);
        TransactionUtils.executeAfterTransactionCommits(
                () -> enqueue(callbackUrlEvent)
        );
    }

    /**
     * Try to submit a Callback URL Event to a task executor.
     * If rejected, enqueue the Callback URL Event to a database.
     * @param callbackUrlEvent Callback URL Event to enqueue
     */
    private void enqueue(final CallbackUrlEvent callbackUrlEvent) {
        try {
            callbackUrlEventQueueService.submitToExecutor(callbackUrlEvent);
        } catch (RejectedExecutionException e) {
            logger.debug("CallbackUrlEventEntity was rejected by the executor: callbackUrlEntityId={}", callbackUrlEvent.callbackUrlEventEntityId());
            callbackUrlEventQueueService.enqueueToDatabase(callbackUrlEvent);
        }
    }

    /**
     * Check if a Callback URL is configured to be dispatched at least once.
     * @param callbackUrlEntity Callback URL to check.
     * @return True if the Callback URL should be dispatched at least once, false otherwise.
     */
    private boolean isMaxAttemptsPositive(final CallbackUrlEntity callbackUrlEntity) {
        final int maxAttempts = Objects.requireNonNullElse(callbackUrlEntity.getMaxAttempts(), powerAuthCallbacksConfiguration.getDefaultMaxAttempts());
        return maxAttempts > 0;
    }

}
