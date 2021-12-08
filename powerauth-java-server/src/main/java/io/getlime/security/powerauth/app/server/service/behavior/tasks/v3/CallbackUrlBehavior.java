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

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.v3.CallbackAuthenticationPublicConverter;
import io.getlime.security.powerauth.app.server.database.model.CallbackUrlType;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Class that manages the service logic related to callback URL management.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class CallbackUrlBehavior {

    private final CallbackUrlRepository callbackUrlRepository;
    private LocalizationProvider localizationProvider;
    private PowerAuthServiceConfiguration configuration;

    private final Map<CallbackUrlEntity, RestClient> restClientCache = new HashMap<>();
    private final CallbackAuthenticationPublicConverter authenticationPublicConverter = new CallbackAuthenticationPublicConverter();

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(CallbackUrlBehavior.class);

    /**
     * Behavior constructor.
     * @param callbackUrlRepository Callback URL repository.
     */
    @Autowired
    public CallbackUrlBehavior(CallbackUrlRepository callbackUrlRepository) {
        this.callbackUrlRepository = callbackUrlRepository;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    @Autowired
    public void setConfiguration(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Creates a new callback URL record for application with given ID.
     * @param request Instance specifying parameters of the callback URL.
     * @return Newly created callback URL record.
     * @throws GenericServiceException Thrown when callback URL in request is malformed.
     */
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws GenericServiceException {

        // Check the URL format
        try {
            new URL(request.getCallbackUrl());
        } catch (MalformedURLException e) {
            logger.warn("Invalid callback URL: "+request.getCallbackUrl());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_URL_FORMAT);
        }

        CallbackUrlEntity entity = new CallbackUrlEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setApplicationId(request.getApplicationId());
        entity.setName(request.getName());
        entity.setType(CallbackUrlType.valueOf(request.getType()));
        entity.setCallbackUrl(request.getCallbackUrl());
        entity.setAttributes(request.getAttributes());
        entity.setAuthentication(request.getAuthentication());
        callbackUrlRepository.save(entity);
        CreateCallbackUrlResponse response = new CreateCallbackUrlResponse();
        response.setId(entity.getId());
        response.setApplicationId(entity.getApplicationId());
        response.setName(entity.getName());
        response.setCallbackUrl(entity.getCallbackUrl());
        if (entity.getAttributes() != null) {
            response.getAttributes().addAll(entity.getAttributes());
        }
        response.setAuthentication(authenticationPublicConverter.toPublic(entity.getAuthentication()));
        return response;
    }

    /**
     * Update a callback URL record for application with given ID.
     * @param request Instance specifying parameters of the callback URL.
     * @return Update callback URL record.
     * @throws GenericServiceException Thrown when callback URL in request is malformed or callback URL could not be found.
     */
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws GenericServiceException {

        if (request.getId() == null) {
            logger.warn("Missing callback ID");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        Optional<CallbackUrlEntity> entityOptional = callbackUrlRepository.findById(request.getId());
        if (!entityOptional.isPresent()) {
            logger.warn("Invalid callback ID: "+request.getId());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Check the URL format
        try {
            new URL(request.getCallbackUrl());
        } catch (MalformedURLException e) {
            logger.warn("Invalid callback URL: "+request.getCallbackUrl());
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_URL_FORMAT);
        }

        CallbackUrlEntity entity = entityOptional.get();
        entity.setName(request.getName());
        entity.setCallbackUrl(request.getCallbackUrl());
        entity.setAttributes(request.getAttributes());
        // Retain existing passwords in case new password is not set
        HttpAuthenticationPrivate authRequest = request.getAuthentication();
        HttpAuthenticationPrivate authExisting = entity.getAuthentication();
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
        entity.setAuthentication(authRequest);
        callbackUrlRepository.save(entity);
        UpdateCallbackUrlResponse response = new UpdateCallbackUrlResponse();
        response.setId(entity.getId());
        response.setApplicationId(entity.getApplicationId());
        response.setName(entity.getName());
        response.setType(entity.getType().toString());
        response.setCallbackUrl(entity.getCallbackUrl());
        if (entity.getAttributes() != null) {
            response.getAttributes().addAll(entity.getAttributes());
        }
        response.setAuthentication(authenticationPublicConverter.toPublic(entity.getAuthentication()));
        return response;
    }

    /**
     * Get the list of all current callback URLs for given application.
     * @param request Request with application ID to fetch the callback URL agains.
     * @return List of all current callback URLs.
     */
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) {
        final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdOrderByName(request.getApplicationId());
        GetCallbackUrlListResponse response = new GetCallbackUrlListResponse();
        for (CallbackUrlEntity callbackUrl: callbackUrlEntities) {
            GetCallbackUrlListResponse.CallbackUrlList item = new GetCallbackUrlListResponse.CallbackUrlList();
            item.setId(callbackUrl.getId());
            item.setApplicationId(callbackUrl.getApplicationId());
            item.setName(callbackUrl.getName());
            item.setType(callbackUrl.getType().toString());
            item.setCallbackUrl(callbackUrl.getCallbackUrl());
            if (callbackUrl.getAttributes() != null) {
                item.getAttributes().addAll(callbackUrl.getAttributes());
            }
            item.setAuthentication(authenticationPublicConverter.toPublic(callbackUrl.getAuthentication()));
            response.getCallbackUrlList().add(item);
        }
        return response;
    }

    /**
     * Remove callback URL with given ID.
     * @param request Request specifying the callback URL to be removed.
     * @return Information about removal status.
     */
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) {
        RemoveCallbackUrlResponse response = new RemoveCallbackUrlResponse();
        response.setId(request.getId());
        final Optional<CallbackUrlEntity> callbackUrlEntityOptional = callbackUrlRepository.findById(request.getId());
        if (callbackUrlEntityOptional.isPresent()) {
            callbackUrlRepository.delete(callbackUrlEntityOptional.get());
            response.setRemoved(true);
        } else {
            response.setRemoved(false);
        }
        return response;
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
                    Map<String, Object> callbackData = prepareCallbackDataActivation(callbackUrlEntity, activation);
                    notifyCallbackUrl(callbackUrlEntity, callbackData);
                }
            }
        } catch (RestClientException ex) {
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
        Map<String, Object> callbackData = new HashMap<>();
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
            if (operation != null && operation.getApplication() != null) {
                final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdAndTypeOrderByName(operation.getApplication().getId(), CallbackUrlType.OPERATION_STATUS_CHANGE);
                for (CallbackUrlEntity callbackUrlEntity : callbackUrlEntities) {
                    Map<String, Object> callbackData = prepareCallbackDataOperation(callbackUrlEntity, operation);
                    notifyCallbackUrl(callbackUrlEntity, callbackData);
                }
            }
        } catch (RestClientException ex) {
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
        Map<String, Object> callbackData = new HashMap<>();
        callbackData.put("operationId", operation.getId());
        if (callbackUrlEntity.getAttributes().contains("userId")) {
            callbackData.put("userId", operation.getUserId());
        }
        if (callbackUrlEntity.getAttributes().contains("applicationId")) {
            callbackData.put("applicationId", operation.getApplication().getId());
        }
        if (callbackUrlEntity.getAttributes().contains("operationType")) {
            callbackData.put("operationType", operation.getOperationType());
        }
        if (callbackUrlEntity.getAttributes().contains("parameters")) {
            callbackData.put("parameters", operation.getParameters());
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
     */
    private void notifyCallbackUrl(CallbackUrlEntity callbackUrlEntity, Map<String, Object> callbackData) throws RestClientException {
        Consumer<ResponseEntity<String>> onSuccess = response -> logger.debug("Callback succeeded, URL: {}", callbackUrlEntity.getCallbackUrl());
        Consumer<Throwable> onError = error -> logger.warn("Callback failed, URL: {}, error: {}", callbackUrlEntity.getCallbackUrl(), error.getMessage());
        ParameterizedTypeReference<String> responseType = new ParameterizedTypeReference<String>(){};
        RestClient restClient = getRestClient(callbackUrlEntity);
        restClient.postNonBlocking(callbackUrlEntity.getCallbackUrl(), callbackData, responseType, onSuccess, onError);
    }

    /**
     * Get a rest client for a callback URL entity.
     * @param callbackUrlEntity Callback URL entity.
     * @return Rest client.
     * @throws RestClientException Thrown when rest client initialization fails.
     */
    private synchronized RestClient getRestClient(CallbackUrlEntity callbackUrlEntity) throws RestClientException {
        RestClient restClient = restClientCache.get(callbackUrlEntity);
        if (restClient == null) {
            restClient = initializeRestClient(callbackUrlEntity);
            restClientCache.put(callbackUrlEntity, restClient);
        }
        return restClient;
    }

    /**
     * Initialize Rest client instance and configure it based on client configuration.
     * @param callbackUrlEntity Callback URL entity.
     */
    private RestClient initializeRestClient(CallbackUrlEntity callbackUrlEntity) throws RestClientException {
        DefaultRestClient.Builder builder = DefaultRestClient.builder();
        if (configuration.getHttpConnectionTimeout() != null) {
            builder.connectionTimeout(configuration.getHttpConnectionTimeout());
        }
        if (configuration.getHttpProxyEnabled()) {
            DefaultRestClient.ProxyBuilder proxyBuilder = builder.proxy().host(configuration.getHttpProxyHost()).port(configuration.getHttpProxyPort());
            if (configuration.getHttpProxyUsername() != null) {
                proxyBuilder.username(configuration.getHttpProxyUsername()).password(configuration.getHttpProxyPassword());
            }
        }
        HttpAuthenticationPrivate authentication = callbackUrlEntity.getAuthentication();
        HttpAuthenticationPrivate.Certificate certificateAuth = authentication.getCertificate();
        if (certificateAuth != null && certificateAuth.isEnabled()) {
            DefaultRestClient.CertificateAuthBuilder certificateAuthBuilder = builder.certificateAuth();
            if (certificateAuth.isUseCustomKeyStore()) {
                certificateAuthBuilder.enableCustomKeyStore()
                        .keyStoreLocation(certificateAuth.getKeyStoreLocation())
                        .keyStorePassword(certificateAuth.getKeyStorePassword())
                        .keyAlias(certificateAuth.getKeyAlias())
                        .keyPassword(certificateAuth.getKeyPassword());
            }
            if (certificateAuth.isUseCustomTrustStore()) {
                certificateAuthBuilder.enableCustomTruststore()
                        .trustStoreLocation(certificateAuth.getTrustStoreLocation())
                        .trustStorePassword(certificateAuth.getTrustStorePassword());
            }
        }
        HttpAuthenticationPrivate.HttpBasic httpBasicAuth = authentication.getHttpBasic();
        if (httpBasicAuth != null && httpBasicAuth.isEnabled()) {
            builder.httpBasicAuth()
                    .username(httpBasicAuth.getUsername())
                    .password(httpBasicAuth.getPassword());
        }
        return builder.build();
    }

}
