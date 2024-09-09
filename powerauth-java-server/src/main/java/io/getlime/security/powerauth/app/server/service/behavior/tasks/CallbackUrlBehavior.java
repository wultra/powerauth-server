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

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPublic;
import com.wultra.security.powerauth.client.model.request.CreateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.GetCallbackUrlListRequest;
import com.wultra.security.powerauth.client.model.request.RemoveCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.UpdateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.CallbackAuthenticationConverter;
import io.getlime.security.powerauth.app.server.converter.CallbackAuthenticationPublicConverter;
import io.getlime.security.powerauth.app.server.database.model.entity.*;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlType;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlRepository;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptableString;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptionService;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;
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
    private LocalizationProvider localizationProvider;
    private PowerAuthServiceConfiguration configuration;
    private CallbackAuthenticationConverter callbackAuthenticationConverter;
    private EncryptionService encryptionService;

    // Store REST clients in cache with their callback ID as a key
    private final Map<String, RestClient> restClientCache = new ConcurrentHashMap<>();
    private final Object restClientCacheLock = new Object();

    private final CallbackAuthenticationPublicConverter authenticationPublicConverter = new CallbackAuthenticationPublicConverter();

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
            final EncryptableString encrypted = encrypt(request.getAuthentication(), entity.getApplication().getId());
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
            response.setAuthentication(decryptToPublic(entity));
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

            evictRestClientFromCache(entity);

            entity.setName(request.getName());
            entity.setCallbackUrl(request.getCallbackUrl());
            entity.setAttributes(request.getAttributes());
            // Retain existing passwords in case new password is not set
            final HttpAuthenticationPrivate authRequest = request.getAuthentication();
            final CallbackUrlAuthentication authExisting = decrypt(entity);
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
            final EncryptableString encrypted = encrypt(authRequest, entity.getApplication().getId());
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
            response.setAuthentication(decryptToPublic(entity));
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
                item.setAuthentication(decryptToPublic(callbackUrl));
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
                evictRestClientFromCache(callbackEntity);
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
        final Consumer<ResponseEntity<String>> onSuccess = response -> logger.info("Callback succeeded, URL: {}", callbackUrlEntity.getCallbackUrl());
        final Consumer<Throwable> onError = error -> logger.warn("Callback failed, URL: {}, error: {}", callbackUrlEntity.getCallbackUrl(), error.getMessage());
        final ParameterizedTypeReference<String> responseType = new ParameterizedTypeReference<>(){};
        final RestClient restClient = getRestClient(callbackUrlEntity);
        restClient.postNonBlocking(callbackUrlEntity.getCallbackUrl(), callbackData, responseType, onSuccess, onError);
    }

    /**
     * Get a rest client for a callback URL entity.
     * @param callbackUrlEntity Callback URL entity.
     * @return Rest client.
     * @throws RestClientException Thrown when rest client initialization fails.
     * @throws GenericServiceException Thrown when callback configuration is wrong.
     */
    private RestClient getRestClient(final CallbackUrlEntity callbackUrlEntity) throws RestClientException, GenericServiceException {
        final String cacheKey = getRestClientCacheKey(callbackUrlEntity);
        RestClient restClient;
        synchronized (restClientCacheLock) {
            restClient = restClientCache.get(cacheKey);
            if (restClient == null) {
                logger.debug("REST client not found in cache, initializing new REST client, callback cache key: {}", cacheKey);
                restClient = createRestClientAndStoreInCache(callbackUrlEntity);
            } else {
                logger.debug("REST client found in cache, callback cache key: {}", cacheKey);
            }
        }
        return restClient;
    }

    /**
     * Get a key for the REST client cache from a callback URL entity.
     * @param callbackUrlEntity Callback URL entity.
     * @return Cache key.
     */
    private String getRestClientCacheKey(final CallbackUrlEntity callbackUrlEntity) {
        return callbackUrlEntity.getId();
    }

    /**
     * Create a new REST client and store it in cache for given callback URL entity.
     * @param callbackUrlEntity Callback URL entity.
     * @return Rest client.
     */
    public RestClient createRestClientAndStoreInCache(final CallbackUrlEntity callbackUrlEntity) throws RestClientException, GenericServiceException {
        final String cacheKey = getRestClientCacheKey(callbackUrlEntity);
        final RestClient restClient = initializeRestClient(callbackUrlEntity);
        restClientCache.put(cacheKey, restClient);
        return restClient;
    }

    /**
     * Evict an instance from REST client cache for given callback URL entity.
     * @param callbackUrlEntity Callback URL entity.
     */
    private void evictRestClientFromCache(final CallbackUrlEntity callbackUrlEntity) {
        synchronized (restClientCacheLock) {
            restClientCache.remove(getRestClientCacheKey(callbackUrlEntity));
        }
    }

    /**
     * Initialize Rest client instance and configure it based on client configuration.
     * @param callbackUrlEntity Callback URL entity.
     */
    private RestClient initializeRestClient(CallbackUrlEntity callbackUrlEntity) throws RestClientException, GenericServiceException {
        final DefaultRestClient.Builder builder = DefaultRestClient.builder();
        if (configuration.getHttpConnectionTimeout() != null) {
            builder.connectionTimeout(configuration.getHttpConnectionTimeout());
        }
        if (configuration.getHttpResponseTimeout() != null) {
            builder.responseTimeout(configuration.getHttpResponseTimeout());
        }
        if (configuration.getHttpMaxIdleTime() != null) {
            builder.maxIdleTime(configuration.getHttpMaxIdleTime());
        }
        if (configuration.getHttpProxyEnabled()) {
            final DefaultRestClient.ProxyBuilder proxyBuilder = builder.proxy().host(configuration.getHttpProxyHost()).port(configuration.getHttpProxyPort());
            if (configuration.getHttpProxyUsername() != null) {
                proxyBuilder.username(configuration.getHttpProxyUsername()).password(configuration.getHttpProxyPassword());
            }
        }
        final CallbackUrlAuthentication authentication = decrypt(callbackUrlEntity);
        final CallbackUrlAuthentication.Certificate certificateAuth = authentication.getCertificate();
        if (certificateAuth != null && certificateAuth.isEnabled()) {
            final DefaultRestClient.CertificateAuthBuilder certificateAuthBuilder = builder.certificateAuth();
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
        final CallbackUrlAuthentication.HttpBasic httpBasicAuth = authentication.getHttpBasic();
        if (httpBasicAuth != null && httpBasicAuth.isEnabled()) {
            builder.httpBasicAuth()
                    .username(httpBasicAuth.getUsername())
                    .password(httpBasicAuth.getPassword());
        }

        final CallbackUrlAuthentication.OAuth2 oAuth2Config = authentication.getOAuth2();
        if (oAuth2Config != null && oAuth2Config.isEnabled()) {
            builder.filter(configureOAuth2ExchangeFilter(oAuth2Config, callbackUrlEntity.getId()));
        }

        return builder.build();
    }

    private static ServerOAuth2AuthorizedClientExchangeFilterFunction configureOAuth2ExchangeFilter(final CallbackUrlAuthentication.OAuth2 config, final String callbackId) {
        logger.debug("Configuring OAuth2 for callback ID: {}", callbackId);
        final String registrationId = "callback OAuth2";
        final ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(registrationId)
                .tokenUri(config.getTokenUri())
                .clientId(config.getClientId())
                .clientSecret(config.getClientSecret())
                .scope(config.getScope())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        final ReactiveClientRegistrationRepository clientRegistrations = new InMemoryReactiveClientRegistrationRepository(clientRegistration);
        final ReactiveOAuth2AuthorizedClientService clientService = new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrations);

        final AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(clientRegistrations, clientService);
        final ServerOAuth2AuthorizedClientExchangeFilterFunction oAuth2ExchangeFilterFunction = new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oAuth2ExchangeFilterFunction.setDefaultClientRegistrationId(registrationId);
        return oAuth2ExchangeFilterFunction;
    }

    private EncryptableString encrypt(final HttpAuthenticationPrivate source, final String applicationId) throws GenericServiceException {
        final CallbackUrlAuthentication callbackAuthentication = authenticationPublicConverter.fromNetworkObject(source);
        final String callbackAuthenticationString = callbackAuthenticationConverter.convertToDatabaseColumn(callbackAuthentication);
        return encryptionService.encrypt(callbackAuthenticationString, createEncryptionKeyProvider(applicationId));
    }

    private CallbackUrlAuthentication decrypt(final CallbackUrlEntity entity) throws GenericServiceException {
        final String authentication = entity.getAuthentication();
        if (authentication == null) {
            return new CallbackUrlAuthentication();
        }
        final String existingCallbackAuthenticationString = encryptionService.decrypt(authentication, entity.getEncryptionMode(), createEncryptionKeyProvider(entity.getApplication().getId()));
        return callbackAuthenticationConverter.convertToEntityAttribute(existingCallbackAuthenticationString);
    }

    private HttpAuthenticationPublic decryptToPublic(final CallbackUrlEntity entity) throws GenericServiceException {
        final CallbackUrlAuthentication authentication = decrypt(entity);
        return authenticationPublicConverter.toPublic(authentication);
    }

    private static Supplier<List<String>> createEncryptionKeyProvider(final String applicationId) {
        return () -> List.of(applicationId);
    }
}
