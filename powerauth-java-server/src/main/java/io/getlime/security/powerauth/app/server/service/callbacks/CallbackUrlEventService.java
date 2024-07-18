/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.service.callbacks;

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthCallbacksConfiguration;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlAuthentication;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.domain.PageRequest;
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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Service dispatching Callback URL Events.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class CallbackUrlEventService {

    /**
     * States of callback events that are eligible for being processed.
     */
    private static final Set<CallbackUrlEventStatus> EVENT_STATES_TO_BE_PROCESSED = EnumSet.of(CallbackUrlEventStatus.PENDING, CallbackUrlEventStatus.FAILED);

    private CallbackUrlEventRepository callbackUrlEventRepository;
    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;
    private CallbackUrlAuthenticationCryptor callbackUrlAuthenticationCryptor;

    // Store REST clients in cache with their callback ID as a key
    private final Map<String, RestClient> restClientCache = new ConcurrentHashMap<>();
    private final Object restClientCacheLock = new Object();

    /**
     * Dispatch a pending Callback URL Event.
     * @param callbackUrlEventEntity Callback URL Event to dispatch.
     */
    @Transactional
    public void dispatchPendingCallbackUrlEvent(final CallbackUrlEventEntity callbackUrlEventEntity) {
        callbackUrlEventRepository.findPendingByIdWithTryLock(callbackUrlEventEntity.getId())
                .ifPresentOrElse(
                        this::dispatchEvent,
                        () -> logger.debug("Published CallbackUrlEvent {} is no longer waiting to be processed.", callbackUrlEventEntity.getId())
                );
    }

    /**
     * Dispatch again Callback URL Events, that previously failed and are eligible for another attempt.
     */
    @Transactional
    public void dispatchFailedCallbackUrlEvents() {
        final PageRequest pageRequest = PageRequest.of(0, powerAuthCallbacksConfiguration.getFailedCallbackUrlEventsRetryLimit());
        callbackUrlEventRepository.findScheduledForRetry(LocalDateTime.now(), pageRequest)
                .forEach(this::dispatchEvent);
    }

    /**
     * Dispatch Callback URL Events in pending state.
     * <p>
     * This method acts as a safety net to ensure that any events which were not received by the Callback URL Event
     * listener are processed and dispatched.
     */
    @Transactional
    public void dispatchPendingCallbackUrlEvents() {
        final PageRequest pageRequest = PageRequest.of(0, powerAuthCallbacksConfiguration.getPendingCallbackUrlEventsDispatchLimit());
        callbackUrlEventRepository.findPendingWithLock(pageRequest)
                .forEach(this::dispatchEvent);
    }

    /**
     * Delete Callback URL Events, that are past their retention period.
     */
    @Transactional
    public void deleteCallbackUrlEventsAfterRetentionPeriod() {
        callbackUrlEventRepository.deleteAllAfterRetentionPeriod(LocalDateTime.now());
    }

    /**
     * Dispatch Callback URL Event.
     * @param callbackUrlEventEntity Event to dispatch.
     */
    private void dispatchEvent(final CallbackUrlEventEntity callbackUrlEventEntity) {
        if (!shouldBeProcessed(callbackUrlEventEntity)) {
            logger.debug("Callback URL Event {} should not be processed, state={}", callbackUrlEventEntity.getId(), callbackUrlEventEntity.getStatus());
            return;
        }

        markAsProcessing(callbackUrlEventEntity);

        final CallbackUrlEntity callbackUrlEntity = callbackUrlEventEntity.getCallbackUrlEntity();
        try {
            final Consumer<ResponseEntity<String>> onSuccess = response -> handleCallbackSuccess(callbackUrlEventEntity);
            final Consumer<Throwable> onError = error -> handleCallbackFailure(callbackUrlEventEntity, error);
            final ParameterizedTypeReference<String> responseType = new ParameterizedTypeReference<>(){};

            final RestClient restClient = getRestClient(callbackUrlEntity);

            final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
            headers.add("Idempotency-Key", callbackUrlEventEntity.getId());

            restClient.postNonBlocking(callbackUrlEntity.getCallbackUrl(),
                    callbackUrlEventEntity.getCallbackData(),
                    new LinkedMultiValueMap<>(),
                    headers,
                    responseType,
                    onSuccess,
                    onError);

            logger.debug("CallbackUrlEvent {} was dispatched.", callbackUrlEventEntity.getId());
        } catch (RestClientException | GenericServiceException e) {
            handleCallbackFailure(callbackUrlEventEntity, e);
        }
    }

    /**
     * Check if a Callback URL Event should be processed.
     * @param callbackUrlEventEntity Callback URL Event to check.
     * @return True if the Callback URL Event should be processed, false otherwise.
     */
    private static boolean shouldBeProcessed(final CallbackUrlEventEntity callbackUrlEventEntity) {
        return EVENT_STATES_TO_BE_PROCESSED.contains(callbackUrlEventEntity.getStatus());
    }

    /**
     * Handle successful Callback URL Event attempt.
     * @param callbackUrlEventEntity Callback URL Event successfully delivered.
     */
    private void handleCallbackSuccess(CallbackUrlEventEntity callbackUrlEventEntity) {
        logger.info("Callback succeeded, URL={}, callbackEventId={}", callbackUrlEventEntity.getCallbackUrlEntity().getCallbackUrl(), callbackUrlEventEntity.getId());

        final Duration retentionPeriod = Objects.requireNonNullElse(callbackUrlEventEntity.getCallbackUrlEntity().getRetentionPeriod(), powerAuthCallbacksConfiguration.getDefaultRetentionPeriod());
        callbackUrlEventEntity.setTimestampDeleteAfter(callbackUrlEventEntity.getTimestampCreated().plus(retentionPeriod));

        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.COMPLETED);
        callbackUrlEventRepository.save(callbackUrlEventEntity);
    }

    /**
     * Handle failure of callback attempt.
     * @param callbackUrlEventEntity Failed Callback URL Event.
     * @param error Exception describing the cause of failure.
     */
    private void handleCallbackFailure(final CallbackUrlEventEntity callbackUrlEventEntity, final Throwable error) {
        logger.info("Callback failed, URL={}, callbackEventId={}, error={}", callbackUrlEventEntity.getCallbackUrlEntity().getCallbackUrl(), callbackUrlEventEntity.getId(), error.getMessage());

        final CallbackUrlEntity callbackUrlEntity = callbackUrlEventEntity.getCallbackUrlEntity();
        final int maxAttempts = Objects.requireNonNullElse(callbackUrlEntity.getMaxAttempts(), powerAuthCallbacksConfiguration.getDefaultMaxAttempts());
        final int attemptsMade = callbackUrlEventEntity.getAttempts();

        if (attemptsMade < maxAttempts) {
            final long initialBackoff = Objects.requireNonNullElse(callbackUrlEntity.getInitialBackoff(), powerAuthCallbacksConfiguration.getDefaultInitialBackoffMilliseconds());
            final Duration backoffPeriod = calculateExponentialBackoffPeriod(callbackUrlEventEntity.getAttempts(), initialBackoff, powerAuthCallbacksConfiguration.getBackoffMultiplier(), powerAuthCallbacksConfiguration.getMaxBackoffMilliseconds());
            callbackUrlEventEntity.setTimestampNextCall(callbackUrlEventEntity.getTimestampLastCall().plus(backoffPeriod));
        } else {
            final Duration retentionPeriod = Objects.requireNonNullElse(callbackUrlEventEntity.getCallbackUrlEntity().getRetentionPeriod(), powerAuthCallbacksConfiguration.getDefaultRetentionPeriod());
            callbackUrlEventEntity.setTimestampDeleteAfter(callbackUrlEventEntity.getTimestampCreated().plus(retentionPeriod));
        }

        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.FAILED);
        callbackUrlEventRepository.save(callbackUrlEventEntity);
    }

    /**
     * Set a Callback URL Event as currently being processed.
     * @param callbackUrlEventEntity The Callback URL Event to set as currently being processed.
     */
    private void markAsProcessing(final CallbackUrlEventEntity callbackUrlEventEntity) {
        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.PROCESSING);
        callbackUrlEventEntity.setTimestampNextCall(null);
        callbackUrlEventEntity.setTimestampLastCall(LocalDateTime.now());
        callbackUrlEventEntity.setAttempts(callbackUrlEventEntity.getAttempts() + 1);
        callbackUrlEventRepository.save(callbackUrlEventEntity);
    }

    /**
     * Calculate back off period for next retry attempt using exponential backoff strategy.
     * @param attempts Number of already made attempts.
     * @param initialBackoff Initial backoff.
     * @return Duration between last and next attempt.
     */
     private static Duration calculateExponentialBackoffPeriod(final int attempts, final long initialBackoff, final double multiplier, final long maxBackoffMilliseconds) {
        if (attempts < 0) {
            throw new IllegalArgumentException("Attempts must be non-negative.");
        }

        if (initialBackoff < 0) {
            throw new IllegalArgumentException("Initial backoff must be non-negative.");
        }

        if (attempts == 0) {
            return Duration.ZERO;
        }

        final long backoff = (long) (initialBackoff * Math.pow(multiplier, attempts - 1));
        return Duration.ofMillis(Math.min(backoff, maxBackoffMilliseconds));
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
    public void evictRestClientFromCache(final CallbackUrlEntity callbackUrlEntity) {
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
        if (powerAuthServiceConfiguration.getHttpConnectionTimeout() != null) {
            builder.connectionTimeout(powerAuthServiceConfiguration.getHttpConnectionTimeout());
        }
        if (powerAuthServiceConfiguration.getHttpResponseTimeout() != null) {
            builder.responseTimeout(powerAuthServiceConfiguration.getHttpResponseTimeout());
        }
        if (powerAuthServiceConfiguration.getHttpMaxIdleTime() != null) {
            builder.maxIdleTime(powerAuthServiceConfiguration.getHttpMaxIdleTime());
        }
        if (powerAuthServiceConfiguration.getHttpProxyEnabled()) {
            final DefaultRestClient.ProxyBuilder proxyBuilder = builder.proxy().host(powerAuthServiceConfiguration.getHttpProxyHost()).port(powerAuthServiceConfiguration.getHttpProxyPort());
            if (powerAuthServiceConfiguration.getHttpProxyUsername() != null) {
                proxyBuilder.username(powerAuthServiceConfiguration.getHttpProxyUsername()).password(powerAuthServiceConfiguration.getHttpProxyPassword());
            }
        }
        final CallbackUrlAuthentication authentication = callbackUrlAuthenticationCryptor.decrypt(callbackUrlEntity);
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

}
