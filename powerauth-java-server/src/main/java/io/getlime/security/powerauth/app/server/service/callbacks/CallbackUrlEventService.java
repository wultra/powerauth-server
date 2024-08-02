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
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlAuthenticationEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlConvertor;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEventConfiguration;
import io.getlime.security.powerauth.app.server.service.util.TransactionUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

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
    private static final Set<CallbackUrlEventStatus> EVENT_STATES_TO_BE_PROCESSED = EnumSet.of(
            CallbackUrlEventStatus.INSTANT,
            CallbackUrlEventStatus.PENDING,
            CallbackUrlEventStatus.FAILED
    );

    private final CallbackUrlEventRepository callbackUrlEventRepository;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;
    private final CallbackUrlEventResponseHandler callbackUrlEventResponseHandler;

    // Store REST clients in cache with their callback ID as a key
    private final Map<String, RestClient> restClientCache = new ConcurrentHashMap<>();
    private final Object restClientCacheLock = new Object();

    /**
     * Dispatch a Callback URL Event.
     * @param callbackUrlEvent Callback URL Event to dispatch.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void dispatchInstantCallbackUrlEvent(final CallbackUrlEvent callbackUrlEvent) {
        callbackUrlEventRepository.findById(callbackUrlEvent.callbackUrlEventEntityId())
                .ifPresentOrElse(
                        this::dispatchEvent,
                        () -> { throw new IllegalStateException("Callback Url Event cannot be dispatched, because it was not found in database: callbackUrlEventEntityId=" + callbackUrlEvent.callbackUrlEventEntityId()); }
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
     */
    @Transactional
    public void dispatchPendingCallbackUrlEvents() {
        final PageRequest pageRequest = PageRequest.of(0, powerAuthCallbacksConfiguration.getPendingCallbackUrlEventsDispatchLimit());
        callbackUrlEventRepository.findPending(pageRequest)
                .forEach(this::dispatchEvent);
    }

    /**
     * Delete Callback URL Events, that are past their retention period.
     */
    @Transactional
    public void deleteCallbackUrlEventsAfterRetentionPeriod() {
        callbackUrlEventRepository.deleteCompletedAfterRetentionPeriod(LocalDateTime.now());
    }

    /**
     * Dispatch Callback URL Event.
     * @param callbackUrlEventEntity Event to dispatch.
     */
    private void dispatchEvent(final CallbackUrlEventEntity callbackUrlEventEntity) {

        if (!maxAttemptsPositive(callbackUrlEventEntity)) {
            logger.info("Callback URL Event {} has not positive max number of attempts.", callbackUrlEventEntity.getId());
            final CallbackUrlEvent callbackUrlEvent = CallbackUrlConvertor.convert(callbackUrlEventEntity);
            callbackUrlEventResponseHandler.handleSuccess(callbackUrlEvent);
            return;
        }

        if (!shouldBeProcessed(callbackUrlEventEntity)) {
            logger.debug("Callback URL Event {} should not be processed, state={}", callbackUrlEventEntity.getId(), callbackUrlEventEntity.getStatus());
            return;
        }

        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.PROCESSING);
        callbackUrlEventEntity.setTimestampNextCall(null);
        callbackUrlEventEntity.setTimestampLastCall(LocalDateTime.now());
        callbackUrlEventEntity.setAttempts(callbackUrlEventEntity.getAttempts() + 1);
        callbackUrlEventRepository.save(callbackUrlEventEntity);

        final CallbackUrlEvent callbackUrlEvent = CallbackUrlConvertor.convert(callbackUrlEventEntity);
        TransactionUtils.executeAfterTransactionCommits(
                () -> postCallback(callbackUrlEvent)
        );
    }

    /**
     * Send Callback URL Event as a non-blocking POST request.
     * @param callbackUrlEvent Event to post.
     */
    public void postCallback(final CallbackUrlEvent callbackUrlEvent) {

        try {
            final Consumer<ResponseEntity<String>> onSuccess = response -> callbackUrlEventResponseHandler.handleSuccess(callbackUrlEvent);
            final Consumer<Throwable> onError = error -> callbackUrlEventResponseHandler.handleFailure(callbackUrlEvent, error);
            final ParameterizedTypeReference<String> responseType = new ParameterizedTypeReference<>(){};

            final RestClient restClient = getRestClient(callbackUrlEvent.callbackUrlEventConfiguration());
            final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
            headers.add("Idempotency-Key", callbackUrlEvent.callbackUrlEventEntityId());

            restClient.postNonBlocking(callbackUrlEvent.callbackUrlEventConfiguration().callbackUrl(),
                    callbackUrlEvent.callbackData(),
                    new LinkedMultiValueMap<>(),
                    headers,
                    responseType,
                    onSuccess,
                    onError);

            logger.debug("CallbackUrlEvent {} was dispatched.", callbackUrlEvent.callbackUrlEventEntityId());

        } catch (RestClientException e) {
            callbackUrlEventResponseHandler.handleFailure(callbackUrlEvent, e);
        }
    }

    /**
     * Check if a Callback URL Event should be processed.
     * @param callbackUrlEventEntity Callback URL Event to check.
     * @return True if the Callback URL Event should be processed, false otherwise.
     */
    private boolean shouldBeProcessed(final CallbackUrlEventEntity callbackUrlEventEntity) {
        final int maxAttempts = Objects.requireNonNullElse(callbackUrlEventEntity.getCallbackUrlEntity().getMaxAttempts(), powerAuthCallbacksConfiguration.getDefaultMaxAttempts());
        return EVENT_STATES_TO_BE_PROCESSED.contains(callbackUrlEventEntity.getStatus())
                && callbackUrlEventEntity.getAttempts() < maxAttempts;
    }

    /**
     * Check if a Callback URL Event is configured to be dispatched at least once.
     * @param callbackUrlEventEntity Callback URL Event to check.
     * @return True if the Callback URL Event should be dispatched at least once, false otherwise.
     */
    private boolean maxAttemptsPositive(final CallbackUrlEventEntity callbackUrlEventEntity) {
        final int maxAttempts = Objects.requireNonNullElse(callbackUrlEventEntity.getCallbackUrlEntity().getMaxAttempts(), powerAuthCallbacksConfiguration.getDefaultMaxAttempts());
        return maxAttempts > 0;
    }

    /**
     * Get a REST Client using which a Callback URL Event will be dispatched.
     * @param callbackUrlEventConfiguration Configuration of the Callback.
     * @return REST Client.
     * @throws RestClientException In case the REST Client initialization fails.
     */
    private RestClient getRestClient(final CallbackUrlEventConfiguration callbackUrlEventConfiguration) throws RestClientException {
        final String cacheKey = getRestClientCacheKey(callbackUrlEventConfiguration);
        synchronized (restClientCacheLock) {
            final RestClient restClient = restClientCache.get(cacheKey);
            if (restClient == null) {
                logger.debug("REST client not found in cache, initializing new REST client, callback cache key: {}", cacheKey);
                return createRestClientAndStoreInCache(callbackUrlEventConfiguration);
            } else {
                logger.debug("REST client found in cache, callback cache key: {}", cacheKey);
                return restClient;
            }
        }
    }

    /**
     * Get a key of the REST Client Cache for a Callback URL Configuration.
     * @param callbackUrlEventConfiguration Configuration of the Callback.
     * @return Cache key.
     */
    private static String getRestClientCacheKey(final CallbackUrlEventConfiguration callbackUrlEventConfiguration) {
        return callbackUrlEventConfiguration.callbackUrlEntityId();
    }

    /**
     * Create a new REST Client for a Callback URL Configuration and store it in a cache.
     * @param callbackUrlEventConfiguration Configuration of the Callback.
     * @return Rest client.
     */
    private RestClient createRestClientAndStoreInCache(final CallbackUrlEventConfiguration callbackUrlEventConfiguration) throws RestClientException {
        final String cacheKey = getRestClientCacheKey(callbackUrlEventConfiguration);
        final RestClient restClient = initializeRestClient(callbackUrlEventConfiguration);
        restClientCache.put(cacheKey, restClient);
        return restClient;
    }

    /**
     * Evict an instance of a REST Client for a Callback URL Configuration from cache.
     * @param callbackUrlEventConfiguration Configuration of the Callback.
     */
    public void evictRestClientFromCache(final CallbackUrlEventConfiguration callbackUrlEventConfiguration) {
        synchronized (restClientCacheLock) {
            restClientCache.remove(getRestClientCacheKey(callbackUrlEventConfiguration));
        }
    }

    /**
     * Initialize REST Client instance and configure it based on a Callback URL Configuration.
     * @param callbackUrlEventConfiguration Configuration of the Callback.
     */
    private RestClient initializeRestClient(final CallbackUrlEventConfiguration callbackUrlEventConfiguration) throws RestClientException {
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
        final CallbackUrlAuthenticationEntity authentication = callbackUrlEventConfiguration.authentication();
        final CallbackUrlAuthenticationEntity.Certificate certificateAuth = authentication.getCertificate();
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
        final CallbackUrlAuthenticationEntity.HttpBasic httpBasicAuth = authentication.getHttpBasic();
        if (httpBasicAuth != null && httpBasicAuth.isEnabled()) {
            builder.httpBasicAuth()
                    .username(httpBasicAuth.getUsername())
                    .password(httpBasicAuth.getPassword());
        }
        return builder.build();
    }

}
