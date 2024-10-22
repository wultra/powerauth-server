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

import com.github.benmanes.caffeine.cache.LoadingCache;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthCallbacksConfiguration;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CachedRestClient;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlConvertor;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
import io.getlime.security.powerauth.app.server.service.util.TransactionUtils;
import jakarta.annotation.PostConstruct;
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

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
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

    private final CallbackUrlEventRepository callbackUrlEventRepository;
    private final CallbackUrlEventResponseHandler callbackUrlEventResponseHandler;
    private final LoadingCache<String, CachedRestClient> callbackUrlRestClientCache;

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;

    /**
     * Dispatch a Callback URL Event.
     * @param callbackUrlEvent Callback URL Event to dispatch.
     */
    public void dispatchInstantCallbackUrlEvent(final CallbackUrlEvent callbackUrlEvent) {
        postCallback(callbackUrlEvent);
    }

    /**
     * Move a Callback URL Event to the PENDING state.
     * @param callbackUrlEvent Callback URL Event to set as PENDING.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void moveCallbackUrlEventToPending(final CallbackUrlEvent callbackUrlEvent) {
        callbackUrlEventRepository.updateEventToPendingState(callbackUrlEvent.entityId());
    }

    /**
     * Dispatch Callback URL Events in pending state.
     */
    @Transactional
    public void dispatchPendingCallbackUrlEvents() {
        final PageRequest pageRequest = PageRequest.of(0, powerAuthCallbacksConfiguration.getPendingCallbackUrlEventsDispatchLimit());
        callbackUrlEventRepository.findPending(LocalDateTime.now(), pageRequest)
                .forEach(event -> {
                    if (failureThresholdReached(event.getCallbackUrlEntity())) {
                        logger.warn("Callback URL has reached failure threshold, associated events are not dispatched: callbackUrlId={}", event.getCallbackUrlEntity().getId());
                        failWithoutDispatching(event);
                    } else {
                        dispatchPendingCallbackUrlEvent(event);
                    }
                });
    }

    /**
     * Delete Callback URL Events, that are past their retention period.
     */
    @Transactional
    public void deleteCallbackUrlEventsAfterRetentionPeriod() {
        callbackUrlEventRepository.deleteCompletedAfterRetentionPeriod(LocalDateTime.now());
    }

    /**
     * Reset stale Callback URL Events in PROCESSING state by setting them to PENDING state.
     * <p>
     * This should be applied only to those Callback URL Events, that got stuck in PROCESSING
     * state and won't be dispatched without this action. Otherwise, there is a risk of posting
     * a Callback URL Event more than once.
     */
    @Transactional
    public void resetStaleCallbackUrlEvents() {
        final int numberOfAffectedEvents = callbackUrlEventRepository.updateStaleEventsToPendingState(LocalDateTime.now());
        logger.debug("Number of stale Callback URL Events moved to PENDING state: {}", numberOfAffectedEvents);
    }

    /**
     * Create and save a new {@link CallbackUrlEventEntity} in processing state.
     * @param callbackUrlEntity Existing CallbackUrlEntity with the Callback URL configuration.
     * @param callbackData Data to be sent with the Callback URL.
     * @return Saved {@link CallbackUrlEventEntity}.
     */
    public CallbackUrlEventEntity createAndSaveEventForProcessing(final CallbackUrlEntity callbackUrlEntity, final Map<String, Object> callbackData) {
        final LocalDateTime timestampNow = LocalDateTime.now();
        final Duration forceRerunPeriod = Objects.requireNonNullElse(powerAuthCallbacksConfiguration.getForceRerunPeriod(), defaultForceRerunPeriod());

        final CallbackUrlEventEntity callbackUrlEventEntity = new CallbackUrlEventEntity();
        callbackUrlEventEntity.setCallbackUrlEntity(callbackUrlEntity);
        callbackUrlEventEntity.setCallbackData(callbackData);
        callbackUrlEventEntity.setIdempotencyKey(UUID.randomUUID().toString());
        callbackUrlEventEntity.setTimestampCreated(timestampNow);
        callbackUrlEventEntity.setTimestampLastCall(timestampNow);
        callbackUrlEventEntity.setTimestampRerunAfter(shouldBeSentAtMostOnce(callbackUrlEntity) ? null : timestampNow.plus(forceRerunPeriod));
        callbackUrlEventEntity.setAttempts(0);
        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.PROCESSING);
        return callbackUrlEventRepository.save(callbackUrlEventEntity);
    }

    /**
     * Create and save a new {@link CallbackUrlEventEntity} in failed state.
     * @param callbackUrlEntity Existing CallbackUrlEntity with the Callback URL configuration.
     * @param callbackData Data to be sent with the Callback URL.
     * @return Saved {@link CallbackUrlEventEntity}.
     */
    public CallbackUrlEventEntity createAndSaveFailedEvent(final CallbackUrlEntity callbackUrlEntity, final Map<String, Object> callbackData) {
        final CallbackUrlEventEntity callbackUrlEventEntity = new CallbackUrlEventEntity();
        callbackUrlEventEntity.setCallbackUrlEntity(callbackUrlEntity);
        callbackUrlEventEntity.setCallbackData(callbackData);
        callbackUrlEventEntity.setIdempotencyKey(UUID.randomUUID().toString());
        callbackUrlEventEntity.setTimestampCreated(LocalDateTime.now());
        callbackUrlEventEntity.setAttempts(0);
        return callbackUrlEventRepository.save(failWithoutDispatching(callbackUrlEventEntity));
    }

    /**
     * Obtain maximum attempts to send a Callback URL Event.
     * @param callbackUrlEntity The Callback URL Event configuration.
     * @return Maximum number of attempts.
     */
    public int obtainMaxAttempts(final CallbackUrlEntity callbackUrlEntity) {
        return Objects.requireNonNullElse(callbackUrlEntity.getMaxAttempts(), powerAuthCallbacksConfiguration.getDefaultMaxAttempts());
    }

    /**
     * Check if the Callback URL should be processed. This check prevents from failed callback event flooding.
     * @param callbackUrlEntity Callback Url Entity holding failure statistics.
     * @return True if the callback should be processed, false otherwise.
     */
    public boolean failureThresholdReached(final CallbackUrlEntity callbackUrlEntity) {
        if (powerAuthCallbacksConfiguration.failureStatsDisabled()) {
            logger.debug("Failure stats are turned off for Callback URL processing");
            return false;
        }

        final String callbackUrlId = callbackUrlEntity.getId();
        final CachedRestClient cachedRestClient = callbackUrlRestClientCache.getIfPresent(callbackUrlId);
        if (cachedRestClient == null) {
            logger.debug("No failure stats available yet for Callback URL processing: id={}", callbackUrlId);
            return false;
        }

        final int failureThreshold = powerAuthCallbacksConfiguration.getFailureThreshold();
        final Duration resetTimeout = powerAuthCallbacksConfiguration.getFailureResetTimeout();

        final int failureCount = cachedRestClient.failureCount();
        final LocalDateTime timestampLastFailure = cachedRestClient.timestampLastFailure();

        if (failureCount >= failureThreshold && LocalDateTime.now().minus(resetTimeout).isAfter(timestampLastFailure)) {
            logger.debug("Callback URL reached failure threshold, but before specified reset timeout period, id={}", callbackUrlId);
            return false;
        }

        return failureCount >= failureThreshold;
    }

    /**
     * Dispatch Callback URL Event.
     * @param callbackUrlEventEntity Event to dispatch.
     */
    private void dispatchPendingCallbackUrlEvent(final CallbackUrlEventEntity callbackUrlEventEntity) {
        final CallbackUrlEntity callbackUrlEntity = callbackUrlEventEntity.getCallbackUrlEntity();
        final LocalDateTime timestampNow = LocalDateTime.now();
        final Duration forceRerunPeriod = Objects.requireNonNullElse(powerAuthCallbacksConfiguration.getForceRerunPeriod(), defaultForceRerunPeriod());

        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.PROCESSING);
        callbackUrlEventEntity.setTimestampNextCall(null);
        callbackUrlEventEntity.setTimestampLastCall(timestampNow);
        callbackUrlEventEntity.setTimestampRerunAfter(shouldBeSentAtMostOnce(callbackUrlEntity) ? null : timestampNow.plus(forceRerunPeriod));
        final CallbackUrlEventEntity savedEventEntity = callbackUrlEventRepository.save(callbackUrlEventEntity);

        final CallbackUrlEvent callbackUrlEvent = CallbackUrlConvertor.convert(savedEventEntity, callbackUrlEntity.getId());
        TransactionUtils.executeAfterTransactionCommits(
                () -> postCallback(callbackUrlEvent)
        );
    }

    /**
     * Send Callback URL Event as a non-blocking POST request.
     * @param callbackUrlEvent Event to post.
     */
    private void postCallback(final CallbackUrlEvent callbackUrlEvent) {
        if (callbackUrlEvent.status() != CallbackUrlEventStatus.PROCESSING) {
            logger.warn("Callback URL Event to post is not in PROCESSING state: callbackUrlEventId={}", callbackUrlEvent.entityId());
            return;
        }

        try {
            final Consumer<ResponseEntity<String>> onSuccess = response -> callbackUrlEventResponseHandler.handleSuccess(callbackUrlEvent);
            final Consumer<Throwable> onError = error -> callbackUrlEventResponseHandler.handleFailure(callbackUrlEvent, error);
            final ParameterizedTypeReference<String> responseType = new ParameterizedTypeReference<>(){};

            final RestClient restClient = getRestClient(callbackUrlEvent);
            final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
            headers.add("Idempotency-Key", callbackUrlEvent.idempotencyKey());

            restClient.postNonBlocking(callbackUrlEvent.callbackUrl(),
                    callbackUrlEvent.callbackData(),
                    new LinkedMultiValueMap<>(),
                    headers,
                    responseType,
                    onSuccess,
                    onError);

            logger.debug("CallbackUrlEvent {} was dispatched.", callbackUrlEvent.entityId());
        } catch (RestClientException e) {
            callbackUrlEventResponseHandler.handleFailure(callbackUrlEvent, e);
        }
    }

    /**
     * Get default force rerun period, after which is a Callback URL Event in PROCESSING state considered stale.
     * @return Default force rerun period.
     */
    private Duration defaultForceRerunPeriod() {
        // This is an arbitrary value, representing allowed delay before trying establishing remote connection.
        final Duration allowedProcessingDelay = Duration.ofSeconds(10);
        return powerAuthServiceConfiguration.getHttpConnectionTimeout()
                .plus(powerAuthServiceConfiguration.getHttpResponseTimeout())
                .plus(allowedProcessingDelay);
    }

    private boolean shouldBeSentAtMostOnce(final CallbackUrlEntity callbackUrlEntity) {
        return obtainMaxAttempts(callbackUrlEntity) == 1;
    }

    private CallbackUrlEventEntity failWithoutDispatching(final CallbackUrlEventEntity callbackUrlEventEntity) {
        final Duration retentionPeriod = Objects.requireNonNullElse(callbackUrlEventEntity.getCallbackUrlEntity().getRetentionPeriod(), powerAuthCallbacksConfiguration.getDefaultRetentionPeriod());

        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.FAILED);
        callbackUrlEventEntity.setTimestampNextCall(null);
        callbackUrlEventEntity.setTimestampDeleteAfter(LocalDateTime.now().plus(retentionPeriod));
        callbackUrlEventEntity.setTimestampRerunAfter(null);
        return callbackUrlEventEntity;
    }

    private RestClient getRestClient(final CallbackUrlEvent callbackUrlEvent) throws RestClientException {
        final String cacheKey = callbackUrlEvent.restClientCacheKey();
        final CachedRestClient cachedRestClient = callbackUrlRestClientCache.get(cacheKey);
        if (cachedRestClient == null) {
            throw new RestClientException("REST Client not available for the Callback URL: id=" + cacheKey);
        }

        return cachedRestClient.restClient();
    }

    @PostConstruct
    private void validateForceRerunSetting() {
        final Duration forceRerunPeriod = Objects.requireNonNullElse(powerAuthCallbacksConfiguration.getForceRerunPeriod(), defaultForceRerunPeriod());
        final Duration httpTimeoutsSum = powerAuthServiceConfiguration.getHttpResponseTimeout()
                .plus(powerAuthServiceConfiguration.getHttpConnectionTimeout());
        if (forceRerunPeriod.compareTo(httpTimeoutsSum) <= 0) {
            logger.warn("The force rerun period for Callback URL Events should be longer than the sum of HTTP connection timeout and HTTP response timeout.");
        }
    }

}
