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
import io.getlime.security.powerauth.app.server.configuration.PowerAuthCallbacksConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CachedRestClient;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Handlers of a Callback URL Event response.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Component
@AllArgsConstructor
@Slf4j
public class CallbackUrlEventResponseHandler {

    private final CallbackUrlEventRepository callbackUrlEventRepository;
    private final PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;
    private final LoadingCache<String, CachedRestClient> callbackUrlRestClientCache;

    /**
     * Handle successful Callback URL Event attempt.
     * @param callbackUrlEvent Callback URL Event successfully delivered.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void handleSuccess(final CallbackUrlEvent callbackUrlEvent) {
        final CallbackUrlEventEntity callbackUrlEventEntity = callbackUrlEventRepository.findById(callbackUrlEvent.entityId())
                        .orElseThrow(() -> new IllegalStateException("Callback Url Event was not found in database during its success handling: callbackUrlEventId=" + callbackUrlEvent.entityId()));

        logger.info("Callback succeeded, URL={}, callbackEventId={}", callbackUrlEvent.config().url(), callbackUrlEventEntity.getId());

        final Duration retentionPeriod = Objects.requireNonNullElse(callbackUrlEvent.config().retentionPeriod(), powerAuthCallbacksConfiguration.getDefaultRetentionPeriod());
        callbackUrlEventEntity.setTimestampDeleteAfter(LocalDateTime.now().plus(retentionPeriod));
        callbackUrlEventEntity.setTimestampNextCall(null);
        callbackUrlEventEntity.setTimestampRerunAfter(null);
        callbackUrlEventEntity.setAttempts(callbackUrlEventEntity.getAttempts() + 1);
        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.COMPLETED);
        callbackUrlEventRepository.save(callbackUrlEventEntity);
        resetFailureCount(callbackUrlEventEntity.getCallbackUrlEntityId());
    }

    /**
     * Handle failure of callback attempt.
     * @param callbackUrlEvent Failed Callback URL Event.
     * @param error Exception describing the cause of failure.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void handleFailure(final CallbackUrlEvent callbackUrlEvent, final Throwable error) {
        final CallbackUrlEventEntity callbackUrlEventEntity = callbackUrlEventRepository.findById(callbackUrlEvent.entityId())
                .orElseThrow(() -> new IllegalStateException("Callback Url Event was not found in database during its failure handling: callbackUrlEventId=" + callbackUrlEvent.entityId()));

        logger.info("Callback failed, URL={}, callbackEventId={}, error={}", callbackUrlEvent.config().url(), callbackUrlEventEntity.getId(), error.getMessage());

        callbackUrlEventEntity.setAttempts(callbackUrlEventEntity.getAttempts() + 1);
        callbackUrlEventEntity.setTimestampRerunAfter(null);

        final int maxAttempts = Objects.requireNonNullElse(callbackUrlEvent.config().maxAttempts(), powerAuthCallbacksConfiguration.getDefaultMaxAttempts());
        final int attemptsMade = callbackUrlEventEntity.getAttempts();

        if (attemptsMade < maxAttempts) {
            final Duration initialBackoff = Objects.requireNonNullElse(callbackUrlEvent.config().initialBackoff(), powerAuthCallbacksConfiguration.getDefaultInitialBackoff());
            final Duration backoffPeriod = calculateExponentialBackoffPeriod(callbackUrlEventEntity.getAttempts(), initialBackoff, powerAuthCallbacksConfiguration.getBackoffMultiplier(), powerAuthCallbacksConfiguration.getMaxBackoff());
            callbackUrlEventEntity.setTimestampNextCall(LocalDateTime.now().plus(backoffPeriod));
            callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.PENDING);
        } else {
            logger.debug("Maximum number of attempts reached for callbackUrlEventId={}", callbackUrlEventEntity.getId());
            final Duration retentionPeriod = Objects.requireNonNullElse(callbackUrlEvent.config().retentionPeriod(), powerAuthCallbacksConfiguration.getDefaultRetentionPeriod());
            callbackUrlEventEntity.setTimestampDeleteAfter(LocalDateTime.now().plus(retentionPeriod));
            callbackUrlEventEntity.setTimestampNextCall(null);
            callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.FAILED);
        }

        callbackUrlEventRepository.save(callbackUrlEventEntity);
        incrementFailureCount(callbackUrlEventEntity.getCallbackUrlEntityId());
    }

    /**
     * Calculate back off period for next retry attempt using exponential backoff strategy.
     * @param attempts Number of already made attempts.
     * @param initialBackoff Initial backoff.
     * @return Duration between last and next attempt.
     */
    private static Duration calculateExponentialBackoffPeriod(final int attempts, final Duration initialBackoff, final double multiplier, final Duration maxBackoff) {
         Assert.isTrue(attempts >= 0, "Attempts must be non-negative.");
         Assert.isTrue(!initialBackoff.isNegative(), "Initial backoff must be non-negative.");

        if (attempts == 0) {
            return Duration.ZERO;
        }

        final long backoffMillis = (long) (initialBackoff.toMillis() * Math.pow(multiplier, attempts - 1));
        return Duration.ofMillis(Math.min(backoffMillis, maxBackoff.toMillis()));
    }

    private void incrementFailureCount(final String callbackUrlId) {
        if (powerAuthCallbacksConfiguration.failureStatsDisabled()) {
            return;
        }

        callbackUrlRestClientCache.asMap().computeIfPresent(callbackUrlId,
                (key, cached) -> CachedRestClient.builder()
                        .restClient(cached.restClient())
                        .timestampCreated(cached.timestampCreated())
                        .failureCount(cached.failureCount() + 1)
                        .timestampLastFailure(LocalDateTime.now())
                        .callbackUrlEntity(cached.callbackUrlEntity())
                        .build()
        );
    }

    private void resetFailureCount(final String callbackUrlId) {
        if (powerAuthCallbacksConfiguration.failureStatsDisabled()) {
            return;
        }

        callbackUrlRestClientCache.asMap().computeIfPresent(callbackUrlId,
                (key, cached) -> CachedRestClient.builder()
                        .restClient(cached.restClient())
                        .timestampCreated(cached.timestampCreated())
                        .failureCount(0)
                        .timestampLastFailure(cached.timestampLastFailure())
                        .callbackUrlEntity(cached.callbackUrlEntity())
                        .build()
        );
    }

}
