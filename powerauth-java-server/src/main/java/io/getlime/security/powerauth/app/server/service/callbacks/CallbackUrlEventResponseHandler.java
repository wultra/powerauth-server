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

import io.getlime.security.powerauth.app.server.configuration.PowerAuthCallbacksConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
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

    final CallbackUrlEventRepository callbackUrlEventRepository;
    private PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;

    /**
     * Handle successful Callback URL Event attempt.
     * @param callbackUrlEvent Callback URL Event successfully delivered.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void handleSuccess(final CallbackUrlEvent callbackUrlEvent) {
        final CallbackUrlEventEntity callbackUrlEventEntity = callbackUrlEventRepository.findById(callbackUrlEvent.callbackUrlEventEntityId())
                        .orElseThrow(() -> new IllegalStateException("Callback Url Event was not found in database during its successful response handling: callbackUrlEventId=" + callbackUrlEvent.callbackUrlEventEntityId()));

        logger.info("Callback succeeded, URL={}, callbackEventId={}", callbackUrlEventEntity.getCallbackUrlEntity().getCallbackUrl(), callbackUrlEventEntity.getId());

        final Duration retentionPeriod = Objects.requireNonNullElse(callbackUrlEventEntity.getCallbackUrlEntity().getRetentionPeriod(), powerAuthCallbacksConfiguration.getDefaultRetentionPeriod());
        callbackUrlEventEntity.setTimestampDeleteAfter(callbackUrlEventEntity.getTimestampCreated().plus(retentionPeriod));

        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.COMPLETED);
        callbackUrlEventRepository.save(callbackUrlEventEntity);
    }

    /**
     * Handle failure of callback attempt.
     * @param callbackUrlEvent Failed Callback URL Event.
     * @param error Exception describing the cause of failure.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void handleFailure(final CallbackUrlEvent callbackUrlEvent, final Throwable error) {
        final CallbackUrlEventEntity callbackUrlEventEntity = callbackUrlEventRepository.findById(callbackUrlEvent.callbackUrlEventEntityId())
                .orElseThrow(() -> new IllegalStateException("Callback Url Event was not found in database during its failed response handling: callbackUrlEventId=" + callbackUrlEvent.callbackUrlEventEntityId()));

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

}
