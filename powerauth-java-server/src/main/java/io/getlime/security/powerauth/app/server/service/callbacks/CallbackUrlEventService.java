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

import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthCallbacksConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlEventRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlConvertor;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
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
import java.util.Objects;
import java.util.Set;
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
    private final PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;
    private final CallbackUrlEventResponseHandler callbackUrlEventResponseHandler;
    private final CallbackUrlRestClientManager callbackUrlRestClientManager;


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

            final RestClient restClient = callbackUrlRestClientManager.getRestClient(callbackUrlEvent);
            final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
            headers.add("Idempotency-Key", callbackUrlEvent.callbackUrlEventEntityId());

            restClient.postNonBlocking(callbackUrlEvent.callbackUrl(),
                    callbackUrlEvent.callbackData(),
                    new LinkedMultiValueMap<>(),
                    headers,
                    responseType,
                    onSuccess,
                    onError);

            logger.debug("CallbackUrlEvent {} was dispatched.", callbackUrlEvent.callbackUrlEventEntityId());
        } catch (RestClientException | GenericServiceException e) {
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

}
