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
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
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
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Objects;
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
    private final CallbackUrlRestClientManager callbackUrlRestClientManager;

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
     * Dispatch Callback URL Events in pending state.
     */
    @Transactional
    public void dispatchPendingCallbackUrlEvents() {
        final PageRequest pageRequest = PageRequest.of(0, powerAuthCallbacksConfiguration.getPendingCallbackUrlEventsDispatchLimit());
        callbackUrlEventRepository.findPending(LocalDateTime.now(), pageRequest)
                .forEach(this::dispatchPendingCallbackUrlEvent);
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
        final Duration forceRerunPeriod = Objects.requireNonNullElse(powerAuthCallbacksConfiguration.getForceRerunPeriod(), defaultForceRerunPeriod());
        final int numberOfAffectedEvents = callbackUrlEventRepository.updateStaleEventsToPendingState(LocalDateTime.now().minus(forceRerunPeriod));
        logger.debug("Number of stale Callback URL Events moved to PENDING state: {}", numberOfAffectedEvents);
    }

    /**
     * Dispatch Callback URL Event.
     * @param callbackUrlEventEntity Event to dispatch.
     */
    private void dispatchPendingCallbackUrlEvent(final CallbackUrlEventEntity callbackUrlEventEntity) {
        callbackUrlEventEntity.setStatus(CallbackUrlEventStatus.PROCESSING);
        callbackUrlEventEntity.setTimestampNextCall(null);
        callbackUrlEventEntity.setTimestampLastCall(LocalDateTime.now());
        final CallbackUrlEventEntity savedEventEntity = callbackUrlEventRepository.save(callbackUrlEventEntity);

        final CallbackUrlEvent callbackUrlEvent = CallbackUrlConvertor.convert(savedEventEntity);
        TransactionUtils.executeAfterTransactionCommits(
                () -> postCallback(callbackUrlEvent)
        );
    }

    /**
     * Send Callback URL Event as a non-blocking POST request.
     * @param callbackUrlEvent Event to post.
     */
    public void postCallback(final CallbackUrlEvent callbackUrlEvent) {
        if (callbackUrlEvent.status() != CallbackUrlEventStatus.PROCESSING) {
            logger.debug("Callback URL Event is not in PROCESSING state: callbackUrlEventId={}", callbackUrlEvent.callbackUrlEventEntityId());
            return;
        }

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

}
