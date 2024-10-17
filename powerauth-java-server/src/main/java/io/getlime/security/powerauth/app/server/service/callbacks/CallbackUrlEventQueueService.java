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

import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEvent;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlEventRunnable;
import io.getlime.security.powerauth.app.server.task.CleaningTask;
import jakarta.annotation.PreDestroy;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Component;

import java.util.concurrent.RejectedExecutionException;

/**
 * Service for enqueueing Callback URL Events for further processing.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class CallbackUrlEventQueueService {

    private CallbackUrlEventService callbackUrlEventService;
    private ThreadPoolTaskExecutor callbackUrlEventsThreadPoolExecutor;

    /**
     * Submit Callback URL Event to be dispatched by a task executor as soon as possible.
     * @param callbackUrlEvent Callback URL Event to submit.
     * @throws RejectedExecutionException In case the Callback URL Event could not be submitted.
     */
    public void submitToExecutor(final CallbackUrlEvent callbackUrlEvent) throws RejectedExecutionException {
        final CallbackUrlEventRunnable runnable = CallbackUrlEventRunnable.builder()
                .dispatchAction(() -> callbackUrlEventService.dispatchInstantCallbackUrlEvent(callbackUrlEvent))
                .cancelAction(() -> callbackUrlEventService.moveCallbackUrlEventToPending(callbackUrlEvent))
                .build();

        callbackUrlEventsThreadPoolExecutor.execute(runnable);
    }

    /**
     * Enqueue a Callback URL Event to database to be dispatched by {@link CleaningTask#dispatchPendingCallbackUrlEvents()}.
     * @param callbackUrlEvent Callback URL Event to enqueue.
     */
    public void enqueueToDatabase(final CallbackUrlEvent callbackUrlEvent) {
        callbackUrlEventService.moveCallbackUrlEventToPending(callbackUrlEvent);
    }

    /**
     * Move all Callback URL Events from the Executor's queue to the database queue on graceful shutdown.
     */
    @PreDestroy
    private void clearExecutorQueue() {
        logger.info("Moving Callback URL Events from executor's queue to PENDING state.");
        callbackUrlEventsThreadPoolExecutor.getThreadPoolExecutor().shutdownNow()
                .forEach(runnable -> {
                    if (runnable instanceof CallbackUrlEventRunnable callbackUrlEventAction) {
                        callbackUrlEventAction.cancel();
                    }
                });
    }

}
