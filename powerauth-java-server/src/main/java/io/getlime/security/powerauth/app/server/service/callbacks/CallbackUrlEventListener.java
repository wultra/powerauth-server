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

import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Listener implementation to react immediately to a published Callback URL Event.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class CallbackUrlEventListener {

    private CallbackUrlEventService callbackUrlEventService;

    /**
     * Listener to react immediately to a newly created Callback URL Event that should be instantly dispatched.
     * @param callbackUrlEventEntity Callback URL Event to dispatch.
     */
    @Async("callbackUrlEventsThreadPoolExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handlePublishedCallbackUrlEvent(final CallbackUrlEventEntity callbackUrlEventEntity) {
        callbackUrlEventService.dispatchPendingCallbackUrlEvent(callbackUrlEventEntity);
    }

}
