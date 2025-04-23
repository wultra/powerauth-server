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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Behavior class implementing activation validations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ActivationRemoveServiceBehavior {

    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final ActivationQueryService activationQueryService;
    private final LocalizationProvider localizationProvider;
    private final CallbackUrlBehavior callbackUrlBehavior;

    /**
     * Deactivate the activation in CREATED or PENDING_COMMIT if it's activation expiration timestamp
     * is below the given timestamp.
     *
     * @param timestamp  Timestamp to check activations against.
     * @param activation Activation to check.
     */
    public void deactivatePendingActivation(Date timestamp, ActivationRecordEntity activation, boolean isActivationLocked) throws GenericServiceException {
        if ((activation.getActivationStatus() == ActivationStatus.CREATED || activation.getActivationStatus() == ActivationStatus.PENDING_COMMIT) && (timestamp.getTime() > activation.getTimestampActivationExpire().getTime())) {
            logger.info("Deactivating pending activation, activation ID: {}", activation.getActivationId());
            if (!isActivationLocked) {
                // Make sure activation is locked until the end of transaction in case it was not locked yet
                final String activationId = activation.getActivationId();
                activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                    logger.info("Activation not found, activation ID: {}", activationId);
                    return localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
                });
            }
            removeActivation(activation, null);
        }
    }

    /**
     * Internal logic for processing activation removal.
     * @param activation Activation entity.
     * @param externalUserId External user identifier.
     */
    public void removeActivation(final ActivationRecordEntity activation, final String externalUserId) {
        activation.setActivationStatus(ActivationStatus.REMOVED);
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
    }

}
