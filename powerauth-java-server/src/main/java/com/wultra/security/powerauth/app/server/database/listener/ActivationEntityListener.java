/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.database.listener;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationRemoveServiceBehavior;
import jakarta.persistence.PostUpdate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

/**
 * Listener for {@link ActivationRecordEntity} changes.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Component
@Slf4j
public class ActivationEntityListener {

    private final ActivationRemoveServiceBehavior activationRemoveServiceBehavior;

    @Autowired
    public ActivationEntityListener(@Lazy final ActivationRemoveServiceBehavior activationRemoveServiceBehavior) {
        this.activationRemoveServiceBehavior = activationRemoveServiceBehavior;
    }

    /**
     * Processes activation status changes after an update.
     * If the activation status changes to ACTIVE and the activation is a result of a transfer operation type of MOVE,
     * this method handles the removal of the parent activation.
     * Parent removal is not performed if the previous activation status was BLOCKED.
     *
     * @param activation The activation record entity that was updated
     */
    @PostUpdate
    public void processActivationStatusChange(final ActivationRecordEntity activation) {
        if (activation.getPreviousActivationStatus() != null
                && activation.getPreviousActivationStatus() != activation.getActivationStatus()
                && activation.getActivationStatus() == ActivationStatus.ACTIVE
                && activation.getPreviousActivationStatus() != ActivationStatus.BLOCKED
                && activation.getTransferType() == ActivationTransferType.MOVE) {

            final ActivationRecordEntity parentActivation = activation.getParentActivation();
            if (parentActivation != null) {
                logger.info("Deleting activation ID: {}, because is a parent of the moved activation ID :{}", parentActivation.getActivationId(), activation.getActivationId());
                activationRemoveServiceBehavior.removeActivation(parentActivation, null);
            }
        }
    }
}
