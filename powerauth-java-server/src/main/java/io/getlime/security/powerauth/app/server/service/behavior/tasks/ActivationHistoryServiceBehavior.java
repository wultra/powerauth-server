/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.client.model.entity.ActivationHistoryItem;
import com.wultra.security.powerauth.client.model.response.ActivationHistoryResponse;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusVOConverter;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationHistoryEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationHistoryRepository;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Behavior class used for storing and retrieving activation history which includes activation status change log.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class ActivationHistoryServiceBehavior {

    private final ActivationHistoryRepository activationHistoryRepository;

    private final ActivationRepository activationRepository;

    // Prepare converters
    private final ActivationStatusVOConverter activationStatusVOConverter = new ActivationStatusVOConverter();

    @Autowired
    public ActivationHistoryServiceBehavior(ActivationHistoryRepository activationHistoryRepository, ActivationRepository activationRepository) {
        this.activationHistoryRepository = activationHistoryRepository;
        this.activationRepository = activationRepository;
    }

    /**
     * Log activation status change into activation history.
     *
     * @param activation Activation.
     */
    public void saveActivationAndLogChange(ActivationRecordEntity activation) {
        saveActivationAndLogChange(activation, null, null);
    }

    /**
     * Log activation status change into activation history.
     *
     * @param activation Activation.
     * @param externalUserId User ID of user who caused the change.
     */
    public void saveActivationAndLogChange(ActivationRecordEntity activation,  String externalUserId) {
        saveActivationAndLogChange(activation, externalUserId, null);
    }

    /**
     * Log activation status change into activation history.
     *
     * @param activation Activation.
     * @param externalUserId User ID of user who caused the change.
     * @param historyEventReason Optional reason, why this activation save event happened.
     */
    public void saveActivationAndLogChange(ActivationRecordEntity activation, String externalUserId, String historyEventReason) {
        final Date changeTimestamp = new Date();
        activation.setTimestampLastChange(changeTimestamp);
        final ActivationHistoryEntity activationHistoryEntity = new ActivationHistoryEntity();
        activationHistoryEntity.setActivation(activation);
        activationHistoryEntity.setActivationStatus(activation.getActivationStatus());
        if (activation.getActivationStatus() == ActivationStatus.BLOCKED) {
            activationHistoryEntity.setEventReason(activation.getBlockedReason());
        } else {
            activationHistoryEntity.setEventReason(historyEventReason);
        }
        activationHistoryEntity.setExternalUserId(externalUserId);
        activationHistoryEntity.setTimestampCreated(changeTimestamp);
        activation.getActivationHistory().add(activationHistoryEntity);
        // ActivationHistoryEntity is persisted together with activation using Cascade.ALL on ActivationEntity
        activationRepository.save(activation);
    }

    /**
     * List status changes for given activation.
     * @param activationId Activation ID.
     * @param startingDate Since when should the changes be displayed.
     * @param endingDate Until when should the changes be displayed.
     * @return Response with activation changes.
     */
    public ActivationHistoryResponse getActivationHistory(String activationId, Instant startingDate, Instant endingDate) {

        final List<ActivationHistoryEntity> activationHistoryEntityList = activationHistoryRepository.findActivationHistory(activationId, startingDate, endingDate);

        final ActivationHistoryResponse response = new ActivationHistoryResponse();
        if (activationHistoryEntityList != null) {
            for (ActivationHistoryEntity activationHistoryEntity : activationHistoryEntityList) {

                final ActivationHistoryItem item = new ActivationHistoryItem();
                item.setId(activationHistoryEntity.getId());
                item.setActivationId(activationHistoryEntity.getActivation().getActivationId());
                item.setActivationStatus(activationStatusVOConverter.convert(activationHistoryEntity.getActivationStatus()));
                item.setEventReason(activationHistoryEntity.getEventReason());
                item.setExternalUserId(activationHistoryEntity.getExternalUserId());
                item.setTimestampCreated(Instant.ofEpochMilli(activationHistoryEntity.getTimestampCreated().getTime()));

                response.getItems().add(item);
            }
        }

        return response;
    }

}
