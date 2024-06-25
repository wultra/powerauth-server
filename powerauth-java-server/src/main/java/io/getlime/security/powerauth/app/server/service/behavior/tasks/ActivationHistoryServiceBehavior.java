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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.client.model.entity.ActivationHistoryItem;
import com.wultra.security.powerauth.client.model.request.ActivationHistoryRequest;
import com.wultra.security.powerauth.client.model.response.ActivationHistoryResponse;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationHistoryEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationHistoryRepository;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

/**
 * Behavior class used for storing and retrieving activation history which includes activation status change log.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ActivationHistoryServiceBehavior {

    private final ActivationHistoryRepository activationHistoryRepository;

    private final ActivationRepository activationRepository;
    private final LocalizationProvider localizationProvider;
    private final AuditingServiceBehavior audit;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    @Autowired
    public ActivationHistoryServiceBehavior(ActivationHistoryRepository activationHistoryRepository, ActivationRepository activationRepository, LocalizationProvider localizationProvider, AuditingServiceBehavior audit) {
        this.activationHistoryRepository = activationHistoryRepository;
        this.activationRepository = activationRepository;
        this.localizationProvider = localizationProvider;
        this.audit = audit;
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
        activationHistoryEntity.setActivationVersion(activation.getVersion());
        activationHistoryEntity.setActivationName(activation.getActivationName());

        activation.getActivationHistory().add(activationHistoryEntity);
        // ActivationHistoryEntity is persisted together with activation using Cascade.ALL on ActivationEntity
        activationRepository.save(activation);

        logAuditItem(activation, externalUserId, historyEventReason);

    }

    /**
     * List status changes for given activation.
     * @param request Request with history query definition.
     * @return Response with activation changes.
     */
    @Transactional(readOnly = true)
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final Date startingDate = request.getTimestampFrom();
            final Date endingDate = request.getTimestampTo();
            if (request.getActivationId() == null) {
                logger.warn("Invalid request parameter activationId in method getActivationHistory");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final List<ActivationHistoryEntity> activationHistoryEntityList = activationHistoryRepository.findActivationHistory(activationId, startingDate, endingDate);

            final ActivationHistoryResponse response = new ActivationHistoryResponse();
            if (activationHistoryEntityList != null) {
                for (ActivationHistoryEntity activationHistoryEntity : activationHistoryEntityList) {

                    final ActivationHistoryItem item = new ActivationHistoryItem();
                    item.setId(activationHistoryEntity.getId());
                    item.setActivationId(activationHistoryEntity.getActivation().getActivationId());
                    item.setActivationStatus(activationStatusConverter.convert(activationHistoryEntity.getActivationStatus()));
                    item.setEventReason(activationHistoryEntity.getEventReason());
                    final Integer activationVersion = activationHistoryEntity.getActivationVersion();
                    if (activationVersion != null) {
                        item.setVersion(Long.valueOf(activationVersion));
                    }
                    item.setExternalUserId(activationHistoryEntity.getExternalUserId());
                    item.setActivationName(activationHistoryEntity.getActivationName());
                    item.setTimestampCreated(activationHistoryEntity.getTimestampCreated());

                    response.getItems().add(item);
                }
            }

            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    // Private methods

    private void logAuditItem(ActivationRecordEntity activation, String externalUserId, String historyEventReason) {
        // Prepare shared parameters
        final AuditDetail.Builder auditDetailBuilder = AuditDetail.builder()
                .type(AuditType.ACTIVATION.getCode())
                .param("activationId", activation.getActivationId())
                .param("userId", activation.getUserId())
                .param("applicationId", activation.getApplication().getId())
                .param("status", activation.getActivationStatus())
                .param("maxFailedAttempts", activation.getMaxFailedAttempts());

        // Handle other than CREATED states with rich info
        if (activation.getActivationStatus() != ActivationStatus.CREATED) {
            auditDetailBuilder
                    .param("activationName", activation.getActivationName())
                    .param("platform", activation.getPlatform())
                    .param("failedAttempts", activation.getFailedAttempts())
                    .param("deviceInfo", activation.getDeviceInfo())
                    .param("reason", (activation.getActivationStatus() == ActivationStatus.BLOCKED) ? activation.getBlockedReason() : historyEventReason)
                    .param("activationVersion", activation.getVersion());
        }

        // Check presence of external user
        if (externalUserId != null) {
            auditDetailBuilder
                    .param("externalUserId", externalUserId);
        }

        // Build audit log message
        final AuditDetail auditDetail = auditDetailBuilder.build();
        if (AdditionalInformation.Reason.ACTIVATION_NAME_UPDATED.equals(historyEventReason)) {
            audit.log(AuditLevel.INFO, "Updated activation with ID: {}", auditDetail, activation.getActivationId());
        } else {
            switch (activation.getActivationStatus()) {
                case CREATED -> audit.log(AuditLevel.INFO, "Created activation with ID: {}", auditDetail, activation.getActivationId());
                case PENDING_COMMIT, BLOCKED, ACTIVE -> audit.log(AuditLevel.INFO, "Activation ID: {} is now {}", auditDetail, activation.getActivationId(), activation.getActivationStatus());
                default -> audit.log(AuditLevel.INFO, "Removing activation with ID: {}", auditDetail, activation.getActivationId());
            }
        }
    }

}
