/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;
import com.wultra.security.powerauth.client.model.enumeration.UserActionResult;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.OperationStatusDo;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationRepository;
import io.getlime.security.powerauth.app.server.database.repository.OperationTemplateRepository;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.apache.commons.text.StringSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Behavior class implementing the operation related processes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class OperationServiceBehavior {

    private final OperationRepository operationRepository;
    private final OperationTemplateRepository templateRepository;

    private final ServiceBehaviorCatalogue bahavior;

    private LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(OperationServiceBehavior.class);

    // Helper classes
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public OperationServiceBehavior(
            OperationRepository operationRepository,
            OperationTemplateRepository templateRepository,
            ServiceBehaviorCatalogue bahavior,
            PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.operationRepository = operationRepository;
        this.templateRepository = templateRepository;
        this.bahavior = bahavior;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    public OperationDetailResponse createOperation(OperationCreateRequest request) throws GenericServiceException {

        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();
        final String templateName = request.getTemplateName();
        final Map<String, String> parameters = request.getParameters() != null ? request.getParameters() : new LinkedHashMap<>();
        final String externalId = request.getExternalId();

        // Prepare current timestamp in advance
        final Date currentTimestamp = new Date();

        // Fetch the operation template
        final Optional<OperationTemplateEntity> template = templateRepository.findTemplateByName(templateName);
        final OperationTemplateEntity templateEntity;
        if (template.isPresent()) {
            templateEntity = template.get();
        } else {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
        }

        // Generate unique token ID.
        String operationId = null;
        for (int i = 0; i < powerAuthServiceConfiguration.getGenerateOperationIterations(); i++) {
            final String tmpOperationId = UUID.randomUUID().toString();
            final Optional<OperationEntity> tmpTokenOptional = operationRepository.findOperation(tmpOperationId);
            if (!tmpTokenOptional.isPresent()) {
                operationId = tmpOperationId;
                break;
            } // ... else this token ID has a collision, reset it and try to find another one
        }
        if (operationId == null) {
            logger.error("Unable to generate token");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_TOKEN);
        }

        // Get operation expiration date
        final long expiration = templateEntity.getExpiration() * 1000L;
        final Date timestampExpiration = new Date(currentTimestamp.getTime() + expiration);

        // Build operation data
        final StringSubstitutor sub = new StringSubstitutor(parameters);
        final String operationData = sub.replace(templateEntity.getDataTemplate());

        // Serialize parameters in the string
        String parametersString;
        try {
            parametersString = objectMapper.writeValueAsString(parameters);
        } catch (JsonProcessingException ex) { // Should not happen
            parametersString = "{}";
            logger.error("Unable to serialize JSON parameter payload for operation {}.", operationId, ex);
        }

        // Create a new operation
        final OperationEntity operationEntity = new OperationEntity();
        operationEntity.setId(operationId);
        operationEntity.setUserId(userId);
        operationEntity.setApplicationId(applicationId);
        operationEntity.setTemplate(templateEntity);
        operationEntity.setExternalId(externalId);
        operationEntity.setOperationType(templateEntity.getOperationType());
        operationEntity.setData(operationData);
        operationEntity.setParameters(parametersString);
        operationEntity.setStatus(OperationStatusDo.PENDING);
        operationEntity.setSignatureType(templateEntity.getSignatureType());
        operationEntity.setFailureCount(0L);
        operationEntity.setMaxFailureCount(templateEntity.getMaxFailureCount());
        operationEntity.setTimestampCreated(currentTimestamp);
        operationEntity.setTimestampExpires(timestampExpiration);
        operationEntity.setTimestampFinalized(null); // empty initially

        final OperationEntity savedEntity = operationRepository.save(operationEntity);
        bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
        return convertFromEntity(savedEntity);

    }

    public OperationUserActionResponse attemptApproveOperation(OperationApproveRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();
        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();
        final String data = request.getData();
        final String signatureType = request.getSignatureType();

        // TODO: We might need a lock here!!!
        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperation(operationId);
        if (!operationOptional.isPresent()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_APPROVE_FAILURE);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        if (!OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_APPROVE_FAILURE);
        }

        // Check the operation properties match the request
        final PowerAuthSignatureTypes factorEnum = PowerAuthSignatureTypes.getEnumFromString(signatureType);
        if (factorEnum != null // the used factor is known
            && operationEntity.getUserId().equals(userId) // correct user approved the operation
            && operationEntity.getApplicationId().equals(applicationId) // operation is approved by the expected application
            && operationEntity.getData().equals(data) // operation data matched the expected value
            && factorsAcceptable(operationEntity.getSignatureType(), factorEnum) // auth factors are acceptable
            && operationEntity.getMaxFailureCount() > operationEntity.getFailureCount()) { // operation has sufficient attempts left (redundant check)

            // Approve the operation
            operationEntity.setStatus(OperationStatusDo.APPROVED);
            operationEntity.setTimestampFinalized(currentTimestamp);

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

            OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.APPROVED);
            response.setOperation(operationDetailResponse);
            return response;
        } else {

            // Update failure count, check the failure count and FAIL operation if needed
            final Long failureCount = operationEntity.getFailureCount() + 1;
            final Long maxFailureCount = operationEntity.getMaxFailureCount();

            if (failureCount < maxFailureCount) {
                operationEntity.setFailureCount(failureCount);

                final OperationEntity savedEntity = operationRepository.save(operationEntity);
                bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                OperationUserActionResponse response = new OperationUserActionResponse();
                response.setResult(UserActionResult.APPROVAL_FAILED);
                response.setOperation(operationDetailResponse);
                return response;
            } else {
                operationEntity.setStatus(OperationStatusDo.FAILED);
                operationEntity.setTimestampFinalized(currentTimestamp);
                operationEntity.setFailureCount(maxFailureCount); // just in case, set the failure count to max value

                final OperationEntity savedEntity = operationRepository.save(operationEntity);
                bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                OperationUserActionResponse response = new OperationUserActionResponse();
                response.setResult(UserActionResult.OPERATION_FAILED);
                response.setOperation(operationDetailResponse);
                return response;
            }
        }
    }

    public OperationUserActionResponse rejectOperation(OperationRejectRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();
        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();

        // TODO: We might need a lock here!!!
        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperation(operationId);
        if (!operationOptional.isPresent()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_REJECT_FAILURE);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        if (!OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_REJECT_FAILURE);
        }

        if (operationEntity.getUserId().equals(userId) // correct user rejects the operation
                && operationEntity.getApplicationId().equals(applicationId)) { // operation is rejected by the expected application

            // Approve the operation
            operationEntity.setStatus(OperationStatusDo.REJECTED);
            operationEntity.setTimestampFinalized(currentTimestamp);

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

            OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.REJECTED);
            response.setOperation(operationDetailResponse);
            return response;
        } else {
            final OperationDetailResponse operationDetailResponse = convertFromEntity(operationEntity);
            OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.REJECT_FAILED);
            response.setOperation(operationDetailResponse);
            return response;
        }
    }

    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();

        // TODO: We might need a lock here!!!
        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperation(operationId);
        if (!operationOptional.isPresent()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        if (!OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_INVALID_STATE);
        }

        // Update failure count, check the failure count and FAIL operation if needed
        final Long failureCount = operationEntity.getFailureCount() + 1;
        final Long maxFailureCount = operationEntity.getMaxFailureCount();

        if (failureCount < maxFailureCount) {
            operationEntity.setFailureCount(failureCount);

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            final Long applicationId = savedEntity.getApplicationId();
            bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

            OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.APPROVAL_FAILED);
            response.setOperation(operationDetailResponse);
            return response;
        } else {
            operationEntity.setStatus(OperationStatusDo.FAILED);
            operationEntity.setTimestampFinalized(currentTimestamp);
            operationEntity.setFailureCount(maxFailureCount); // just in case, set the failure count to max value

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            final Long applicationId = savedEntity.getApplicationId();
            bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

            OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.OPERATION_FAILED);
            response.setOperation(operationDetailResponse);
            return response;
        }

    }

    public OperationDetailResponse cancelOperation(OperationCancelRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperation(operationId);
        if (!operationOptional.isPresent()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        if (!OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_INVALID_STATE);
        }

        operationEntity.setStatus(OperationStatusDo.CANCELED);
        final OperationEntity savedEntity = operationRepository.save(operationEntity);
        final Long applicationId = savedEntity.getApplicationId();
        bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
        return convertFromEntity(savedEntity);
    }

    public OperationDetailResponse getOperation(OperationDetailRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperation(operationId);
        if (!operationOptional.isPresent()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
        }

        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        return convertFromEntity(operationEntity);
    }

    public OperationListResponse findAllOperationsForUser(OperationListForUserRequest request) {
        final Date currentTimestamp = new Date();

        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();

        final Stream<OperationEntity> operationsForUser = operationRepository.findAllOperationsForUser(userId, applicationId);

        final OperationListResponse result = new OperationListResponse();
        operationsForUser.forEach(op -> {
            final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
            result.add(convertFromEntity(operationEntity));
        });
        return result;
    }

    public OperationListResponse findPendingOperationsForUser(OperationListForUserRequest request) {
        final Date currentTimestamp = new Date();

        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();

        final Iterable<OperationEntity> operationsForUser = operationRepository.findPendingOperationsForUser(userId, applicationId);

        final OperationListResponse result = new OperationListResponse();
        for (OperationEntity op: operationsForUser) {
            final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
            // Skip operation that just expired
            if (OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
                result.add(convertFromEntity(operationEntity));
            }
        }
        return result;
    }

    /**
     * Find operations identified by an external ID value.
     * @param request Request with the external ID.
     * @return List of operations that match.
     */
    public OperationListResponse findOperationsByExternalId(OperationExtIdRequest request) {
        final Date currentTimestamp = new Date();

        final String externalId = request.getExternalId();
        final Long applicationId = request.getApplicationId();

        final Stream<OperationEntity> operationsByExternalId = operationRepository.findOperationsByExternalId(externalId, applicationId);

        final OperationListResponse result = new OperationListResponse();
        operationsByExternalId.forEach(op -> {
            final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
            result.add(convertFromEntity(operationEntity));
        });
        return result;
    }

    private OperationDetailResponse convertFromEntity(OperationEntity source) {
        OperationDetailResponse destination = new OperationDetailResponse();
        destination.setId(source.getId());
        destination.setUserId(source.getUserId());
        destination.setApplicationId(source.getApplicationId());
        destination.setTemplateName(source.getTemplate().getTemplateName());
        destination.setExternalId(source.getExternalId());
        destination.setOperationType(source.getOperationType());
        destination.setData(source.getData());
        try {
            final TypeReference<Map<String,String>> typeRef = new TypeReference<Map<String,String>>() {};
            final Map<String, String> map = objectMapper.readValue(source.getParameters(), typeRef);
            destination.setParameters(map);
        } catch (JsonProcessingException e) {
            destination.setParameters(new HashMap<>());
        }
        final List<String> signatureTypeList = Arrays.stream(source.getSignatureType())
                .map(PowerAuthSignatureTypes::toString)
                .collect(Collectors.toList());
        destination.setSignatureType(signatureTypeList);
        destination.setFailureCount(source.getFailureCount());
        destination.setMaxFailureCount(source.getMaxFailureCount());
        destination.setTimestampCreated(source.getTimestampCreated());
        destination.setTimestampExpires(source.getTimestampExpires());
        destination.setTimestampFinalized(source.getTimestampFinalized());
        switch (source.getStatus()) {
            case PENDING:
                destination.setStatus(OperationStatus.PENDING);
                break;
            case CANCELED:
                destination.setStatus(OperationStatus.CANCELED);
                break;
            case EXPIRED:
                destination.setStatus(OperationStatus.EXPIRED);
                break;
            case APPROVED:
                destination.setStatus(OperationStatus.APPROVED);
                break;
            case REJECTED:
                destination.setStatus(OperationStatus.REJECTED);
                break;
            case FAILED:
                destination.setStatus(OperationStatus.FAILED);
                break;
        }
        return destination;
    }

    private OperationEntity expireOperation(OperationEntity source, Date currentTimestamp) {
        // Operation is still pending and timestamp is after the expiration.
        if (OperationStatusDo.PENDING.equals(source.getStatus())
                && source.getTimestampExpires().before(currentTimestamp)) {
            logger.info("Operation {} expired.", source.getId());
            source.setStatus(OperationStatusDo.EXPIRED);
            final OperationEntity savedEntity = operationRepository.save(source);
            final Long applicationId = savedEntity.getApplicationId();
            bahavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(applicationId, savedEntity);
            return savedEntity;
        }
        return source;
    }

    private boolean factorsAcceptable(PowerAuthSignatureTypes[] allowedSignatureTypes, PowerAuthSignatureTypes usedFactors) {
        if (allowedSignatureTypes == null) {
            return false; // likely a misconfiguration
        }
        return Arrays.asList(allowedSignatureTypes).contains(usedFactors);
    }

    // Scheduled tasks

    @Scheduled(fixedRateString = "${powerauth.service.scheduled.job.operationCleanup}")
    @SchedulerLock(name = "expireOperationsTask")
    @Transactional
    public void expireOperations() {
        LockAssert.assertLocked();
        final Date currentTimestamp = new Date();
        logger.debug("Running scheduled task for expiring operations");
        final Stream<OperationEntity> pendingOperations = operationRepository.findExpiredPendingOperations(currentTimestamp);
        pendingOperations.forEach(op -> {
            expireOperation(op, currentTimestamp);
        });
    }
}
