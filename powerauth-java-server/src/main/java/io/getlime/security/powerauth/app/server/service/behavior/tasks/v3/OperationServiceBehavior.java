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

import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.UserActionResult;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.OperationStatusDo;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
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

import javax.validation.constraints.NotNull;
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
    private final ApplicationRepository applicationRepository;

    private final ServiceBehaviorCatalogue behavior;

    private LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(OperationServiceBehavior.class);

    @Autowired
    public OperationServiceBehavior(
            OperationRepository operationRepository,
            OperationTemplateRepository templateRepository,
            ApplicationRepository applicationRepository, ServiceBehaviorCatalogue behavior,
            PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.operationRepository = operationRepository;
        this.templateRepository = templateRepository;
        this.applicationRepository = applicationRepository;
        this.behavior = behavior;
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
        if (!template.isPresent()) {
            logger.error("Operation template was not found: {}. Check your configuration in pa_operation_template table.", templateName);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
        }
        final OperationTemplateEntity templateEntity = template.get();

        // Check if application exists
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (!application.isPresent()) {
            logger.error("Application was not found for ID: {}", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        final ApplicationEntity applicationEntity = application.get();

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
            logger.error("Unable to generate token due to too many UUID.randomUUID() collisions. Check your random generator setup.");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_TOKEN);
        }

        // Get operation expiration date
        final long expiration = templateEntity.getExpiration() * 1000L;
        final Date timestampExpiration = new Date(currentTimestamp.getTime() + expiration);

        // Build operation data
        final StringSubstitutor sub = new StringSubstitutor(parameters);
        final String operationData = sub.replace(templateEntity.getDataTemplate());

        // Create a new operation
        final OperationEntity operationEntity = new OperationEntity();
        operationEntity.setId(operationId);
        operationEntity.setUserId(userId);
        operationEntity.setApplication(applicationEntity);
        operationEntity.setExternalId(externalId);
        operationEntity.setOperationType(templateEntity.getOperationType());
        operationEntity.setData(operationData);
        operationEntity.setParameters(parameters);
        operationEntity.setStatus(OperationStatusDo.PENDING);
        operationEntity.setSignatureType(templateEntity.getSignatureType());
        operationEntity.setFailureCount(0L);
        operationEntity.setMaxFailureCount(templateEntity.getMaxFailureCount());
        operationEntity.setTimestampCreated(currentTimestamp);
        operationEntity.setTimestampExpires(timestampExpiration);
        operationEntity.setTimestampFinalized(null); // empty initially

        final OperationEntity savedEntity = operationRepository.save(operationEntity);
        behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
        return convertFromEntity(savedEntity);

    }

    public OperationUserActionResponse attemptApproveOperation(OperationApproveRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();
        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();
        final String data = request.getData();
        final SignatureType signatureType = request.getSignatureType();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (!operationOptional.isPresent()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_APPROVE_FAILURE);
        }

        // Fetch application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (!application.isPresent()) {
            logger.error("Application was not found for ID: {}.", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        final OperationStatusDo operationStatus = operationEntity.getStatus();
        if (!OperationStatusDo.PENDING.equals(operationStatus)) {
            logger.debug("Operation is not PENDING - operation ID: {}, status: {}", operationId, operationStatus);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_APPROVE_FAILURE);
        }

        // Check the operation properties match the request
        final PowerAuthSignatureTypes factorEnum = PowerAuthSignatureTypes.getEnumFromString(signatureType.toString());
        if (operationEntity.getUserId().equals(userId) // correct user approved the operation
            && operationEntity.getApplication().getId().equals(applicationId) // operation is approved by the expected application
            && isDataEqual(operationEntity, data) // operation data matched the expected value
            && factorsAcceptable(operationEntity, factorEnum) // auth factors are acceptable
            && operationEntity.getMaxFailureCount() > operationEntity.getFailureCount()) { // operation has sufficient attempts left (redundant check)

            // Approve the operation
            operationEntity.setStatus(OperationStatusDo.APPROVED);
            operationEntity.setTimestampFinalized(currentTimestamp);

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
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
                behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                logger.info("Operation approval failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

                OperationUserActionResponse response = new OperationUserActionResponse();
                response.setResult(UserActionResult.APPROVAL_FAILED);
                response.setOperation(operationDetailResponse);
                return response;
            } else {
                operationEntity.setStatus(OperationStatusDo.FAILED);
                operationEntity.setTimestampFinalized(currentTimestamp);
                operationEntity.setFailureCount(maxFailureCount); // just in case, set the failure count to max value

                final OperationEntity savedEntity = operationRepository.save(operationEntity);
                behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                logger.info("Operation failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

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

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (!operationOptional.isPresent()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_REJECT_FAILURE);
        }

        // Fetch application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (!application.isPresent()) {
            logger.error("Application was not found for ID: {}.", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        final OperationStatusDo operationStatus = operationEntity.getStatus();
        if (!OperationStatusDo.PENDING.equals(operationStatus)) {
            logger.debug("Operation is not PENDING - operation ID: {}, status: {}", operationId, operationStatus);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_REJECT_FAILURE);
        }

        if (operationEntity.getUserId().equals(userId) // correct user rejects the operation
                && operationEntity.getApplication().getId().equals(applicationId)) { // operation is rejected by the expected application

            // Approve the operation
            operationEntity.setStatus(OperationStatusDo.REJECTED);
            operationEntity.setTimestampFinalized(currentTimestamp);

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

            OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.REJECTED);
            response.setOperation(operationDetailResponse);
            return response;
        } else {
            logger.info("Operation reject failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);
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

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (!operationOptional.isPresent()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        final OperationStatusDo operationStatus = operationEntity.getStatus();
        if (!OperationStatusDo.PENDING.equals(operationStatus)) {
            logger.debug("Operation is not PENDING - operation ID: {}, status: {}", operationId, operationStatus);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_INVALID_STATE);
        }

        // Update failure count, check the failure count and FAIL operation if needed
        final Long failureCount = operationEntity.getFailureCount() + 1;
        final Long maxFailureCount = operationEntity.getMaxFailureCount();

        if (failureCount < maxFailureCount) {
            operationEntity.setFailureCount(failureCount);

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
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
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
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
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (!operationOptional.isPresent()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
        }

        // Check if the operation is not expired
        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        final OperationStatusDo operationStatus = operationEntity.getStatus();
        if (!OperationStatusDo.PENDING.equals(operationStatus)) {
            logger.debug("Operation is not PENDING - operation ID: {}, status: {}", operationId, operationStatus);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_INVALID_STATE);
        }

        operationEntity.setStatus(OperationStatusDo.CANCELED);
        final OperationEntity savedEntity = operationRepository.save(operationEntity);
        behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
        return convertFromEntity(savedEntity);
    }

    public OperationDetailResponse getOperation(OperationDetailRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperation(operationId);
        if (!operationOptional.isPresent()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
        }

        final OperationEntity operationEntity = expireOperation(operationOptional.get(), currentTimestamp);
        return convertFromEntity(operationEntity);
    }

    public OperationListResponse findAllOperationsForUser(OperationListForUserRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();

        // Fetch application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (!application.isPresent()) {
            logger.error("Application was not found for ID: {}.", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        final OperationListResponse result = new OperationListResponse();
        try (final Stream<OperationEntity> operationsForUser = operationRepository.findAllOperationsForUser(userId, applicationId)) {
            operationsForUser.forEach(op -> {
                final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
                result.add(convertFromEntity(operationEntity));
            });
        }
        return result;
    }

    public OperationListResponse findPendingOperationsForUser(OperationListForUserRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String userId = request.getUserId();
        final Long applicationId = request.getApplicationId();

        // Fetch application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (!application.isPresent()) {
            logger.error("Application was not found for ID: {}.", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        final OperationListResponse result = new OperationListResponse();
        try (final Stream<OperationEntity> operationsForUser = operationRepository.findPendingOperationsForUser(userId, applicationId)) {
            operationsForUser.forEach(op -> {
                final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
                // Skip operation that just expired
                if (OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
                    result.add(convertFromEntity(operationEntity));
                }
            });
        }
        return result;
    }

    /**
     * Find operations identified by an external ID value.
     * @param request Request with the external ID.
     * @return List of operations that match.
     */
    public OperationListResponse findOperationsByExternalId(OperationExtIdRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String externalId = request.getExternalId();
        final Long applicationId = request.getApplicationId();

        // Fetch application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (!application.isPresent()) {
            logger.error("Application was not found for ID: {}.", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        final OperationListResponse result = new OperationListResponse();
        try (final Stream<OperationEntity> operationsByExternalId = operationRepository.findOperationsByExternalId(externalId, applicationId)) {
            operationsByExternalId.forEach(op -> {
                final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
                result.add(convertFromEntity(operationEntity));
            });
        }
        return result;
    }

    private OperationDetailResponse convertFromEntity(OperationEntity source) {
        OperationDetailResponse destination = new OperationDetailResponse();
        destination.setId(source.getId());
        destination.setUserId(source.getUserId());
        destination.setApplicationId(source.getApplication().getId());
        destination.setExternalId(source.getExternalId());
        destination.setOperationType(source.getOperationType());
        destination.setData(source.getData());
        destination.setParameters(source.getParameters());
        final List<SignatureType> signatureTypeList = Arrays.stream(source.getSignatureType())
                .distinct()
                .map(p -> SignatureType.enumFromString(p.toString()))
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
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
            return savedEntity;
        }
        return source;
    }

    private boolean factorsAcceptable(@NotNull OperationEntity operation, PowerAuthSignatureTypes usedFactor) {
        final String operationId = operation.getId();
        final PowerAuthSignatureTypes[] allowedFactors = operation.getSignatureType();
        if (usedFactor == null) { // the used factor is unknown
            logger.warn("Null authentication factors used for operation ID: {} - allowed: {}", operationId, Arrays.toString(allowedFactors));
            return false;
        }
        if (allowedFactors == null) {
            logger.error("Null allowed signature types for operation ID: {}. Check your configuration in pa_operation_template table.", operationId);
            return false; // likely a misconfiguration
        }
        if (Arrays.asList(allowedFactors).contains(usedFactor)) {
            return true;
        } else {
            logger.warn("Invalid authentication factors used for operation ID: {} - allowed: {}, used: {}", operationId, Arrays.toString(allowedFactors), usedFactor);
            return false;
        }
    }

    private boolean isDataEqual(@NotNull OperationEntity operation, String providedData) {
        final String operationId = operation.getId();
        final String operationData = operation.getData();
        if (operationData == null) {
            logger.error("Null operation data for operation ID: {}. Check your configuration in pa_operation_template table.", operationId);
            return false; // likely a misconfiguration
        }
        if (operationData.equals(providedData)) {
            return true;
        } else {
            logger.warn("Invalid data for operation ID: {} - expected: {}, used: {}", operationId, operationData, providedData);
            return false;
        }
    }

    // Scheduled tasks

    @Scheduled(fixedRateString = "${powerauth.service.scheduled.job.operationCleanup}")
    @SchedulerLock(name = "expireOperationsTask")
    @Transactional
    public void expireOperations() {
        LockAssert.assertLocked();
        final Date currentTimestamp = new Date();
        logger.debug("Running scheduled task for expiring operations");
        try (final Stream<OperationEntity> pendingOperations = operationRepository.findExpiredPendingOperations(currentTimestamp)) {
            pendingOperations.forEach(op -> expireOperation(op, currentTimestamp));
        }
    }
}
