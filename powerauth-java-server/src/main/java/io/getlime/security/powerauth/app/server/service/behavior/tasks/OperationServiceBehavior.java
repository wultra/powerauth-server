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
import com.wultra.core.http.common.headers.UserAgent;
import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.UserActionResult;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.database.repository.OperationRepository;
import io.getlime.security.powerauth.app.server.database.repository.OperationTemplateRepository;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.totp.Totp;
import jakarta.validation.constraints.NotNull;
import lombok.SneakyThrows;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.apache.commons.text.StringSubstitutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
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

    private static final int PROXIMITY_OTP_SEED_LENGTH = 16;
    private static final String PROXIMITY_OTP = "proximity_otp";
    private static final String ATTR_USER_AGENT = "userAgent";
    private static final String ATTR_DEVICE = "device";

    private final OperationRepository operationRepository;
    private final OperationTemplateRepository templateRepository;
    private final ApplicationRepository applicationRepository;
    private final ActivationRepository activationRepository;

    private final ServiceBehaviorCatalogue behavior;
    private final AuditingServiceBehavior audit;

    private LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    /**
     * Lambda interface that allows customizing the approval of operation.
     */
    public interface OperationApprovalCustomizer {
        /**
         * Method to proceed with approval or fail the operation. Mandatory checks have precedence over this call
         * result, so it is not possible to force approve an operation that would otherwise be rejected.
         *
         * @param operationEntity Operation entity to be approved.
         * @param request Request with approval attempt.
         * @return True in case the operation can be approved, false to fail operation approval.
         */
        boolean operationShouldFail(OperationEntity operationEntity, OperationApproveRequest request);
    }

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(OperationServiceBehavior.class);

    @Autowired
    public OperationServiceBehavior(
            OperationRepository operationRepository,
            OperationTemplateRepository templateRepository,
            ApplicationRepository applicationRepository,
            ActivationRepository activationRepository,
            ServiceBehaviorCatalogue behavior,
            AuditingServiceBehavior audit,
            PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.operationRepository = operationRepository;
        this.templateRepository = templateRepository;
        this.applicationRepository = applicationRepository;
        this.behavior = behavior;
        this.audit = audit;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.activationRepository = activationRepository;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    public OperationDetailResponse createOperation(OperationCreateRequest request) throws GenericServiceException {

        final String userId = request.getUserId();
        final List<String> applications = request.getApplications();
        final String activationFlag = request.getActivationFlag();
        final String templateName = request.getTemplateName();
        final Date timestampExpiresRequest = request.getTimestampExpires();
        final Map<String, String> parameters = request.getParameters() != null ? request.getParameters() : new LinkedHashMap<>();
        final Map<String, Object> additionalData = request.getAdditionalData() != null ? request.getAdditionalData() : new LinkedHashMap<>();
        final String externalId = request.getExternalId();
        final String activationId = request.getActivationId();

        // Prepare current timestamp in advance
        final Date currentTimestamp = new Date();

        if (timestampExpiresRequest != null && timestampExpiresRequest.before(currentTimestamp)) {
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Fetch the operation template
        final Optional<OperationTemplateEntity> template = templateRepository.findTemplateByName(templateName);
        if (template.isEmpty()) {
            logger.error("Operation template was not found: {}. Check your configuration in pa_operation_template table.", templateName);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
        }
        final OperationTemplateEntity templateEntity = template.get();

        // Resolve the operation expiration date
        final Date timestampExpires;
        if (timestampExpiresRequest != null) {
            timestampExpires = timestampExpiresRequest;
        } else {
            final long expiration = templateEntity.getExpiration() * 1000L;
            timestampExpires = new Date(currentTimestamp.getTime() + expiration);
        }

        // Check if applications exist
        final List<ApplicationEntity> applicationEntities = applicationRepository.findAllByIdIn(applications);
        if (applicationEntities.size() != applications.size()) {
            logger.error("Not matching expected applications: {} vs. {}", applications, applicationEntities.stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        // Generate unique token ID.
        String operationId = null;
        for (int i = 0; i < powerAuthServiceConfiguration.getGenerateOperationIterations(); i++) {
            final String tmpOperationId = UUID.randomUUID().toString();
            final Optional<OperationEntity> tmpTokenOptional = operationRepository.findOperation(tmpOperationId);
            if (tmpTokenOptional.isEmpty()) {
                operationId = tmpOperationId;
                break;
            } // ... else this token ID has a collision, reset it and try to find another one
        }
        if (operationId == null) {
            logger.error("Unable to generate token due to too many UUID.randomUUID() collisions. Check your random generator setup.");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_TOKEN);
        }

        // Build operation data
        final StringSubstitutor sub = new StringSubstitutor(parameters);
        final String operationData = sub.replace(templateEntity.getDataTemplate());

        // Create a new operation
        final OperationEntity operationEntity = new OperationEntity();
        operationEntity.setId(operationId);
        operationEntity.setUserId(userId);
        operationEntity.setApplications(applicationEntities);
        operationEntity.setExternalId(externalId);
        operationEntity.setActivationFlag(activationFlag);
        operationEntity.setOperationType(templateEntity.getOperationType());
        operationEntity.setTemplateName(templateEntity.getTemplateName());
        operationEntity.setData(operationData);
        operationEntity.setParameters(parameters);
        operationEntity.setAdditionalData(additionalData);
        operationEntity.setStatus(OperationStatusDo.PENDING);
        operationEntity.setSignatureType(templateEntity.getSignatureType());
        operationEntity.setFailureCount(0L);
        operationEntity.setMaxFailureCount(templateEntity.getMaxFailureCount());
        operationEntity.setTimestampCreated(currentTimestamp);
        operationEntity.setTimestampExpires(timestampExpires);
        operationEntity.setTimestampFinalized(null); // empty initially
        operationEntity.setRiskFlags(templateEntity.getRiskFlags());
        operationEntity.setTotpSeed(generateTotpSeed(request, templateEntity));
        operationEntity.setActivationId(activationId);

        final AuditDetail auditDetail = AuditDetail.builder()
                .type(AuditType.OPERATION.getCode())
                .param("id", operationId)
                .param("userId", userId)
                .param("applications", applications)
                .param("externalId", externalId)
                .param("activationFlag", activationFlag)
                .param("operationType", templateEntity.getOperationType())
                .param("template", templateEntity.getTemplateName())
                .param("data", operationData)
                .param("parameters", parameters)
                .param("additionalData", additionalData)
                .param("status", OperationStatusDo.PENDING.name())
                .param("allowedSignatureType", templateEntity.getSignatureType())
                .param("maxFailureCount", operationEntity.getMaxFailureCount())
                .param("timestampExpires", timestampExpires)
                .param("proximityCheckEnabled", operationEntity.getTotpSeed() != null)
                .param("activationId", activationId)
                .build();
        audit.log(AuditLevel.INFO, "Operation created with ID: {}", auditDetail, operationId);

        final OperationEntity savedEntity = operationRepository.save(operationEntity);
        behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
        return convertFromEntity(savedEntity);

    }

    public OperationUserActionResponse attemptApproveOperation(OperationApproveRequest request) throws GenericServiceException {
        return attemptApproveOperation(request, (op, req) -> false);
    }

    public OperationUserActionResponse attemptApproveOperation(OperationApproveRequest request, OperationApprovalCustomizer operationApprovalCustomizer) throws GenericServiceException {
        final Instant currentInstant = Instant.now();
        final Date currentTimestamp = Date.from(currentInstant);

        final String operationId = request.getOperationId();
        final String userId = request.getUserId();
        final String applicationId = request.getApplicationId();
        final String data = request.getData();
        final SignatureType signatureType = request.getSignatureType();
        final Map<String, Object> additionalData = request.getAdditionalData();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (operationOptional.isEmpty()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_APPROVE_FAILURE);
        }

        // Fetch application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (application.isEmpty()) {
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
        final ProximityCheckResult proximityCheckResult = fetchProximityCheckResult(operationEntity, request, currentInstant);
        final String expectedUserId = operationEntity.getUserId();
        final boolean activationIdMatches = activationIdMatches(request, operationEntity.getActivationId());
        final boolean operationShouldFail = operationApprovalCustomizer.operationShouldFail(operationEntity, request);
        if (expectedUserId == null || expectedUserId.equals(userId) // correct user approved the operation
            && operationEntity.getApplications().contains(application.get()) // operation is approved by the expected application
            && isDataEqual(operationEntity, data) // operation data matched the expected value
            && factorsAcceptable(operationEntity, factorEnum) // auth factors are acceptable
            && operationEntity.getMaxFailureCount() > operationEntity.getFailureCount() // operation has sufficient attempts left (redundant check)
            && proximityCheckPassed(proximityCheckResult)
            && activationIdMatches // either Operation does not have assigned activationId or it has one, and it matches activationId from request
            && !operationShouldFail) { // operation customizer can change the approval status by an external impulse

            // Approve the operation
            operationEntity.setUserId(userId);
            operationEntity.setStatus(OperationStatusDo.APPROVED);
            operationEntity.setTimestampFinalized(currentTimestamp);
            operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);
            extendAdditionalDataWithDevice(operationDetailResponse.getAdditionalData());

            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.OPERATION.getCode())
                    .param("id", operationId)
                    .param("userId", userId)
                    .param("appId", applicationId)
                    .param("status", savedEntity.getStatus().name())
                    .param("additionalData", operationDetailResponse.getAdditionalData())
                    .param("failureCount", savedEntity.getFailureCount())
                    .param("proximityCheckResult", proximityCheckResult)
                    .param("currentTimestamp", currentTimestamp)
                    .param("activationIdOperation", savedEntity.getActivationId())
                    .build();
            audit.log(AuditLevel.INFO, "Operation approved with ID: {}", auditDetail, operationId);

            final OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.APPROVED);
            response.setOperation(operationDetailResponse);
            return response;
        } else {

            // Update failure count, check the failure count and FAIL operation if needed
            final Long failureCount = operationEntity.getFailureCount() + 1;
            final Long maxFailureCount = operationEntity.getMaxFailureCount();

            if (failureCount < maxFailureCount) {
                operationEntity.setUserId(userId);
                operationEntity.setFailureCount(failureCount);
                operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

                final OperationEntity savedEntity = operationRepository.save(operationEntity);
                behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                logger.info("Operation approval failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

                final AuditDetail auditDetail = AuditDetail.builder()
                        .type(AuditType.OPERATION.getCode())
                        .param("id", operationId)
                        .param("userId", userId)
                        .param("appId", applicationId)
                        .param("status", operationEntity.getStatus().name())
                        .param("additionalData", operationEntity.getAdditionalData())
                        .param("failureCount", operationEntity.getFailureCount())
                        .param("proximityCheckResult", proximityCheckResult)
                        .param("currentTimestamp", currentTimestamp)
                        .param("activationIdMatches", activationIdMatches)
                        .param("activationIdOperation", operationEntity.getActivationId())
                        .param("activationIdRequest", additionalData.get("activationId"))
                        .param("operationShouldFail", operationShouldFail)
                        .build();
                audit.log(AuditLevel.INFO, "Operation approval failed with ID: {}, failed attempts count: {}", auditDetail, operationId, operationEntity.getFailureCount());

                final OperationUserActionResponse response = new OperationUserActionResponse();
                response.setResult(UserActionResult.APPROVAL_FAILED);
                response.setOperation(operationDetailResponse);
                return response;
            } else {
                operationEntity.setUserId(userId);
                operationEntity.setStatus(OperationStatusDo.FAILED);
                operationEntity.setTimestampFinalized(currentTimestamp);
                operationEntity.setFailureCount(maxFailureCount); // just in case, set the failure count to max value
                operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

                final OperationEntity savedEntity = operationRepository.save(operationEntity);
                behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                logger.info("Operation failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

                final AuditDetail auditDetail = AuditDetail.builder()
                        .type(AuditType.OPERATION.getCode())
                        .param("id", operationId)
                        .param("userId", userId)
                        .param("appId", applicationId)
                        .param("status", operationEntity.getStatus().name())
                        .param("additionalData", operationEntity.getAdditionalData())
                        .param("failureCount", operationEntity.getFailureCount())
                        .param("maxFailureCount", operationEntity.getMaxFailureCount())
                        .param("proximityCheckResult", proximityCheckResult)
                        .param("currentTimestamp", currentTimestamp)
                        .param("activationIdMatches", activationIdMatches)
                        .param("activationIdOperation", operationEntity.getActivationId())
                        .param("activationIdRequest", additionalData.get("activationId"))
                        .param("operationShouldFail", operationShouldFail)
                        .build();
                audit.log(AuditLevel.INFO, "Operation failed with ID: {}", auditDetail, operationId);

                final OperationUserActionResponse response = new OperationUserActionResponse();
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
        final String applicationId = request.getApplicationId();
        final Map<String, Object> additionalData = request.getAdditionalData();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (operationOptional.isEmpty()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_REJECT_FAILURE);
        }

        // Fetch application
        final Optional<ApplicationEntity> application = applicationRepository.findById(applicationId);
        if (application.isEmpty()) {
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

        final String expectedUserId = operationEntity.getUserId();
        if (expectedUserId == null || expectedUserId.equals(userId) // correct user rejects the operation
                && operationEntity.getApplications().contains(application.get())) { // operation is rejected by the expected application

            // Reject the operation
            operationEntity.setUserId(userId);
            operationEntity.setStatus(OperationStatusDo.REJECTED);
            operationEntity.setTimestampFinalized(currentTimestamp);
            operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);
            extendAdditionalDataWithDevice(operationDetailResponse.getAdditionalData());

            logger.info("Operation rejected operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.OPERATION.getCode())
                    .param("id", operationId)
                    .param("userId", userId)
                    .param("appId", applicationId)
                    .param("status", operationEntity.getStatus().name())
                    .param("additionalData", operationDetailResponse.getAdditionalData())
                    .param("failureCount", operationEntity.getFailureCount())
                    .build();
            audit.log(AuditLevel.INFO, "Operation failed with ID: {}", auditDetail, operationId);

            final OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.REJECTED);
            response.setOperation(operationDetailResponse);
            return response;
        } else {
            logger.info("Operation reject failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.OPERATION.getCode())
                    .param("id", operationId)
                    .param("userId", userId)
                    .param("appId", applicationId)
                    .param("failureCount", operationEntity.getFailureCount())
                    .param("status", operationEntity.getStatus().name())
                    .param("additionalData", operationEntity.getAdditionalData())
                    .build();
            audit.log(AuditLevel.INFO, "Operation failed with ID: {}", auditDetail, operationId);

            final OperationDetailResponse operationDetailResponse = convertFromEntity(operationEntity);
            final OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.REJECT_FAILED);
            response.setOperation(operationDetailResponse);
            return response;
        }
    }

    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();
        final Map<String, Object> additionalData = request.getAdditionalData();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (operationOptional.isEmpty()) {
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
            operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);
            extendAdditionalDataWithDevice(operationDetailResponse.getAdditionalData());

            logger.info("Operation approval failed via explicit server call for operation ID: {}.", operationId);

            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.OPERATION.getCode())
                    .param("id", operationId)
                    .param("failureCount", operationEntity.getFailureCount())
                    .param("status", operationEntity.getStatus().name())
                    .param("additionalData", operationDetailResponse.getAdditionalData())
                    .build();
            audit.log(AuditLevel.INFO, "Operation approval failed via explicit server call with ID: {}", auditDetail, operationId);

            final OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.APPROVAL_FAILED);
            response.setOperation(operationDetailResponse);
            return response;
        } else {
            operationEntity.setStatus(OperationStatusDo.FAILED);
            operationEntity.setTimestampFinalized(currentTimestamp);
            operationEntity.setFailureCount(maxFailureCount); // just in case, set the failure count to max value
            operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

            logger.info("Operation approval permanently failed via explicit server call for operation ID: {}.", operationId);

            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.OPERATION.getCode())
                    .param("id", operationId)
                    .param("failureCount", operationEntity.getFailureCount())
                    .param("status", operationEntity.getStatus().name())
                    .param("additionalData", operationEntity.getAdditionalData())
                    .build();
            audit.log(AuditLevel.INFO, "Operation approval permanently failed via explicit server call with ID: {}", auditDetail, operationId);

            final OperationUserActionResponse response = new OperationUserActionResponse();
            response.setResult(UserActionResult.OPERATION_FAILED);
            response.setOperation(operationDetailResponse);
            return response;
        }

    }

    public OperationDetailResponse cancelOperation(OperationCancelRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();
        final Map<String, Object> additionalData = request.getAdditionalData();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperationWithLock(operationId);
        if (operationOptional.isEmpty()) {
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
        operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

        final OperationEntity savedEntity = operationRepository.save(operationEntity);
        behavior.getCallbackUrlBehavior().notifyCallbackListenersOnOperationChange(savedEntity);

        logger.info("Operation canceled via explicit server call for operation ID: {}.", operationId);

        final AuditDetail auditDetail = AuditDetail.builder()
                .type(AuditType.OPERATION.getCode())
                .param("id", operationId)
                .param("failureCount", operationEntity.getFailureCount())
                .param("status", operationEntity.getStatus().name())
                .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
                .build();
        audit.log(AuditLevel.INFO, "Operation canceled via explicit server call for operation ID: {}", auditDetail, operationId);

        return convertFromEntity(savedEntity);
    }

    public OperationDetailResponse getOperation(OperationDetailRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String operationId = request.getOperationId();

        // Check if the operation exists
        final Optional<OperationEntity> operationOptional = operationRepository.findOperation(operationId);
        if (operationOptional.isEmpty()) {
            logger.warn("Operation was not found for ID: {}.", operationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
        }

        final String userId = request.getUserId();

        final OperationEntity operationEntity = expireOperation(
                claimOperation(operationOptional.get(), userId, currentTimestamp),
                currentTimestamp
        );
        final OperationDetailResponse operationDetailResponse = convertFromEntity(operationEntity);
        extendAdditionalDataWithDevice(operationDetailResponse.getAdditionalData());
        generateAndSetOtpToOperationDetail(operationEntity, operationDetailResponse);
        return operationDetailResponse;
    }

    public OperationListResponse findAllOperationsForUser(final OperationListRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String userId = request.userId();
        final List<String> applicationIds = request.applications();

        // Fetch application
        final List<ApplicationEntity> applications = applicationRepository.findAllByIdIn(applicationIds);
        if (applications.size() != applicationIds.size()) {
            logger.error("Application was not found for ID: {} vs. {}.", applicationIds, applications.stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        final String activationId = request.activationId;
        final List<String> activationFlags = fetchActivationFlags(activationId);

        final OperationListResponse result = new OperationListResponse();
        try (final Stream<OperationEntity> operationsForUser = operationRepository.findAllOperationsForUser(userId, applicationIds, activationId, activationFlags.isEmpty() ? null : activationFlags, request.pageable())) {
            operationsForUser.forEach(op -> {
                final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
                result.add(convertFromEntity(operationEntity));
            });
        }
        return result;
    }

    public OperationListResponse findPendingOperationsForUser(OperationListRequest request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String userId = request.userId();
        final List<String> applicationIds = request.applications();

        // Fetch application
        final List<ApplicationEntity> applications = applicationRepository.findAllByIdIn(applicationIds);
        if (applications.size() != applicationIds.size()) {
            logger.error("Application was not found for ID: {} vs. {}.", applicationIds, applications.stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        final String activationId = request.activationId;
        final List<String> activationFlags = fetchActivationFlags(activationId);

        final OperationListResponse result = new OperationListResponse();
        try (final Stream<OperationEntity> operationsForUser = operationRepository.findPendingOperationsForUser(userId, applicationIds, activationId, activationFlags.isEmpty() ? null : activationFlags,  request.pageable())) {
            operationsForUser.forEach(op -> {
                final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
                // Skip operation that just expired
                if (OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
                    final OperationDetailResponse operationDetail = convertFromEntity(operationEntity);
                    generateAndSetOtpToOperationDetail(operationEntity, operationDetail);
                    result.add(operationDetail);
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
    public OperationListResponse findOperationsByExternalId(OperationListRequestWithExternalId request) throws GenericServiceException {
        final Date currentTimestamp = new Date();

        final String externalId = request.externalId();
        final List<String> applicationIds = request.applications();

        // Fetch application
        final List<ApplicationEntity> applications = applicationRepository.findAllByIdIn(applicationIds);
        if (applications.size() != applicationIds.size()) {
            logger.error("Application was not found for ID: {} vs. {}.", applicationIds, applications.stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }

        final OperationListResponse result = new OperationListResponse();
        try (final Stream<OperationEntity> operationsByExternalId = operationRepository.findOperationsByExternalId(externalId, applicationIds, request.pageable())) {
            operationsByExternalId.forEach(op -> {
                final OperationEntity operationEntity = expireOperation(op, currentTimestamp);
                result.add(convertFromEntity(operationEntity));
            });
        }
        return result;
    }

    private OperationDetailResponse convertFromEntity(OperationEntity source) {
        final OperationDetailResponse destination = new OperationDetailResponse();
        destination.setId(source.getId());
        destination.setUserId(source.getUserId());
        destination.setApplications(source.getApplications().stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
        destination.setExternalId(source.getExternalId());
        destination.setActivationFlag(source.getActivationFlag());
        destination.setOperationType(source.getOperationType());
        destination.setTemplateName(source.getTemplateName());
        destination.setData(source.getData());
        destination.setParameters(source.getParameters());
        destination.setAdditionalData(source.getAdditionalData() != null ? source.getAdditionalData() : Collections.emptyMap());
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
        destination.setRiskFlags(source.getRiskFlags());
        destination.setActivationId(source.getActivationId());

        switch (source.getStatus()) {
            case PENDING -> destination.setStatus(OperationStatus.PENDING);
            case CANCELED -> destination.setStatus(OperationStatus.CANCELED);
            case EXPIRED -> destination.setStatus(OperationStatus.EXPIRED);
            case APPROVED -> destination.setStatus(OperationStatus.APPROVED);
            case REJECTED -> destination.setStatus(OperationStatus.REJECTED);
            case FAILED -> destination.setStatus(OperationStatus.FAILED);
        }
        return destination;
    }

    private OperationEntity claimOperation(OperationEntity source, String userId, Date currentTimestamp) throws GenericServiceException {
        // If a user accessing the operation is specified in the query, either claim the operation to that user,
        // or check if the user is already granted to be able to access the operation.
        if (userId != null) {
            if (OperationStatusDo.PENDING.equals(source.getStatus())
                    && source.getTimestampExpires().after(currentTimestamp)) {
                final String operationId = source.getId();
                final String expectedUserId = source.getUserId();
                if (expectedUserId == null) {
                    logger.info("Operation {} will be assigned to the user {}.", operationId, userId);
                    source.setUserId(userId);
                    return operationRepository.save(source);
                } else if (!expectedUserId.equals(userId)) {
                    logger.warn("Operation with ID: {}, was accessed by user: {}, while previously assigned to user: {}.", operationId, userId, expectedUserId);
                    throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
                }
            }
        }
        return source;
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

    // Merge two maps into new one, replacing values in the first map when collision occurs
    private Map<String, Object> mapMerge(Map<String, Object> m1, Map<String, Object> m2) {
        final Map<String, Object> m3 = new HashMap<>();
        if (m1 != null) {
            m3.putAll(m1);
        }
        if (m2 != null) {
            m3.putAll(m2);
        }
        return m3;
    }

    @SneakyThrows(GenericServiceException.class)
    private void generateAndSetOtpToOperationDetail(final OperationEntity operation, final OperationDetailResponse operationDetailResponse) {
        final String totp = generateTotp(operation, powerAuthServiceConfiguration.getProximityCheckOtpLength());
        operationDetailResponse.setProximityOtp(totp);
    }

    private String generateTotp(final OperationEntity operation, final int otpLength) throws GenericServiceException {
        final String seed = operation.getTotpSeed();
        final String operationId = operation.getId();

        if (seed == null) {
            logger.debug("Seed is null for operation ID: {}", operationId);
            return null;
        }

        try {
            byte[] seedBytes = Base64.getDecoder().decode(seed);
            final Instant now = Instant.now();
            byte[] totp = Totp.generateTotpSha256(seedBytes, now, otpLength);

            return new String(totp, StandardCharsets.UTF_8);
        } catch (CryptoProviderException | IllegalArgumentException e) {
            logger.error("Unable to generate OTP for operation ID: {}, user ID: {}", operationId, operation.getUserId(), e);
            throw new GenericServiceException(ServiceError.OPERATION_ERROR, e.getMessage(), e.getLocalizedMessage());
        }
    }

    private static String generateTotpSeed(final OperationCreateRequest request, final OperationTemplateEntity template) throws GenericServiceException {
        if (Boolean.FALSE.equals(request.getProximityCheckEnabled())) {
            logger.debug("Proximity check is disabled in request from user ID: {}", request.getUserId());
            return null;
        } else if (Boolean.TRUE.equals(request.getProximityCheckEnabled()) || template.isProximityCheckEnabled()) {
            logger.debug("Proximity check is enabled, generating TOTP seed for user ID: {}, templateName: {}", request.getUserId(), template.getTemplateName());
            final KeyGenerator keyGenerator = new KeyGenerator();
            try {
                final byte[] seed = keyGenerator.generateRandomBytes(PROXIMITY_OTP_SEED_LENGTH);
                return Base64.getEncoder().encodeToString(seed);
            } catch (CryptoProviderException e) {
                logger.error("Unable to generate proximity OTP seed for operation, user ID: {}", request.getUserId(), e);
                throw new GenericServiceException(ServiceError.OPERATION_ERROR, e.getMessage(), e.getLocalizedMessage());
            }
        }
        logger.debug("Proximity check not enabled neither in request user ID: {} nor in templateName: {}", request.getUserId(), template.getTemplateName());
        return null;
    }

    private static boolean proximityCheckPassed(final ProximityCheckResult proximityCheckResult) {
        return proximityCheckResult == ProximityCheckResult.SUCCESS || proximityCheckResult == ProximityCheckResult.DISABLED;
    }

    private static boolean activationIdMatches(final OperationApproveRequest operationApproveRequest, String activationId) {
        return activationId == null || activationId.equals(operationApproveRequest.getAdditionalData().get("activationId"));
    }

    private ProximityCheckResult fetchProximityCheckResult(final OperationEntity operation, final OperationApproveRequest request, final Instant now) {
        final String seed = operation.getTotpSeed();
        if (seed == null) {
            return ProximityCheckResult.DISABLED;
        }

        final Object otpObject = request.getAdditionalData().get(PROXIMITY_OTP);
        if (otpObject == null) {
            logger.warn("Proximity check enabled for operation ID: {} but proximity OTP not sent", operation.getId());
            return ProximityCheckResult.FAILED;
        }
        try {
            final String otp = otpObject.toString();
            final int otpLength = powerAuthServiceConfiguration.getProximityCheckOtpLength();
            final boolean result = Totp.validateTotpSha256(otp.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(seed), now, otpLength);
            logger.debug("OTP validation result: {} for operation ID: {}", result, operation.getId());
            return result ? ProximityCheckResult.SUCCESS : ProximityCheckResult.FAILED;
        } catch (CryptoProviderException | IllegalArgumentException e) {
            logger.error("Unable to validate proximity OTP for operation ID: {}", operation.getId(), e);
            return ProximityCheckResult.ERROR;
        }
    }

    public static Map<String, Object> extendAdditionalDataWithDevice(Map<String, Object> additionalData) {
        if (additionalData != null) {
            final Map<String, Object> additionalDataExtended = new HashMap<>(additionalData);
            parseDeviceFromUserAgent(additionalDataExtended).ifPresent(device ->
                    additionalDataExtended.put(ATTR_DEVICE, device));
            return additionalDataExtended;
        }
        return Collections.emptyMap();
    }

    private static Optional<UserAgent.Device> parseDeviceFromUserAgent(Map<String, Object> additionalData) {
        final Object userAgentObject = additionalData.get(ATTR_USER_AGENT);
        if (userAgentObject != null) {
            return UserAgent.parse(userAgentObject.toString());
        }

        return Optional.empty();
    }

    private List<String> fetchActivationFlags(String activationId) {
        if (activationId != null) {
            logger.debug("Searching for operations with activationId: {}", activationId);
            final ActivationRecordEntity activationRecord = activationRepository.findActivationWithoutLock(activationId);
            if (activationRecord != null) {
                final List<String> flags = activationRecord.getFlags();
                return flags != null ? flags : Collections.emptyList();
            }
        }
        return Collections.emptyList();
    }

    // Scheduled tasks

    @Scheduled(fixedRateString = "${powerauth.service.scheduled.job.operationCleanup:5000}")
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

    private enum ProximityCheckResult {
        SUCCESS,
        FAILED,
        DISABLED,
        ERROR
    }

    public record OperationListRequest(String userId, List<String> applications, String activationId, Pageable pageable) {
    }

    public record OperationListRequestWithExternalId(String externalId, List<String> applications, Pageable pageable) {
    }
}
