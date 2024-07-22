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
import com.wultra.security.powerauth.client.model.validator.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthPageableConfiguration;
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
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import io.getlime.security.powerauth.app.server.service.persistence.OperationQueryService;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.totp.Totp;
import jakarta.validation.constraints.NotNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
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
@Slf4j
public class OperationServiceBehavior {

    private static final int PROXIMITY_OTP_SEED_LENGTH = 16;
    private static final String PROXIMITY_OTP = "proximity_otp";
    private static final String ATTR_USER_AGENT = "userAgent";
    private static final String ATTR_DEVICE = "device";

    private final CallbackUrlBehavior callbackUrlBehavior;

    private final OperationRepository operationRepository;
    private final OperationTemplateRepository templateRepository;
    private final ApplicationRepository applicationRepository;
    private final ActivationRepository activationRepository;
    private final OperationQueryService operationQueryService;
    private final ActivationQueryService activationQueryService;

    private final AuditingServiceBehavior audit;

    private LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final PowerAuthPageableConfiguration powerAuthPageableConfiguration;

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

    @Autowired
    public OperationServiceBehavior(
            CallbackUrlBehavior callbackUrlBehavior, OperationRepository operationRepository,
            OperationTemplateRepository templateRepository,
            ApplicationRepository applicationRepository,
            ActivationRepository activationRepository, OperationQueryService operationQueryService, ActivationQueryService activationQueryService,
            AuditingServiceBehavior audit,
            PowerAuthServiceConfiguration powerAuthServiceConfiguration, PowerAuthPageableConfiguration powerAuthPageableConfiguration) {
        this.callbackUrlBehavior = callbackUrlBehavior;
        this.operationRepository = operationRepository;
        this.templateRepository = templateRepository;
        this.applicationRepository = applicationRepository;
        this.operationQueryService = operationQueryService;
        this.activationQueryService = activationQueryService;
        this.audit = audit;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.activationRepository = activationRepository;
        this.powerAuthPageableConfiguration = powerAuthPageableConfiguration;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    @Transactional
    public OperationDetailResponse createOperation(OperationCreateRequest request) throws GenericServiceException {
        try {
            final String error = OperationCreateRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }
            validate(request);

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
                final Optional<OperationEntity> tmpTokenOptional = operationQueryService.findOperationWithoutLock(tmpOperationId);
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
            operationEntity.setUserId(fetchUserId(request));
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
                    .param("userId", operationEntity.getUserId())
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
            callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
            return convertFromEntityAndFillOtp(savedEntity);
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    private String fetchUserId(final OperationCreateRequest request) throws GenericServiceException {
        if (request.getUserId() != null) {
            return request.getUserId();
        } else if (request.getActivationId() != null) {
            final String activationId = request.getActivationId();
            logger.debug("Filling missing user ID from the activation ID: {}", activationId);
            return activationRepository.findById(activationId)
                    .map(ActivationRecordEntity::getUserId)
                    .orElseThrow(() -> {
                        logger.warn("Activation ID: {} does not exist.", activationId);
                        return localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                    });
        } else {
            return null;
        }
    }

    private void validate(final OperationCreateRequest request) throws GenericServiceException {
        final String activationId = request.getActivationId();
        final String userId = request.getUserId();
        if (activationId != null && userId != null && !doesActivationBelongToUser(activationId, userId)) {
            logger.warn("Activation ID: {} does not belong to user ID: {}", activationId, userId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    private boolean doesActivationBelongToUser(final String activationId, final String userId) {
        return activationRepository.findById(activationId)
                .map(ActivationRecordEntity::getUserId)
                .filter(userId::equals)
                .isPresent();
    }

    @Transactional
    public OperationUserActionResponse attemptApproveOperation(OperationApproveRequest request) throws GenericServiceException {
        return attemptApproveOperation(request, (op, req) -> false);
    }

    @Transactional
    public OperationUserActionResponse attemptApproveOperation(OperationApproveRequest request, OperationApprovalCustomizer operationApprovalCustomizer) throws GenericServiceException {
        try {
            final String error = OperationApproveRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Instant currentInstant = Instant.now();
            final Date currentTimestamp = Date.from(currentInstant);

            final String operationId = request.getOperationId();
            final String userId = request.getUserId();
            final String applicationId = request.getApplicationId();
            final String data = request.getData();
            final SignatureType signatureType = request.getSignatureType();
            final Map<String, Object> additionalData = request.getAdditionalData();

            // Check if the operation exists
            final Optional<OperationEntity> operationOptional = operationQueryService.findOperationForUpdate(operationId);
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
                callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                final AuditDetail auditDetail = AuditDetail.builder()
                        .type(AuditType.OPERATION.getCode())
                        .param("id", operationId)
                        .param("userId", userId)
                        .param("appId", applicationId)
                        .param("status", savedEntity.getStatus().name())
                        .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
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
                    callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
                    final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                    logger.info("Operation approval failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

                    final AuditDetail auditDetail = AuditDetail.builder()
                            .type(AuditType.OPERATION.getCode())
                            .param("id", operationId)
                            .param("userId", userId)
                            .param("appId", applicationId)
                            .param("status", operationEntity.getStatus().name())
                            .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
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
                    callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
                    final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                    logger.info("Operation failed for operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

                    final AuditDetail auditDetail = AuditDetail.builder()
                            .type(AuditType.OPERATION.getCode())
                            .param("id", operationId)
                            .param("userId", userId)
                            .param("appId", applicationId)
                            .param("status", operationEntity.getStatus().name())
                            .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
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
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back, operation ID: {}", request.getOperationId(), ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred, operation ID: {}", request.getOperationId(), ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    @Transactional
    public OperationUserActionResponse rejectOperation(OperationRejectRequest request) throws GenericServiceException {
        try {
            final String error = OperationRejectRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Date currentTimestamp = new Date();

            final String operationId = request.getOperationId();
            final String userId = request.getUserId();
            final String applicationId = request.getApplicationId();
            final Map<String, Object> additionalData = request.getAdditionalData();

            // Check if the operation exists
            final Optional<OperationEntity> operationOptional = operationQueryService.findOperationForUpdate(operationId);
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
                callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                logger.info("Operation rejected operation ID: {}, user ID: {}, application ID: {}.", operationId, userId, applicationId);

                final AuditDetail auditDetail = AuditDetail.builder()
                        .type(AuditType.OPERATION.getCode())
                        .param("id", operationId)
                        .param("userId", userId)
                        .param("appId", applicationId)
                        .param("status", operationEntity.getStatus().name())
                        .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
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
                        .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
                        .build();
                audit.log(AuditLevel.INFO, "Operation failed with ID: {}", auditDetail, operationId);

                final OperationDetailResponse operationDetailResponse = convertFromEntity(operationEntity);
                final OperationUserActionResponse response = new OperationUserActionResponse();
                response.setResult(UserActionResult.REJECT_FAILED);
                response.setOperation(operationDetailResponse);
                return response;
            }
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    @Transactional
    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws GenericServiceException {
        try {
            final String error = OperationFailApprovalRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Date currentTimestamp = new Date();

            final String operationId = request.getOperationId();
            final Map<String, Object> additionalData = request.getAdditionalData();

            // Check if the operation exists
            final Optional<OperationEntity> operationOptional = operationQueryService.findOperationForUpdate(operationId);
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
                callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                logger.info("Operation approval failed via explicit server call for operation ID: {}.", operationId);

                final AuditDetail auditDetail = AuditDetail.builder()
                        .type(AuditType.OPERATION.getCode())
                        .param("id", operationId)
                        .param("failureCount", operationEntity.getFailureCount())
                        .param("status", operationEntity.getStatus().name())
                        .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
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
                callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
                final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);

                logger.info("Operation approval permanently failed via explicit server call for operation ID: {}.", operationId);

                final AuditDetail auditDetail = AuditDetail.builder()
                        .type(AuditType.OPERATION.getCode())
                        .param("id", operationId)
                        .param("failureCount", operationEntity.getFailureCount())
                        .param("status", operationEntity.getStatus().name())
                        .param("additionalData", extendAdditionalDataWithDevice(operationEntity.getAdditionalData()))
                        .build();
                audit.log(AuditLevel.INFO, "Operation approval permanently failed via explicit server call with ID: {}", auditDetail, operationId);

                final OperationUserActionResponse response = new OperationUserActionResponse();
                response.setResult(UserActionResult.OPERATION_FAILED);
                response.setOperation(operationDetailResponse);
                return response;
            }
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    @Transactional
    public OperationDetailResponse cancelOperation(OperationCancelRequest request) throws GenericServiceException {
        try {
            final String error = OperationCancelRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Date currentTimestamp = new Date();

            final String operationId = request.getOperationId();
            final Map<String, Object> additionalData = request.getAdditionalData();

            // Check if the operation exists
            final Optional<OperationEntity> operationOptional = operationQueryService.findOperationForUpdate(operationId);
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
            operationEntity.setStatusReason(request.getStatusReason());
            operationEntity.setAdditionalData(mapMerge(operationEntity.getAdditionalData(), additionalData));

            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
            final OperationDetailResponse operationDetailResponse = convertFromEntity(savedEntity);
            extendAndSetOperationDetailData(operationDetailResponse);

            logger.info("Operation canceled via explicit server call for operation ID: {}.", operationId);

            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.OPERATION.getCode())
                    .param("id", operationId)
                    .param("failureCount", operationEntity.getFailureCount())
                    .param("status", operationEntity.getStatus().name())
                    .param("statusReason", request.getStatusReason())
                    .param("additionalData", operationDetailResponse.getAdditionalData())
                    .build();
            audit.log(AuditLevel.INFO, "Operation canceled via explicit server call for operation ID: {}", auditDetail, operationId);

            return operationDetailResponse;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    @Transactional // operation is modified when expiration happens
    public OperationDetailResponse operationDetail(OperationDetailRequest request) throws GenericServiceException {
        try {
            final String error = OperationDetailRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Date currentTimestamp = new Date();
            final String operationId = request.getOperationId();

            final OperationEntity operation = operationRepository.findOperation(operationId).orElseThrow(() -> {
                logger.warn("Operation was not found for ID: {}", operationId);
                return localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
            });

            final String userId = request.getUserId();
            final OperationEntity operationEntity = expireOperation(
                    claimOperation(operation, userId, currentTimestamp),
                    currentTimestamp
            );
            final OperationDetailResponse operationDetailResponse = convertFromEntityAndFillOtp(operationEntity);
            extendAndSetOperationDetailData(operationDetailResponse);
            return operationDetailResponse;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    @Transactional
    public OperationListResponse findAllOperationsForUser(final OperationListForUserRequest request) throws GenericServiceException {
        try {
            final String error = OperationListForUserRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Date currentTimestamp = new Date();

            final OperationListRequest operationListRequest = convert(request);

            final String userId = operationListRequest.userId();
            final List<String> applicationIds = operationListRequest.applications();

            // Fetch application
            final List<ApplicationEntity> applications = applicationRepository.findAllByIdIn(applicationIds);
            if (applications.size() != applicationIds.size()) {
                logger.error("Application was not found for ID: {} vs. {}.", applicationIds, applications.stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final String activationId = operationListRequest.activationId;
            final List<String> activationFlags = fetchActivationFlags(activationId);

            final OperationListResponse result = new OperationListResponse();
            try (final Stream<OperationEntity> operationsForUser = operationQueryService.findAllOperationsForUser(userId, applicationIds, activationId, activationFlags.isEmpty() ? null : activationFlags, operationListRequest.pageable())) {
                operationsForUser.forEach(op -> {
                    final OperationEntity operationEntity;
                    try {
                        operationEntity = expireOperation(op, currentTimestamp);
                        result.add(convertFromEntity(operationEntity));
                    } catch (GenericServiceException e) {
                        logger.error("Operation expiration failed, operation ID: {}", op.getId());
                    }
                });
            }
            return result;
        } catch (GenericServiceException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    @Transactional // operation is modified when expiration happens
    public OperationListResponse findPendingOperationsForUser(OperationListForUserRequest request) throws GenericServiceException {
        try {
            final String error = OperationListForUserRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final OperationListRequest operationListRequest = convert(request);

            final Date currentTimestamp = new Date();

            final String userId = operationListRequest.userId();
            final List<String> applicationIds = operationListRequest.applications();

            // Fetch application
            final List<ApplicationEntity> applications = applicationRepository.findAllByIdIn(applicationIds);
            if (applications.size() != applicationIds.size()) {
                logger.error("Application was not found for ID: {} vs. {}.", applicationIds, applications.stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            final String activationId = operationListRequest.activationId;
            final List<String> activationFlags = fetchActivationFlags(activationId);

            final OperationListResponse result = new OperationListResponse();
            try (final Stream<OperationEntity> operationsForUser = operationQueryService.findPendingOperationsForUser(userId, applicationIds, activationId, activationFlags.isEmpty() ? null : activationFlags, operationListRequest.pageable())) {
                operationsForUser.forEach(op -> {
                    final OperationEntity operationEntity;
                    try {
                        operationEntity = expireOperation(op, currentTimestamp);
                        // Skip operation that just expired
                        if (OperationStatusDo.PENDING.equals(operationEntity.getStatus())) {
                            final OperationDetailResponse operationDetail = convertFromEntityAndFillOtp(operationEntity);
                            result.add(operationDetail);
                        }
                    } catch (GenericServiceException e) {
                        logger.error("Operation expiration failed, operation ID: {}", op.getId());
                    }
                });
            }
            return result;
        } catch (GenericServiceException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Find operations identified by an external ID value.
     * @param request Request with the external ID.
     * @return List of operations that match.
     */
    @Transactional // operation is modified when expiration happens
    public OperationListResponse findOperationsByExternalId(OperationExtIdRequest request) throws GenericServiceException {
        try {
            final String error = OperationExtIdRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Date currentTimestamp = new Date();

            final OperationListRequestWithExternalId requestWithExternalId = convert(request);

            final String externalId = requestWithExternalId.externalId();
            final List<String> applicationIds = requestWithExternalId.applications();

            // Fetch application
            final List<ApplicationEntity> applications = applicationRepository.findAllByIdIn(applicationIds);
            if (applications.size() != applicationIds.size()) {
                logger.error("Application was not found for ID: {} vs. {}.", applicationIds, applications.stream().map(ApplicationEntity::getId).collect(Collectors.toList()));
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            final OperationListResponse result = new OperationListResponse();
            try (final Stream<OperationEntity> operationsByExternalId = operationQueryService.findOperationsByExternalId(externalId, applicationIds, requestWithExternalId.pageable())) {
                operationsByExternalId.forEach(op -> {
                    final OperationEntity operationEntity;
                    try {
                        operationEntity = expireOperation(op, currentTimestamp);
                        result.add(convertFromEntity(operationEntity));
                    } catch (GenericServiceException e) {
                        logger.error("Operation expiration failed, operation ID: {}", op.getId());
                    }
                });
            }
            return result;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Convert the given entity to the response class.
     * Mind that it does not fill the proximity OTP. If you need so, use {@link #convertFromEntityAndFillOtp(OperationEntity)} instead.
     *
     * @param source Entity to convert.
     * @return response class
     * @see #convertFromEntityAndFillOtp(OperationEntity)
     */
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
        destination.setStatusReason(source.getStatusReason());

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
                    logger.info("Operation ID: {} will be assigned to the user {}.", operationId, userId);
                    source.setUserId(userId);
                    return operationRepository.save(source);
                } else if (!expectedUserId.equals(userId)) {
                    logger.warn("Operation ID: {}, was accessed by user: {}, while previously assigned to user: {}.", operationId, userId, expectedUserId);
                    throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
                }
            }
        }
        return source;
    }

    private OperationEntity expireOperation(OperationEntity source, Date currentTimestamp) throws GenericServiceException {
        // Operation is still pending and timestamp is after the expiration.
        if (OperationStatusDo.PENDING.equals(source.getStatus())
                && source.getTimestampExpires().before(currentTimestamp)) {
            OperationEntity operationEntity = operationQueryService.findOperationForUpdate(source.getId()).orElseThrow(() -> {
                logger.warn("Operation was removed, ID: {}.", source.getId());
                return localizationProvider.buildExceptionForCode(ServiceError.OPERATION_NOT_FOUND);
            });
            logger.info("Operation {} expired.", operationEntity.getId());
            operationEntity.setStatus(OperationStatusDo.EXPIRED);
            final OperationEntity savedEntity = operationRepository.save(operationEntity);
            callbackUrlBehavior.notifyCallbackListenersOnOperationChange(savedEntity);
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

    /**
     * Convert the given entity to the response class.
     * Unlike {@link #convertFromEntity(OperationEntity)} also fill proximity OTP value if needed.
     *
     * @param source Entity to convert.
     * @return response class
     * @see #convertFromEntity(OperationEntity)
     */
    @SneakyThrows(GenericServiceException.class)
    private OperationDetailResponse convertFromEntityAndFillOtp(final OperationEntity source) {
        final String totp = generateTotp(source, powerAuthServiceConfiguration.getProximityCheckOtpLength());
        final OperationDetailResponse target = convertFromEntity(source);
        target.setProximityOtp(totp);
        return target;
    }

    private String generateTotp(final OperationEntity operation, final int otpLength) throws GenericServiceException {
        final String seed = operation.getTotpSeed();
        final String operationId = operation.getId();

        if (seed == null) {
            logger.debug("Seed is null for operation ID: {}", operationId);
            return null;
        }

        try {
            final byte[] seedBytes = Base64.getDecoder().decode(seed);
            final Instant now = Instant.now();
            final byte[] totp = Totp.generateTotpSha256(seedBytes, now, otpLength);

            return new String(totp, StandardCharsets.UTF_8);
        } catch (CryptoProviderException | IllegalArgumentException e) {
            logger.error("Unable to generate OTP for operation ID: {}, user ID: {}", operationId, operation.getUserId(), e);
            throw new GenericServiceException(ServiceError.OPERATION_ERROR, e.getMessage());
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
                throw new GenericServiceException(ServiceError.OPERATION_ERROR, e.getMessage());
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

    public static void extendAndSetOperationDetailData(OperationDetailResponse operationDetailResponse) {
        final Map<String, Object> additionalDataExtended = extendAdditionalDataWithDevice(operationDetailResponse.getAdditionalData());
        operationDetailResponse.setAdditionalData(additionalDataExtended);
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
            final Optional<ActivationRecordEntity> activationRecord = activationQueryService.findActivationWithoutLock(activationId);
            if (activationRecord.isPresent()) {
                final List<String> flags = activationRecord.get().getFlags();
                return flags != null ? flags : Collections.emptyList();
            }
        }
        return Collections.emptyList();
    }

    private OperationServiceBehavior.OperationListRequest convert(final OperationListForUserRequest source) {
        final int pageNumber = fetchPageNumberOrDefault(source.getPageNumber());
        final int pageSize = fetchPageSizeOrDefault(source.getPageSize());
        final Pageable pageable = PageRequest.of(pageNumber, pageSize);
        return new OperationServiceBehavior.OperationListRequest(source.getUserId(), source.getApplications(), source.getActivationId(), pageable);
    }

    private OperationServiceBehavior.OperationListRequestWithExternalId convert(final OperationExtIdRequest source) {
        final int pageNumber = fetchPageNumberOrDefault(source.getPageNumber());
        final int pageSize = fetchPageSizeOrDefault(source.getPageSize());
        final Pageable pageable = PageRequest.of(pageNumber, pageSize);
        return new OperationServiceBehavior.OperationListRequestWithExternalId(source.getExternalId(), source.getApplications(), pageable);
    }

    private int fetchPageNumberOrDefault(final Integer pageNumber) {
        return pageNumber != null ? pageNumber : powerAuthPageableConfiguration.defaultPageNumber();
    }

    private int fetchPageSizeOrDefault(final Integer pageSize) {
        return pageSize != null ? pageSize : powerAuthPageableConfiguration.defaultPageSize();
    }

    @Transactional
    public void expireOperations() {
        final Date currentTimestamp = new Date();
        logger.debug("Running scheduled task for expiring operations");

        final PageRequest pageRequest = PageRequest.of(0, powerAuthServiceConfiguration.getExpireOperationsLimit());
        try (final Stream<OperationEntity> pendingOperations = operationQueryService.findExpiredPendingOperations(currentTimestamp, pageRequest)) {
            pendingOperations.forEach(op -> {
                try {
                    expireOperation(op, currentTimestamp);
                } catch (GenericServiceException e) {
                    logger.error("Operation expiration failed, operation ID: {}", op.getId());
                }
            });
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
