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

package io.getlime.security.powerauth.app.server.service.fido2;

import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.converter.AssertionChallengeConverter;
import com.wultra.powerauth.fido2.service.Fido2AuthenticatorService;
import com.wultra.powerauth.fido2.service.provider.AssertionProvider;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.UserActionResult;
import com.wultra.security.powerauth.client.model.request.OperationApproveRequest;
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationFailApprovalRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorData;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorDetail;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;
import com.wultra.security.powerauth.fido2.model.request.AssertionChallengeRequest;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.AuditingServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * Service responsible for assertion verification.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class PowerAuthAssertionProvider implements AssertionProvider {

    private static final String AUDIT_TYPE_FIDO2 = "fido2";
    private static final String ATTR_ACTIVATION_ID = "activationId";
    private static final String ATTR_CREDENTIAL_ID = "credentialId";
    private static final String ATTR_ALLOW_CREDENTIALS = "allowCredentials";
    private static final String ATTR_APPLICATION_ID = "applicationId";
    private static final String ATTR_AUTH_FACTOR = "authFactor";
    private static final String ATTR_ORIGIN = "origin";
    private static final String ATTR_TOP_ORIGIN = "topOrigin";

    private final ServiceBehaviorCatalogue serviceBehaviorCatalogue;
    private final RepositoryCatalogue repositoryCatalogue;
    private final AuditingServiceBehavior audit;
    private final PowerAuthAuthenticatorProvider authenticatorProvider;
    private final Fido2AuthenticatorService fido2AuthenticatorService;
    private final AssertionChallengeConverter assertionChallengeConverter;

    @Autowired
    public PowerAuthAssertionProvider(ServiceBehaviorCatalogue serviceBehaviorCatalogue, RepositoryCatalogue repositoryCatalogue, AuditingServiceBehavior audit, PowerAuthAuthenticatorProvider authenticatorProvider, Fido2AuthenticatorService fido2AuthenticatorService, final AssertionChallengeConverter assertionChallengeConverter) {
        this.serviceBehaviorCatalogue = serviceBehaviorCatalogue;
        this.repositoryCatalogue = repositoryCatalogue;
        this.audit = audit;
        this.authenticatorProvider = authenticatorProvider;
        this.fido2AuthenticatorService = fido2AuthenticatorService;
        this.assertionChallengeConverter = assertionChallengeConverter;
    }

    @Override
    @Transactional
    public AssertionChallenge provideChallengeForAssertion(AssertionChallengeRequest request) throws GenericServiceException, Fido2AuthenticationFailedException {
        final List<AuthenticatorDetail> authenticatorDetails = new ArrayList<>();

        // If user ID is specified, fetch the user authenticators that should be allowed to respond the challenge
        final String userId = request.getUserId();
        if (userId != null) {
            //TODO: Optimize by fetching data for all applications
            for (String applicationId: request.getApplicationIds()) {
                final List<AuthenticatorDetail> ad = authenticatorProvider.findByUserId(userId, applicationId);
                authenticatorDetails.addAll(ad);
            }
        }

        final OperationCreateRequest operationCreateRequest = AssertionChallengeConverter.convertAssertionRequestToOperationRequest(request, authenticatorDetails);
        final OperationDetailResponse operationDetailResponse = serviceBehaviorCatalogue.getOperationBehavior().createOperation(operationCreateRequest);
        return assertionChallengeConverter.convertAssertionChallengeFromOperationDetail(operationDetailResponse, authenticatorDetails);
    }

    @Override
    @Transactional
    public AssertionChallenge approveAssertion(String challengeValue, AuthenticatorDetail authenticatorDetail, AuthenticatorData authenticatorData, CollectedClientData clientDataJSON) throws Fido2AuthenticationFailedException {
        try {

            final String[] split = challengeValue.split("&", 2);
            if (split.length != 2) {
                throw new Fido2AuthenticationFailedException("Invalid challenge");
            }
            final String operationId = split[0];
            final String operationData = split[1];

            final OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
            operationApproveRequest.setOperationId(operationId);
            operationApproveRequest.setData(operationData);
            operationApproveRequest.setApplicationId(authenticatorDetail.getApplicationId());
            operationApproveRequest.setUserId(authenticatorDetail.getUserId());
            operationApproveRequest.setSignatureType(supportedSignatureType(authenticatorDetail, authenticatorData.getFlags().isUserVerified()));
            operationApproveRequest.getAdditionalData().putAll(prepareAdditionalData(authenticatorDetail, authenticatorData, clientDataJSON));
            final OperationUserActionResponse approveOperation = serviceBehaviorCatalogue.getOperationBehavior().attemptApproveOperation(operationApproveRequest, (operationEntity, request) -> {
                @SuppressWarnings("unchecked")
                final List<String> allowCredentials = (List<String>) operationEntity.getAdditionalData().get(ATTR_ALLOW_CREDENTIALS);
                final String credentialId = (String) request.getAdditionalData().get(ATTR_CREDENTIAL_ID);
                return allowCredentials == null || allowCredentials.isEmpty() || allowCredentials.contains(credentialId);
            });
            final UserActionResult result = approveOperation.getResult();
            final OperationDetailResponse operation = approveOperation.getOperation();
            auditAssertionResult(authenticatorDetail, result);
            if (result == UserActionResult.APPROVED) {
                final AssertionChallenge assertionChallenge = new AssertionChallenge();
                assertionChallenge.setChallenge(challengeValue);
                assertionChallenge.setUserId(operation.getUserId());
                assertionChallenge.setApplicationIds(operation.getApplications());
                assertionChallenge.setFailedAttempts(operation.getFailureCount());
                assertionChallenge.setMaxFailedAttempts(operation.getMaxFailureCount());
                return assertionChallenge;
            } else {
                handleStatus(operation.getStatus());
                throw new Fido2AuthenticationFailedException("Operation approval failed");
            }
        } catch (GenericServiceException ex) {
            throw new Fido2AuthenticationFailedException(ex.getMessage(), ex);
        }
    }

    @Override
    @Transactional
    public AssertionChallenge failAssertion(String challengeValue, AuthenticatorDetail authenticatorDetail, AuthenticatorData authenticatorData, CollectedClientData clientDataJSON) throws Fido2AuthenticationFailedException {
        try {
            final Date currentTimestamp = new Date();

            final String[] split = challengeValue.split("&", 1);
            final String operationId = split[0];

            final OperationFailApprovalRequest operationFailApprovalRequest = new OperationFailApprovalRequest();
            operationFailApprovalRequest.setOperationId(operationId);
            operationFailApprovalRequest.getAdditionalData().putAll(prepareAdditionalData(authenticatorDetail, authenticatorData, clientDataJSON));

            final ActivationRecordEntity activationWithLock = repositoryCatalogue.getActivationRepository().findActivationWithLock(authenticatorDetail.getActivationId());

            handleInvalidSignatureImpl(activationWithLock, new SignatureData(), currentTimestamp);

            final OperationUserActionResponse approveOperation = serviceBehaviorCatalogue.getOperationBehavior().failApprovalOperation(operationFailApprovalRequest);
            final OperationDetailResponse operation = approveOperation.getOperation();
            auditAssertionResult(authenticatorDetail, approveOperation.getResult());
            handleStatus(operation.getStatus());
            final AssertionChallenge assertionChallenge = new AssertionChallenge();
            assertionChallenge.setChallenge(challengeValue);
            assertionChallenge.setUserId(operation.getUserId());
            assertionChallenge.setApplicationIds(operation.getApplications());
            assertionChallenge.setFailedAttempts(operation.getFailureCount());
            assertionChallenge.setMaxFailedAttempts(operation.getMaxFailureCount());
            return assertionChallenge;
        } catch (GenericServiceException ex) {
            throw new Fido2AuthenticationFailedException(ex.getMessage(), ex);
        }
    }

    /**
     * Audit result of an assertion verification result.
     * @param authenticator Authenticator detail.
     * @param result Assertion verification result.
     */
    private void auditAssertionResult(final AuthenticatorDetail authenticator, final UserActionResult result) {
        final AuditDetail auditDetail = AuditDetail.builder()
                .type(AUDIT_TYPE_FIDO2)
                .param("userId", authenticator.getUserId())
                .param("applicationId", authenticator.getApplicationId())
                .param("activationId", authenticator.getActivationId())
                .param("result", result)
                .build();
        audit.log(AuditLevel.INFO, "Assertion result for activation with ID: {}", auditDetail, authenticator.getActivationId());
    }

    /**
     * Implementation of handle invalid signature.
     * @param activation Activation used for signature verification.
     * @param signatureData Data related to the signature.
     * @param currentTimestamp Signature verification timestamp.
     */
    private void handleInvalidSignatureImpl(ActivationRecordEntity activation, SignatureData signatureData, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        // By default do not notify listeners
        boolean notifyCallbackListeners = false;

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        if (remainingAttempts <= 0) {
            activation.setActivationStatus(ActivationStatus.BLOCKED);
            activation.setBlockedReason(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
            // Save the activation and log change
            serviceBehaviorCatalogue.getActivationHistoryServiceBehavior().saveActivationAndLogChange(activation);
            final KeyValue entry = new KeyValue();
            entry.setKey(AdditionalInformation.Key.BLOCKED_REASON);
            entry.setValue(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
            signatureData.getAdditionalInfo().add(entry);
            // notify callback listeners
            notifyCallbackListeners = true;
        } else {
            // Save the activation
            activationRepository.save(activation);
        }

        // Create the audit log record.
        serviceBehaviorCatalogue.getAuditingServiceBehavior().logSignatureAuditRecord(activationDto, signatureData, SignatureType.POSSESSION_KNOWLEDGE,false, null, "signature_does_not_match", currentTimestamp);

        // Notify callback listeners, if needed
        if (notifyCallbackListeners) {
            serviceBehaviorCatalogue.getCallbackUrlBehavior().notifyCallbackListenersOnActivationChange(activation);
        }
    }

    /**
     * Prepare map with additional data stored with the operation.
     *
     * @param authenticatorDetail Authenticator detail.
     * @param authenticatorData   Authenticator data.
     * @param clientDataJSON      Client data.
     * @return Additional data map.
     */
    private Map<String, Object> prepareAdditionalData(
            final AuthenticatorDetail authenticatorDetail,
            final AuthenticatorData authenticatorData,
            final CollectedClientData clientDataJSON) {
        final Map<String, Object> additionalData = new LinkedHashMap<>();
        additionalData.put(ATTR_ACTIVATION_ID, authenticatorDetail.getActivationId());
        additionalData.put(ATTR_APPLICATION_ID, authenticatorDetail.getApplicationId());
        additionalData.put(ATTR_CREDENTIAL_ID, authenticatorData.getAttestedCredentialData().getCredentialId());
        additionalData.put(ATTR_AUTH_FACTOR, supportedSignatureType(authenticatorDetail, authenticatorData.getFlags().isUserVerified()));
        additionalData.put(ATTR_ORIGIN, clientDataJSON.getOrigin());
        additionalData.put(ATTR_TOP_ORIGIN, clientDataJSON.getTopOrigin());
        return additionalData;
    }

    /**
     * Handle operation status.
     *
     * <ul>
     *     <li>PENDING - noop</li>
     *     <li>CANCELLED, APPROVED, REJECTED, or EXPIRED - throws exception with appropriate code and message.</li>
     * </ul>
     *
     * @param status Operation status.
     * @throws Fido2AuthenticationFailedException In case operation is in status that does not allow processing, the method throws appropriate exception.
     */
    private void handleStatus(OperationStatus status) throws Fido2AuthenticationFailedException {
        switch (status) {
            case PENDING -> { /* The operation is still pending, no-op. */ }
            case CANCELED -> throw new Fido2AuthenticationFailedException("OPERATION_ALREADY_CANCELED - Operation was already canceled");
            case APPROVED, REJECTED -> throw new Fido2AuthenticationFailedException("OPERATION_ALREADY_FINISHED - Operation was already completed");
            case FAILED -> throw new Fido2AuthenticationFailedException("OPERATION_ALREADY_FAILED - Operation already failed");
            default -> throw new Fido2AuthenticationFailedException("OPERATION_EXPIRED - Operation already expired");
        }
    }

    private SignatureType supportedSignatureType(AuthenticatorDetail authenticatorDetail, boolean userVerified) {
        final String aaguid = (String) authenticatorDetail.getExtras().get("aaguid");
        if (aaguid != null) {
            return userVerified ? fido2AuthenticatorService.findByAaguid(UUID.fromString(aaguid)).signatureType() : SignatureType.POSSESSION;
        } else {
            return SignatureType.POSSESSION;
        }
    }

    private static AuditingServiceBehavior.ActivationRecordDto createActivationDtoFrom(ActivationRecordEntity activation) {
        return AuditingServiceBehavior.ActivationRecordDto.builder()
                .activationId(activation.getActivationId())
                .applicationId(activation.getApplication().getId())
                .counter(activation.getCounter())
                .ctrDataBase64(activation.getCtrDataBase64())
                .userId(activation.getUserId())
                .activationStatus(activation.getActivationStatus())
                .build();
    }

}
