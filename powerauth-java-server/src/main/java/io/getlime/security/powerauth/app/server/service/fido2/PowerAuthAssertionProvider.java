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

import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
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
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.AuditingServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Service responsible for assertion verification.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class PowerAuthAssertionProvider implements AssertionProvider {

    private final ServiceBehaviorCatalogue serviceBehaviorCatalogue;
    private final RepositoryCatalogue repositoryCatalogue;

    @Autowired
    public PowerAuthAssertionProvider(ServiceBehaviorCatalogue serviceBehaviorCatalogue, RepositoryCatalogue repositoryCatalogue) {
        this.serviceBehaviorCatalogue = serviceBehaviorCatalogue;
        this.repositoryCatalogue = repositoryCatalogue;
    }

    @Override
    @Transactional
    public AssertionChallenge provideChallengeForAssertion(List<String> applicationIds, String operationType, Map<String, String> parameters, String externalAuthenticationId) throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(applicationIds);
        operationCreateRequest.setTemplateName(operationType);
        operationCreateRequest.getParameters().putAll(parameters);

        final OperationDetailResponse operationDetailResponse = serviceBehaviorCatalogue.getOperationBehavior().createOperation(operationCreateRequest);
        final AssertionChallenge assertionChallenge = new AssertionChallenge();
        assertionChallenge.setUserId(operationDetailResponse.getUserId());
        assertionChallenge.setApplicationIds(operationDetailResponse.getApplications());
        assertionChallenge.setChallenge(operationDetailResponse.getId() + "&" + operationDetailResponse.getData());
        assertionChallenge.setFailedAttempts(operationDetailResponse.getFailureCount());
        assertionChallenge.setMaxFailedAttempts(operationDetailResponse.getMaxFailureCount());
        return assertionChallenge;
    }

    @Override
    @Transactional
    public AssertionChallenge approveAssertion(String challengeValue, AuthenticatorDetail authenticatorDetail) throws Fido2AuthenticationFailedException {
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
            operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE); //TODO: Use correct type
            //operationApproveRequest.getAdditionalData(); // TODO: Use context data from request
            final OperationUserActionResponse approveOperation = serviceBehaviorCatalogue.getOperationBehavior().attemptApproveOperation(operationApproveRequest);
            final UserActionResult result = approveOperation.getResult();
            final OperationDetailResponse operation = approveOperation.getOperation();
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
    public AssertionChallenge failAssertion(String challengeValue, AuthenticatorDetail authenticatorDetail) throws Fido2AuthenticationFailedException {
        try {
            final Date currentTimestamp = new Date();

            final String[] split = challengeValue.split("&", 1);
            final String operationId = split[0];

            final OperationFailApprovalRequest operationFailApprovalRequest = new OperationFailApprovalRequest();
            operationFailApprovalRequest.setOperationId(operationId);
            //operationApproveRequest.getAdditionalData(); // TODO: Use context data from request

            final ActivationRecordEntity activationWithLock = repositoryCatalogue.getActivationRepository().findActivationWithLock(authenticatorDetail.getActivationId());

            handleInvalidSignatureImpl(activationWithLock, new SignatureData(), currentTimestamp);

            final OperationUserActionResponse approveOperation = serviceBehaviorCatalogue.getOperationBehavior().failApprovalOperation(operationFailApprovalRequest);
            final OperationDetailResponse operation = approveOperation.getOperation();
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
     * Implementation of handle inactive activation during signature verification.
     * @param activation Activation used for signature verification.
     * @param signatureData Data related to the signature.
     * @param signatureType Used signature type.
     * @param currentTimestamp Signature verification timestamp.
     */
    private void handleInactiveActivationSignatureImpl(ActivationRecordEntity activation, SignatureData signatureData, SignatureType signatureType, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);
        serviceBehaviorCatalogue.getAuditingServiceBehavior().logSignatureAuditRecord(activationDto, signatureData, signatureType, false, activation.getVersion(), "activation_invalid_state", currentTimestamp);
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
