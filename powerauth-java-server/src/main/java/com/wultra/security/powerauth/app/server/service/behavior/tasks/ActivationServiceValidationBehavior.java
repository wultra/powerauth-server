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

import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.CommitPhase;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.crypto.lib.util.PasswordHash;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Behavior class implementing activation validations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ActivationServiceValidationBehavior {

    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final LocalizationProvider localizationProvider;
    private final CallbackUrlBehavior callbackUrlBehavior;

    /**
     * Validate activation in prepare or create activation step: it should be in CREATED state, it should be linked to correct
     * application and the activation code should have valid length.
     *
     * @param activation Activation used in prepare activation step.
     * @param application Application used in prepare activation step.
     * @param rollbackInCaseOfError Whether transaction should be rolled back in case of validation error.
     * @throws GenericServiceException In case activation state is invalid.
     */
    public void validateCreatedActivation(ActivationRecordEntity activation, ApplicationEntity application, boolean rollbackInCaseOfError) throws GenericServiceException {
        // If there is no such activation or application does not match the activation application, fail validation
        if (activation == null
                || !ActivationStatus.CREATED.equals(activation.getActivationStatus())
                || !Objects.equals(activation.getApplication().getRid(), application.getRid())) {
            logger.info("Activation state is invalid, activation ID: {}", activation != null ? activation.getActivationId() : "unknown");
            if (rollbackInCaseOfError) {
                // Rollback is used during createActivation, because activation has just been initialized and it is invalid
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            } else {
                // Regular exception is used during prepareActivation
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
        }

        // Make sure activation code has 23 characters
        if (activation.getActivationCode().length() != 23) {
            logger.warn("Activation code is invalid, activation ID: {}", activation.getActivationId());
            if (rollbackInCaseOfError) {
                // Rollback is used during createActivation, because activation has just been initialized and it is invalid
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            } else {
                // Regular exception is used during prepareActivation
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
        }
    }

    /**
     * Validate activation OTP against value set in the activation's record.
     *
     * @param confirmationOtp   OTP value to be validated.
     * @param activation        Activation record.
     * @param externalUserId    User ID of user who is performing this validation. Use null value if activation owner caused the change.
     * @throws GenericServiceException In case invalid data is provided or activation OTP is invalid.
     */
    public void validateActivationOtp(CommitPhase currentPhase, String confirmationOtp, ActivationRecordEntity activation, String externalUserId) throws GenericServiceException {

        final String activationId = activation.getActivationId();
        final ActivationOtpValidation expectedStage = activation.getActivationOtpValidation();
        final CommitPhase expectedCommitPhase = activation.getCommitPhase();
        final String expectedOtpHash = activation.getActivationOtp();

        if (expectedStage != ActivationOtpValidation.NONE) {
            // Validation using ActivationOtpValidation (deprecated):
            // - in case the check is done in different phase, skip validation
            // - for correct phase make sure OTP is available when required
            if (expectedStage == ActivationOtpValidation.ON_KEY_EXCHANGE && currentPhase == CommitPhase.ON_COMMIT
                    || expectedStage == ActivationOtpValidation.ON_COMMIT && currentPhase == CommitPhase.ON_KEY_EXCHANGE) {
                if (StringUtils.hasText(confirmationOtp)) {
                    logger.info("Activation OTP should not be present for activation ID: {}, stage: {}", activationId, currentPhase);
                    // Rollback is not required, database is not used for writing yet.
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
                }
                // Different phase, skip validation
                return;
            }
            if (!StringUtils.hasText(confirmationOtp)) {
                logger.info("Activation OTP is missing for activation ID: {}, phase: {}", activationId, currentPhase);
                // Rollback is not required, database is not used for writing yet.
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
            }
        } else {
            // Validation of commit phase:
            // - if no OTP is specified for an activation, no validation is required
            // - in case the commit is done in different phase, skip validation
            // - for correct phase make sure OTP is available when required
            if (expectedOtpHash == null) {
                return;
            }
            if (currentPhase != expectedCommitPhase) {
                if (StringUtils.hasText(confirmationOtp)) {
                    logger.info("Activation OTP should not be present for activation ID: {}, stage: {}", activationId, currentPhase);
                    // Rollback is not required, database is not used for writing yet.
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
                }
                // Different phase, skip validation
                return;
            }
            if (!StringUtils.hasText(confirmationOtp)) {
                logger.info("Activation OTP is missing for activation ID: {}, stage: {}", activationId, currentPhase);
                // Rollback is not required, database is not used for writing yet.
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
            }
        }

        // Check whether hash is present in the database.
        if (expectedOtpHash == null) {
            logger.info("Activation OTP is missing in activation data: {}", activationId);
            // Rollback is not required, database is not used for writing yet.
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
        }

        // Now verify OTP value
        try {
            if (PasswordHash.verify(confirmationOtp.getBytes(StandardCharsets.UTF_8), expectedOtpHash)) {
                // Everything looks fine. Reset the failed attempts counter.
                activation.setFailedAttempts(0L);
                return;
            }
        } catch (IOException e) {
            // This exception typically means that the hash stored in DB is in wrong format. The rest of this method
            // will treat this as an invalid OTP.
            logger.warn("Invalid activation OTP hash: {}", activationId);
        }

        // Confirmation OTP doesn't match value stored in the database.

        // Increase the number of failed attempts and validate the maximum number of failed attempts.
        activation.setFailedAttempts(activation.getFailedAttempts() + 1L);
        final boolean removeActivation = activation.getFailedAttempts() >= activation.getMaxFailedAttempts();

        // If activation should be removed then set its status to REMOVED.
        if (removeActivation) {
            activation.setActivationStatus(ActivationStatus.REMOVED);
        }

        // Save activation state with the reason.
        final String activationSaveReason = removeActivation ? AdditionalInformation.Reason.ACTIVATION_OTP_MAX_FAILED_ATTEMPTS : AdditionalInformation.Reason.ACTIVATION_OTP_FAILED_ATTEMPT;
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId, activationSaveReason);

        // Also notify the listeners in case that the state of the activation was changed.
        if (removeActivation) {
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        }

        // ...and finally throw an exception.
        logger.info("Invalid activation OTP: {}", activationId);
        // Exception must not be rollbacking, otherwise data written to database in this method would be lost.
        throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
    }

}
