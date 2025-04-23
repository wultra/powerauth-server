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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationInitServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationRemoveServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationValidationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.v3.EncryptionServiceEcies;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.exceptions.RollbackingServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.v3.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.request.v3.PrepareActivationRequest;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.client.model.response.v3.CreateActivationResponse;
import com.wultra.security.powerauth.client.model.response.v3.PrepareActivationResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Set;

/**
 * Activation service specific to V3.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("activationCreateServiceBehaviorV3")
@Slf4j
@AllArgsConstructor
public class ActivationCreateServiceBehavior {

    private final ActivationProcessServiceBehavior activationProcessServiceV3;
    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationInitServiceBehavior activationInitServiceBehavior;
    private final ActivationValidationServiceBehavior activationValidationServiceBehavior;
    private final ActivationRemoveServiceBehavior activationRemoveServiceBehavior;
    private final EncryptionServiceEcies encryptionService;

    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    /**
     * Prepare activation with given parameters.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param request Request with prepared activation.
     * @return Prepare activation response.
     * @throws GenericServiceException If invalid values are provided.
     */
    @Transactional
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws GenericServiceException {
        try {
            final String activationCode = request.getActivationCode();
            final String applicationKey = request.getApplicationKey();
            final String protocolVersion = request.getProtocolVersion();

            // Build encrypted request
            final EciesEncryptedRequest encryptedRequest = new EciesEncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );

            // Get current timestamp
            final Date timestamp = new Date();

            // Decrypt activation data
            final EncryptionContext context = new EncryptionContext(protocolVersion, applicationKey, null, EncryptorId.ACTIVATION_LAYER_2);
            final DecryptionResult decryptionResult = encryptionService.decryptRequest(encryptedRequest, context);
            final ApplicationEntity application = decryptionResult.getApplication();

            // Fetch the current activation by activation code
            final Set<ActivationStatus> states = Set.of(ActivationStatus.CREATED);
            // Search for activation without lock to avoid potential deadlocks
            ActivationRecordEntity activation = activationQueryService.findActivationByCodeWithoutLock(application.getId(), activationCode, states, timestamp).orElseThrow(() -> {
                logger.warn("Activation with activation code: {} could not be obtained. It either does not exist or it already expired.", activationCode);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Search for activation again to acquire PESSIMISTIC_WRITE lock for activation row
            final String activationId = activation.getActivationId();
            activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            // Make sure to deactivate the activation if it is expired
            activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, true);

            // Validate that the activation is in correct state for the prepare step
            activationValidationServiceBehavior.validateCreatedActivation(activation, application, false);

            final EciesEncryptedResponse encryptedResponse = activationProcessServiceV3.processNewActivation(activation, decryptionResult, protocolVersion);

            // Generate response object
            final com.wultra.security.powerauth.client.model.response.v3.PrepareActivationResponse response = new com.wultra.security.powerauth.client.model.response.v3.PrepareActivationResponse();
            response.setActivationId(activation.getActivationId());
            response.setUserId(activation.getUserId());
            response.setApplicationId(application.getId());
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());
            response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            return response;
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

    /**
     * Create activation with given parameters.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param request Encrypted activation request.
     * @return Create activation response.
     * @throws GenericServiceException In case create activation fails
     */
    @Transactional(rollbackFor = {RuntimeException.class, RollbackingServiceException.class})
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws GenericServiceException {
        // Get request parameters
        final String userId = request.getUserId();
        final Date activationExpireTimestamp = request.getTimestampActivationExpire();
        final Long maxFailureCount = request.getMaxFailureCount();
        final String applicationKey = request.getApplicationKey();
        final String activationOtp = request.getActivationOtp();
        final String protocolVersion = request.getProtocolVersion();

        // Build encrypted request
        final EciesEncryptedRequest encryptedRequest = new EciesEncryptedRequest(
                request.getTemporaryKeyId(),
                request.getEphemeralPublicKey(),
                request.getEncryptedData(),
                request.getMac(),
                request.getNonce(),
                request.getTimestamp()
        );

        // Get current timestamp
        final Date timestamp = new Date();

        // Decrypt activation data
        final EncryptionContext context = new EncryptionContext(protocolVersion, applicationKey, null, EncryptorId.ACTIVATION_LAYER_2);
        final DecryptionResult decryptionResult = encryptionService.decryptRequest(encryptedRequest, context);
        final ApplicationEntity application = decryptionResult.getApplication();

        // Prepare activation OTP mode
        final ActivationOtpValidation activationOtpValidation = activationOtp != null ? ActivationOtpValidation.ON_COMMIT : ActivationOtpValidation.NONE;

        // Create an activation record and obtain the activation database record
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setProtocol(ActivationProtocol.POWERAUTH);
        initRequest.setApplicationId(application.getId());
        initRequest.setUserId(userId);
        initRequest.setMaxFailureCount(maxFailureCount);
        initRequest.setTimestampActivationExpire(activationExpireTimestamp);
        initRequest.setActivationOtp(activationOtp);
        initRequest.setActivationOtpValidation(activationOtpValidation);
        initRequest.setCommitPhase(com.wultra.security.powerauth.client.model.enumeration.CommitPhase.ON_COMMIT);
        final InitActivationResponse initResponse = activationInitServiceBehavior.initActivation(initRequest);
        final String activationId = initResponse.getActivationId();
        final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
            logger.warn("Activation not found, activation ID: {}", activationId);
            // The whole transaction is rolled back in case of this unexpected state
            return localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });

        // Make sure to deactivate the activation if it is expired
        activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, true);

        activationValidationServiceBehavior.validateCreatedActivation(activation, application, true);
        final EciesEncryptedResponse encryptedResponse = activationProcessServiceV3.processNewActivation(activation, decryptionResult, protocolVersion);

        // Generate encrypted response
        final CreateActivationResponse response = new CreateActivationResponse();
        response.setActivationId(activation.getActivationId());
        response.setUserId(activation.getUserId());
        response.setApplicationId(activation.getApplication().getId());
        response.setEncryptedData(encryptedResponse.getEncryptedData());
        response.setMac(encryptedResponse.getMac());
        response.setNonce(encryptedResponse.getNonce());
        response.setTimestamp(encryptedResponse.getTimestamp());
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        return response;
    }

}
