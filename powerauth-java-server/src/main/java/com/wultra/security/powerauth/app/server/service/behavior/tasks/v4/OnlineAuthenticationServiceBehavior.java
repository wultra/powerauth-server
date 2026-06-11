/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationBlockService;
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.OnlineAuthenticationRequest;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationData;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationResponse;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthenticationResponse;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthAuthenticationCodeFormat;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * Behavior class implementing the authentication code validation related processes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class OnlineAuthenticationServiceBehavior {

    private final AuthenticationSharedServiceBehavior authenticationSharedServiceBehavior;
    private final ActivationQueryService activationQueryService;
    private final LocalizationProvider localizationProvider;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final ActivationBlockService activationBlockService;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    /**
     * Verify authentication for given activation and provided data in online mode. Log every validation attempt in the audit log.
     *
     * @param request Authentication verification request.
     * @return Response with the authentication verification result object.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    @Transactional
    public VerifyAuthenticationResponse verifyAuthentication(VerifyAuthenticationRequest request, List<KeyValue> additionalInfo) throws GenericServiceException {
        try {
            // Get request data
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String dataString = request.getData();
            final String authenticationCode = request.getAuthenticationCode();
            final String authenticationVersion = request.getAuthenticationVersion();
            final AuthenticationCodeType authenticationCodeType = request.getAuthenticationCodeType();
            boolean pendingCommitAllowed = false;
            if (request.getAllowedStates() != null) {
                for (com.wultra.security.powerauth.client.model.enumeration.ActivationStatus requestedState: request.getAllowedStates()) {
                    if (requestedState == com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.CREATED
                        || requestedState == com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.BLOCKED
                        || requestedState == com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.REMOVED) {
                        logger.warn("Invalid requested allowed states: {}", request.getAllowedStates());
                        // Rollback is not required, cryptography methods are executed before database is used for writing
                        throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                    }
                }
                pendingCommitAllowed = request.getAllowedStates().contains(com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.PENDING_COMMIT);
            }
            return verifyAuthenticationImpl(activationId, authenticationCodeType, authenticationCode, authenticationVersion, additionalInfo, dataString, applicationKey, pendingCommitAllowed);
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_AUTHENTICATION_CODE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }  catch (GenericServiceException ex) {
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
     * Verify offline authentication implementation.
     *
     * @param activationId                Activation ID.
     * @param authenticationCodeType      Authentication code type to use for authentication code verification.
     * @param authenticationCode          Authentication code.
     * @param authenticationVersion       Authentication version.
     * @param additionalInfo              Additional information related to authentication verification.
     * @param dataString                  Authentication data.
     * @param applicationKey              Application key.
     * @param pendingCommitStateAllowed   Whether authentication is allowed in PENDING_COMMIT state.
     * @return Verify offline authentication response.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws InvalidKeyException     In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws GenericCryptoException  In case of a cryptography error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private VerifyAuthenticationResponse verifyAuthenticationImpl(String activationId, AuthenticationCodeType authenticationCodeType, String authenticationCode, String authenticationVersion, List<KeyValue> additionalInfo,
                                                                  String dataString, String applicationKey, boolean pendingCommitStateAllowed)
            throws InvalidKeySpecException, InvalidKeyException, GenericServiceException, GenericCryptoException, CryptoProviderException {
        // Prepare current timestamp in advance
        final Date currentTimestamp = new Date();

        // Fetch related activation
        final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationForUpdate(activationId);
        if (activationOptional.isEmpty()) {
            return invalidStateResponse(activationId, ActivationStatus.REMOVED);
        }
        final ActivationRecordEntity activation = activationOptional.get();

        // Expire temporary block before any further evaluation - effect of unblocking is immediate when the activation is used
        activationBlockService.expireTemporaryBlockIfRequired(activation, currentTimestamp);

        final Long applicationId = activation.getApplication().getRid();

        // Convert authentication version to expected authentication format.
        final PowerAuthAuthenticationCodeFormat authCodeFormat = PowerAuthAuthenticationCodeFormat.getFormatForVersion(authenticationVersion);
        final AuthenticationCodeConfiguration authCodeConfig = AuthenticationCodeConfiguration.forFormat(authCodeFormat);

        // Check the activation - application relationship and version support
        final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);

        if (applicationVersion == null || !applicationVersion.getSupported() || !Objects.equals(applicationVersion.getApplication().getRid(), applicationId)) {
            logger.warn("Application version is incorrect, application key: {}", applicationKey);
            // Get the data and append application KEY in this case, just for auditing reasons
            final byte[] data = (dataString + "&" + applicationKey).getBytes(StandardCharsets.UTF_8);
            final AuthenticationData authenticationData = new AuthenticationData(data, authenticationCode, authCodeConfig, authenticationVersion, additionalInfo);
            final OnlineAuthenticationRequest authenticationRequest = new OnlineAuthenticationRequest(authenticationData, authenticationCodeType);
            authenticationSharedServiceBehavior.handleInvalidApplicationVersion(activation, authenticationRequest, currentTimestamp);

            // return the data
            return invalidStateResponse(activationId, activation.getActivationStatus());
        }

        final byte[] data = (dataString + "&" + applicationVersion.getApplicationSecret()).getBytes(StandardCharsets.UTF_8);
        final AuthenticationData authenticationData = new AuthenticationData(data, authenticationCode, authCodeConfig, authenticationVersion, additionalInfo);
        final OnlineAuthenticationRequest authenticationRequest = new OnlineAuthenticationRequest(authenticationData, authenticationCodeType);

        boolean verificationInPendingConfirmationState = activation.getActivationStatus() == ActivationStatus.PENDING_COMMIT
                && pendingCommitStateAllowed
                && activation.isConfirmationPending();

        if (activation.getActivationStatus() == ActivationStatus.ACTIVE || verificationInPendingConfirmationState) {

            // Double-check that there are at least some remaining attempts
            if (activation.getFailedAttempts() >= activation.getMaxFailedAttempts()) { // ... otherwise, the activation should be already blocked
                authenticationSharedServiceBehavior.handleInactiveActivationWithMismatchAuthentication(activation, authenticationRequest, currentTimestamp);
                return invalidStateResponse(activationId, activation.getActivationStatus());
            }

            final AuthenticationResponse verificationResponse = authenticationSharedServiceBehavior.verifyAuthentication(activation, authenticationRequest);

            // Check if the authentication is valid
            if (verificationResponse.isAuthenticationValid()) {

                authenticationSharedServiceBehavior.handleValidAuthentication(activation, verificationResponse, authenticationRequest, currentTimestamp);

                return validAuthenticationResponse(activation, verificationResponse.getUsedAuthenticationCodeType());

            } else {

                authenticationSharedServiceBehavior.handleInvalidAuthentication(activation, verificationResponse, authenticationRequest, currentTimestamp);

                return invalidAuthenticationResponse(activation, authenticationRequest);

            }
        } else {

            authenticationSharedServiceBehavior.handleInactiveActivationAuthentication(activation, authenticationRequest, currentTimestamp);

            // return the data
            return invalidStateResponse(activationId, activation.getActivationStatus());

        }

    }

    /**
     * Generates an invalid authentication response when state is invalid (invalid applicationVersion, activation is not active, activation does not exist, etc.).
     * @param activationId Activation ID.
     * @param activationStatus Activation status.
     * @return Invalid authentication response.
     */
    private VerifyAuthenticationResponse invalidStateResponse(String activationId, ActivationStatus activationStatus) {
        final VerifyAuthenticationResponse response = new VerifyAuthenticationResponse();
        response.setActivationId(activationId);
        response.setAuthenticationValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activationStatus));
        return response;
    }

    /**
     * Generates a valid authentication response when authentication validation succeeded.
     * @param activation Activation ID.
     * @param usedAuthenticationCodeType Authentication code type which was used during validation of the authentication.
     * @return Valid authentication response.
     */
    private VerifyAuthenticationResponse validAuthenticationResponse(ActivationRecordEntity activation, AuthenticationCodeType usedAuthenticationCodeType) {
        // Extract application ID and application roles
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifyAuthenticationResponse response = new VerifyAuthenticationResponse();
        response.setAuthenticationValid(true);
        response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.ACTIVE));
        response.setBlockedReason(null);
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
        response.getActivationFlags().addAll(activationFlags);
        response.setAuthenticationCodeType(usedAuthenticationCodeType);
        return response;
    }

    /**
     * Generates an invalid authentication response when authentication code validation failed.
     * @param activation Activation ID.
     * @param onlineAuthenticationRequest Authentication request.
     * @return Invalid authentication response.
     */
    private VerifyAuthenticationResponse invalidAuthenticationResponse(ActivationRecordEntity activation, OnlineAuthenticationRequest onlineAuthenticationRequest) {
        // Calculate remaining attempts
        final long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        // Extract application ID and application roles
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // return the data
        final VerifyAuthenticationResponse response = new VerifyAuthenticationResponse();
        response.setAuthenticationValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        response.setBlockedReason(activation.getBlockedReason());
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
        response.getActivationFlags().addAll(activationFlags);
        // In case multiple authentication code types are used, use the first one as authentication code type
        response.setAuthenticationCodeType(onlineAuthenticationRequest.getAuthenticationCodeType());
        return response;
    }

}
