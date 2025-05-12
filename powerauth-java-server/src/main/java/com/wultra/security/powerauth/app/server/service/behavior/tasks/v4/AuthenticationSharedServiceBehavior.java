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

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.AuthenticationCodeTypeConverter;
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationData;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.OfflineAuthenticationRequest;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.OnlineAuthenticationRequest;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationResponse;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AuthenticationCodeUtils;
import com.wultra.security.powerauth.crypto.lib.v4.authentication.AuthenticationKeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Service behaviour with shared methods for both online and offline authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationSharedServiceBehavior {

    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final AuditingServiceBehavior auditingServiceBehavior;
    private final CallbackUrlBehavior callbackUrlBehavior;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationContextValidator activationValidator;
    private final ActivationRepository activationRepository;

    private final AuthenticationKeyFactory authenticationKeyFactory = new AuthenticationKeyFactory();
    private final AuthenticationCodeUtils authenticationCodeUtils = new AuthenticationCodeUtils();
    private final AuthenticationCodeTypeConverter authenticationCodeTypeConverter = new AuthenticationCodeTypeConverter();
    private final CryptographyServiceFactory cryptographyServiceFactory;

    /**
     * Verify online authentication.
     * @param activation Activation used for authentication code verification.
     * @param authenticationRequest Online authentication code verification request.
     * @return Authentication code verification response.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider initialization fails.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    public AuthenticationResponse verifyAuthentication(ActivationRecordEntity activation, OnlineAuthenticationRequest authenticationRequest) throws InvalidKeyException, GenericServiceException, CryptoProviderException, GenericCryptoException {
        final List<AuthenticationCodeType> authenticationCodeTypes = Collections.singletonList(authenticationRequest.getAuthenticationCodeType());
        return verifyAuthenticationImpl(activation, authenticationRequest.getAuthenticationData(), authenticationCodeTypes);
    }

    /**
     * Verify offline authentication.
     * @param activation Activation used for authentication verification.
     * @param authenticationRequest Offline authentication verification request.
     * @return Authentication verification response.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider initialization fails.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    public AuthenticationResponse verifyAuthentication(ActivationRecordEntity activation, OfflineAuthenticationRequest authenticationRequest) throws InvalidKeyException, GenericServiceException, CryptoProviderException, GenericCryptoException {
        return verifyAuthenticationImpl(activation, authenticationRequest.getAuthenticationData(), authenticationRequest.getAuthenticationCodeTypes());
    }

    /**
     * Handle invalid application version for online authentication.
     * @param activation Activation used for authentication verification.
     * @param authenticationRequest Online authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleInvalidApplicationVersion(ActivationRecordEntity activation, OnlineAuthenticationRequest authenticationRequest, Date currentTimestamp) {
        handleInvalidApplicationVersionImpl(activation, authenticationRequest.getAuthenticationData(), authenticationRequest.getAuthenticationCodeType(), currentTimestamp);
    }

    /**
     * Handle valid authentication verification event for online authentication.
     * @param activation Activation used for authentication code verification.
     * @param verificationResponse Authentication verification response.
     * @param onlineAuthenticationRequest Online authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleValidAuthentication(ActivationRecordEntity activation, AuthenticationResponse verificationResponse, OnlineAuthenticationRequest onlineAuthenticationRequest, Date currentTimestamp) {
        handleValidAuthenticationImpl(activation, verificationResponse, onlineAuthenticationRequest.getAuthenticationData(), currentTimestamp);
    }

    /**
     * Handle valid authentication verification event for offline authentication.
     * @param activation Activation used for authentication verification.
     * @param verificationResponse Authentication verification response.
     * @param offlineAuthenticationRequest Offline authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleValidAuthentication(ActivationRecordEntity activation, AuthenticationResponse verificationResponse, OfflineAuthenticationRequest offlineAuthenticationRequest, Date currentTimestamp) {
        handleValidAuthenticationImpl(activation, verificationResponse, offlineAuthenticationRequest.getAuthenticationData(), currentTimestamp);
    }

    /**
     * Handle invalid authentication verification event for online authentication.
     * @param activation Activation used for authentication verification.
     * @param verificationResponse Authentication verification response.
     * @param authenticationRequest Online authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleInvalidAuthentication(ActivationRecordEntity activation, AuthenticationResponse verificationResponse, OnlineAuthenticationRequest authenticationRequest, Date currentTimestamp) {
        handleInvalidAuthenticationImpl(activation, verificationResponse, authenticationRequest.getAuthenticationData(), authenticationRequest.getAuthenticationCodeType(), currentTimestamp, false);
    }

    /**
     * Handle invalid authentication verification event for offline authentication.
     * @param activation Activation used for authentication verification.
     * @param verificationResponse Authentication verification response.
     * @param authenticationRequest Offline authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleInvalidAuthentication(ActivationRecordEntity activation, AuthenticationResponse verificationResponse, OfflineAuthenticationRequest authenticationRequest, Date currentTimestamp) {
        final AuthenticationCodeType authenticationCodeTypeType = authenticationRequest.getAuthenticationCodeTypes().iterator().next();
        final boolean biometryAllowedInOfflineMode = authenticationRequest.getAuthenticationCodeTypes().size() > 1 && authenticationRequest.getAuthenticationCodeTypes().contains(AuthenticationCodeType.POSSESSION_BIOMETRY);
        handleInvalidAuthenticationImpl(activation, verificationResponse, authenticationRequest.getAuthenticationData(), authenticationCodeTypeType, currentTimestamp, biometryAllowedInOfflineMode);
    }

    /**
     * Handle online authentication verification for an inactive activation.
     * @param activation Activation used for authentication verification.
     * @param authenticationRequest Online authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleInactiveActivationAuthentication(ActivationRecordEntity activation, OnlineAuthenticationRequest authenticationRequest, Date currentTimestamp) {
        handleInactiveActivationAuthenticationImpl(activation, authenticationRequest.getAuthenticationData(), authenticationRequest.getAuthenticationCodeType(), currentTimestamp);
    }

    /**
     * Handle online authentication verification for an inactive activation with a mismatch between status and counter.
     * @param activation Activation used for authentication verification.
     * @param authenticationRequest Online authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleInactiveActivationWithMismatchAuthentication(ActivationRecordEntity activation, OnlineAuthenticationRequest authenticationRequest, Date currentTimestamp) {
        handleInactiveActivationWithMismatchAuthenticationImpl(activation, authenticationRequest.getAuthenticationData(), authenticationRequest.getAuthenticationCodeType(), currentTimestamp);
    }

    /**
     * Handle offline authentication verification for an inactive activation.
     * @param activation Activation used for authentication verification.
     * @param authenticationRequest Offline authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleInactiveActivationAuthentication(ActivationRecordEntity activation, OfflineAuthenticationRequest authenticationRequest, Date currentTimestamp) {
        final AuthenticationCodeType authenticationCodeType = authenticationRequest.getAuthenticationCodeTypes().iterator().next();
        handleInactiveActivationAuthenticationImpl(activation, authenticationRequest.getAuthenticationData(), authenticationCodeType, currentTimestamp);
    }

    /**
     * Handle offline authentication verification for an inactive activation with a mismatch between status and counter.
     * @param activation Activation used for authentication verification.
     * @param authenticationRequest Offline authentication verification request.
     * @param currentTimestamp Authentication verification timestamp.
     */
    public void handleInactiveActivationWithMismatchAuthentication(ActivationRecordEntity activation, OfflineAuthenticationRequest authenticationRequest, Date currentTimestamp) {
        final AuthenticationCodeType authenticationType = authenticationRequest.getAuthenticationCodeTypes().iterator().next();
        handleInactiveActivationWithMismatchAuthenticationImpl(activation, authenticationRequest.getAuthenticationData(), authenticationType, currentTimestamp);
    }

    /**
     * Implementation of authentication verification for both online and offline authentication.
     * @param activation Activation used for authentication verification.
     * @param authenticationData Data related to the authentication.
     * @param authenticationCodeTypes Authentication code types to try to use for authentication verification. List with one authentication code type is used for online authentication. List with multiple authentication code types is used for offline authentication.
     * @return Authentication verification response.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    private AuthenticationResponse verifyAuthenticationImpl(ActivationRecordEntity activation, AuthenticationData authenticationData, List<AuthenticationCodeType> authenticationCodeTypes) throws InvalidKeyException, GenericServiceException, CryptoProviderException, GenericCryptoException {
        activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

        final SecretKey masterSecretKey = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P384).deriveSharedSecretKey(activation);

        // Resolve authentication version based on activation version and request
        final Integer authenticationVersion = resolveAuthenticationVersion(activation, authenticationData.getForcedAuthenticationVersion());

        // Verify the authentication code with given lookahead
        boolean authenticationValid = false;
        // Current numeric counter value
        long ctr = activation.getCounter();
        // Next numeric counter value used in case authentication is valid
        long ctrNext = ctr;
        // Current hash based counter value
        byte[] ctrData = null;
        // Hash of current counter data (incremented value)
        byte[] ctrHash = null;
        // Next hash based counter value used in case authentication is valid
        byte[] ctrDataNext = null;
        final HashBasedCounter hashBasedCounter = new HashBasedCounter(ProtocolVersion.V40.getVersion());
        // Get counter data from activation
        ctrHash = Base64.getDecoder().decode(activation.getCtrDataBase64());
        // Authentication code type which was used to verify authentication code successfully
        AuthenticationCodeType usedAuthenticationCodeType = null;

        counterLoop:
        for (long iteratedCounter = ctr; iteratedCounter < ctr + powerAuthServiceConfiguration.getAuthenticationCodeValidationLookahead(); iteratedCounter++) {
            // Set ctrData for current iteration
            ctrData = ctrHash;
            // Increment the hash based counter
            ctrHash = hashBasedCounter.next(ctrHash);

            // Check all authentication code types for each counter value in case there are multiple authentication code types
            for (AuthenticationCodeType authenticationCodeType : authenticationCodeTypes) {
                // Get the authentication keys according to the authentication code type
                final PowerAuthCodeType powerAuthCodeType = authenticationCodeTypeConverter.convertFrom(authenticationCodeType);
                final List<SecretKey> authenticationKeys = authenticationKeyFactory.keysForAuthenticationCodeType(powerAuthCodeType, masterSecretKey);

                authenticationValid = authenticationCodeUtils.validateAuthCode(authenticationData.getData(), authenticationData.getAuthenticationCode(), authenticationKeys, ctrData, authenticationData.getAuthCodeConfiguration());
                if (authenticationValid) {
                    // Set the next valid value of numeric counter based on current iteration counter +1
                    ctrNext = iteratedCounter + 1;
                    // Set the next valid value of hash based counter (ctrHash is already incremented by +1)
                    ctrDataNext = ctrHash;
                    // Store authentication code type which was used to verify authentication code successfully
                    usedAuthenticationCodeType = authenticationCodeType;
                    break counterLoop;
                }
            }
        }
        if (usedAuthenticationCodeType == null) {
            // In case multiple authentication code types are used, use the first one as authentication code type
            usedAuthenticationCodeType = authenticationCodeTypes.iterator().next();
        }
        return new AuthenticationResponse(authenticationValid, ctrNext, ctrDataNext, authenticationVersion, usedAuthenticationCodeType);
    }

    /**
     * Implementation of handle invalid application version.
     * @param activation Activation used for authentication verification.
     * @param authenticationData Data related to the authentication.
     * @param authenticationCodeType Authentication code type used for authentication verification.
     * @param currentTimestamp Authentication verification timestamp.
     */
    private void handleInvalidApplicationVersionImpl(ActivationRecordEntity activation, AuthenticationData authenticationData, AuthenticationCodeType authenticationCodeType, Date currentTimestamp) {
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        // By default do not notify listeners
        boolean notifyCallbackListeners = false;

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Update failed attempts and block the activation, if necessary
        if (notPossessionFactorAuthentication(authenticationCodeType)) {
            activation.setFailedAttempts(activation.getFailedAttempts() + 1);
            final long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
            if (remainingAttempts <= 0) {
                activation.setActivationStatus(ActivationStatus.BLOCKED);
                activation.setBlockedReason(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
                // Save the activation and log change
                activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
                final KeyValue entry = new KeyValue();
                entry.setKey(AdditionalInformation.Key.BLOCKED_REASON);
                entry.setValue(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
                authenticationData.getAdditionalInfo().add(entry);
                // notify callback listeners
                notifyCallbackListeners = true;
            } else {
                // Save the activation
                activationRepository.save(activation);
            }
        } else {
            // Save the activation
            activationRepository.save(activation);
        }

        // Create the audit log record
        auditingServiceBehavior.logAuthenticationAuditRecord(activationDto, authenticationData, authenticationCodeType, false, activation.getVersion(),
                "activation_invalid_application", currentTimestamp);

        // Notify callback listeners, if needed
        if (notifyCallbackListeners) {
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        }
    }

    /**
     * Implementation of handle valid authentication.
     * @param activation Activation used for authentication verification.
     * @param verificationResponse Authentication verification response.
     * @param authenticationData Data related to the authentication.
     * @param currentTimestamp Authentication verification timestamp.
     */
    private void handleValidAuthenticationImpl(ActivationRecordEntity activation, AuthenticationResponse verificationResponse, AuthenticationData authenticationData, Date currentTimestamp) {
        // Keep unchanged values of ctrDataBase64 and counter before calculating next ones.
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        if (verificationResponse.getForcedAuthenticationVersion() == 4) {
            // Set the ctrData to next valid ctrData value
            activation.setCtrDataBase64(Base64.getEncoder().encodeToString(verificationResponse.getCtrDataNext()));
        }

        // Set the activation record counter to next valid counter value
        activation.setCounter(verificationResponse.getCtrNext());

        // Reset failed attempt count
        if (notPossessionFactorAuthentication(verificationResponse.getUsedAuthenticationCodeType())) {
            activation.setFailedAttempts(0L);
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record with activation values of ctrDataBase64 and counter before calculating next ones.
        auditingServiceBehavior.logAuthenticationAuditRecord(activationDto, authenticationData, verificationResponse.getUsedAuthenticationCodeType(), true, verificationResponse.getForcedAuthenticationVersion(), "authentication_ok", currentTimestamp);
    }

    /**
     * Implementation of handle invalid authentication.
     * @param activation Activation used for authentication verification.
     * @param verificationResponse Authentication verification response.
     * @param authenticationData Data related to the authentication.
     * @param currentTimestamp Authentication verification timestamp.
     */
    private void handleInvalidAuthenticationImpl(ActivationRecordEntity activation, AuthenticationResponse verificationResponse, AuthenticationData authenticationData, AuthenticationCodeType authenticationCodeType,
                                                 Date currentTimestamp, boolean biometryAllowedInOfflineMode) {
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        // By default do not notify listeners
        boolean notifyCallbackListeners = false;

        // Update failed attempts and block the activation, if necessary
        if (notPossessionFactorAuthentication(verificationResponse.getUsedAuthenticationCodeType())) {
            activation.setFailedAttempts(activation.getFailedAttempts() + 1);
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Add information whether POSSESSION_BIOMETRY authentication code type was used into additional info.
        // This is useful when multiple authentication code types are used for authentication code verification in offline mode
        // and it is unclear which authentication code type was used to generate the authentication code because the authentication code
        // verification failed.
        if (biometryAllowedInOfflineMode) {
            final KeyValue entryBiometry = new KeyValue();
            entryBiometry.setKey(AdditionalInformation.Key.BIOMETRY_ALLOWED);
            entryBiometry.setValue("TRUE");
            authenticationData.getAdditionalInfo().add(entryBiometry);
        }

        long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        if (remainingAttempts <= 0) {
            activation.setActivationStatus(ActivationStatus.BLOCKED);
            activation.setBlockedReason(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
            // Save the activation and log change
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            final KeyValue entry = new KeyValue();
            entry.setKey(AdditionalInformation.Key.BLOCKED_REASON);
            entry.setValue(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
            authenticationData.getAdditionalInfo().add(entry);
            // notify callback listeners
            notifyCallbackListeners = true;
        } else {
            // Save the activation
            activationRepository.save(activation);
        }

        // Create the audit log record.
        auditingServiceBehavior.logAuthenticationAuditRecord(activationDto, authenticationData, authenticationCodeType,false,
                verificationResponse.getForcedAuthenticationVersion(), "authentication_code_does_not_match", currentTimestamp);

        // Notify callback listeners, if needed
        if (notifyCallbackListeners) {
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        }
    }

    /**
     * Implementation of handle inactive activation during authentication code verification.
     * @param activation Activation used for authentication code verification.
     * @param authenticationData Data related to the authentication.
     * @param authenticationCodeType Used authentication code type.
     * @param currentTimestamp Authentication verification timestamp.
     */
    private void handleInactiveActivationAuthenticationImpl(ActivationRecordEntity activation, AuthenticationData authenticationData, AuthenticationCodeType authenticationCodeType, Date currentTimestamp) {
        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);
        auditingServiceBehavior.logAuthenticationAuditRecord(activationDto, authenticationData, authenticationCodeType, false,
                activation.getVersion(), "activation_invalid_state", currentTimestamp);
    }

    /**
     * Implementation of handle inactive activation with mismatch in counter and activation status during authentication code verification.
     * @param activation Activation used for authentication code verification.
     * @param authenticationData Data related to the authentication code.
     * @param authenticationCodeType Used authentication code type.
     * @param currentTimestamp Authentication code verification timestamp.
     */
    private void handleInactiveActivationWithMismatchAuthenticationImpl(ActivationRecordEntity activation, AuthenticationData authenticationData, AuthenticationCodeType authenticationCodeType, Date currentTimestamp) {
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Enforce the blocked status on activation
        activation.setActivationStatus(ActivationStatus.BLOCKED);
        activation.setBlockedReason(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);

        // Save the activation and log change
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation);

        // Prepare data for the authentication audit log
        final KeyValue entry = new KeyValue();
        entry.setKey(AdditionalInformation.Key.BLOCKED_REASON);
        entry.setValue(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
        authenticationData.getAdditionalInfo().add(entry);

        // Create the audit log record
        auditingServiceBehavior.logAuthenticationAuditRecord(activationDto, authenticationData, authenticationCodeType, false,
                activation.getVersion(), "activation_invalid_state_ctr_mismatch", currentTimestamp);

        // Notify callback listeners
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
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

    /**
     * Get whether authentication code type is not possession factor.
     * @param authenticationCodeType Authentication code type.
     * @return Whether authentication code type is not possession factor.
     */
    private boolean notPossessionFactorAuthentication(AuthenticationCodeType authenticationCodeType) {
        return authenticationCodeType != null && !authenticationCodeType.equals(AuthenticationCodeType.POSSESSION);
    }

    /**
     * Resolve authentication version based on activation version and forced authentication version from request.
     * @param activation Activation entity.
     * @param forcedAuthenticationVersion Forced authentication version from request.
     * @return Resolved authentication version.
     * @throws GenericServiceException Thrown in case activation state is invalid.
     */
    private Integer resolveAuthenticationVersion(ActivationRecordEntity activation, Integer forcedAuthenticationVersion) throws GenericServiceException {
        // Validate activation version
        activationValidator.validateVersionValid(activation.getVersion(), localizationProvider);

        // Set authentication version based on activation version as default
        Integer authenticationVersion = activation.getVersion();

        // Handle upgrade from version 3 to version 4, the version is forced during upgrade commit
        if (forcedAuthenticationVersion != null && forcedAuthenticationVersion == 4 && activation.getVersion() == 3) {
            // Version 4 is forced by client during upgrade from version 3, ctr_data already exists -> switch authentication to version 4
            authenticationVersion = 4;
        }
        return authenticationVersion;
    }
    
}
