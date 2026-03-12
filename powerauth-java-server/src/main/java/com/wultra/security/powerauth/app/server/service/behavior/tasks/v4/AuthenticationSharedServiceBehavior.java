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
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationHistoryServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationData;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationResponse;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.OfflineAuthenticationRequest;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.OnlineAuthenticationRequest;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.authentication.AuthenticationKeyFactory;
import com.wultra.security.powerauth.crypto.server.v4.authentication.PowerAuthServerAuthentication;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
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
    private final CryptographyServiceFactory cryptographyServiceFactory;

    private static final PowerAuthServerAuthentication SERVER_AUTH = new PowerAuthServerAuthentication();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Verify online authentication.
     * @param activation Activation used for authentication code verification.
     * @param authenticationRequest Online authentication code verification request.
     * @return Authentication code verification response.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider initialization fails.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    public AuthenticationResponse verifyAuthentication(ActivationRecordEntity activation, OnlineAuthenticationRequest authenticationRequest) throws GenericServiceException, CryptoProviderException, GenericCryptoException {
        final List<AuthenticationCodeType> authenticationCodeTypes = Collections.singletonList(authenticationRequest.getAuthenticationCodeType());
        return verifyAuthenticationImpl(activation, authenticationRequest.getAuthenticationData(), authenticationCodeTypes);
    }

    /**
     * Verify offline authentication.
     * @param activation Activation used for authentication verification.
     * @param authenticationRequest Offline authentication verification request.
     * @return Authentication verification response.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider initialization fails.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    public AuthenticationResponse verifyAuthentication(ActivationRecordEntity activation, OfflineAuthenticationRequest authenticationRequest) throws GenericServiceException, CryptoProviderException, GenericCryptoException {
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
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    private AuthenticationResponse verifyAuthenticationImpl(ActivationRecordEntity activation, AuthenticationData authenticationData, List<AuthenticationCodeType> authenticationCodeTypes) throws GenericServiceException, CryptoProviderException, GenericCryptoException {
        activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);
        final SecretKey keyActivationSecret = cryptographyServiceFactory.getService(activation.getCryptoAlgorithm()).deriveSharedSecretKey(activation);

        final long ctr = activation.getCounter();
        final byte[] ctrHash = Base64.getDecoder().decode(activation.getCtrDataV4Base64());

        final AuthenticationResult result = authenticate(activation, authenticationData, authenticationCodeTypes, keyActivationSecret, ctr, ctrHash);
        final AuthenticationCodeType usedAuthenticationCodeType = result.authenticated() ? result.usedAuthenticationCodeType() : authenticationCodeTypes.iterator().next();
        return new AuthenticationResponse(result.authenticated(),
                result.nextCounter(),
                result.nextCtrData(),
                usedAuthenticationCodeType
        );
    }

    /**
     * Performa authentication for an activation with given authentication data and authentication code types.
     * @param activation Activation used for authentication verification.
     * @param authenticationData Data related to the authentication.
     * @param authenticationCodeTypes Authentication code types to try to use for authentication verification. List with one authentication code type is used for online authentication. List with multiple authentication code types is used for offline authentication.
     * @param keyActivationSecret Activation secret key.
     * @param ctr Current counter value.
     * @param initialCtrHash Initial hashed-based counter value.
     * @return Authentication result.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    private AuthenticationResult authenticate(ActivationRecordEntity activation, AuthenticationData authenticationData,
                                              List<AuthenticationCodeType> authenticationCodeTypes, SecretKey keyActivationSecret, long ctr,
                                              byte[] initialCtrHash) throws GenericServiceException, GenericCryptoException, CryptoProviderException {
        byte[] ctrHash = initialCtrHash;
        byte[] ctrData;
        final long ctrNext;
        final byte[] ctrDataNext;
        final HashBasedCounter hashBasedCounter = new HashBasedCounter(ProtocolVersion.V40.getVersion());

        for (long iteratedCounter = ctr; iteratedCounter < ctr + powerAuthServiceConfiguration.getAuthenticationCodeValidationLookahead(); iteratedCounter++) {
            ctrData = ctrHash;
            ctrHash = hashBasedCounter.next(ctrHash);

            for (AuthenticationCodeType codeType : authenticationCodeTypes) {
                checkBiometryAvailable(codeType, activation);
                for (FactorKeys factorKeys : getAllFactorKeyCombinations(codeType, activation, keyActivationSecret)) {
                    List<SecretKey> keys = factorKeys.toSecretKeyList();
                    if (SERVER_AUTH.validateAuthCode(authenticationData.getData(), authenticationData.getAuthenticationCode(), keys, ctrData, authenticationData.getAuthCodeConfiguration())) {
                        updateDynamicFactorKeys(factorKeys, activation, codeType);
                        ctrNext = iteratedCounter + 1;
                        ctrDataNext = ctrHash;
                        return new AuthenticationResult(true, ctrNext, ctrDataNext, codeType);
                    }
                }
            }
        }
        return new AuthenticationResult(false, null, null, null);
    }

    /**
     * Check whether biometry check is available for an activation.
     * @param codeType Authentication code type.
     * @param activation Activation record.
     * @throws GenericServiceException In case biometry is not set up yet.
     */
    private void checkBiometryAvailable(AuthenticationCodeType codeType, ActivationRecordEntity activation) throws GenericServiceException {
        if (hasBiometryComponent(codeType) && !activation.isBiometricFactorEnabled()) {
            logger.info("Invalid authentication attempt skipped, biometry is not set up yet, authentication code type: {}", codeType);
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_AUTHENTICATION_CODE);
        }
    }

    /**
     * Record containing an authentication result.
     * @param authenticated Whether authentication succeeded.
     * @param nextCounter Next value of numeric counter.
     * @param nextCtrData Next value of hash-based counter.
     * @param usedAuthenticationCodeType Authentication code type used for the authentication.
     */
    private record AuthenticationResult(
            boolean authenticated,
            Long nextCounter,
            byte[] nextCtrData,
            AuthenticationCodeType usedAuthenticationCodeType
    ) {}

    /**
     * Update dynamic factor keys on successful authentication.
     * @param factorKeys Factor keys used.
     * @param activation Activation entity.
     * @param codeType Activation code type.
     */
    private void updateDynamicFactorKeys(FactorKeys factorKeys, ActivationRecordEntity activation, AuthenticationCodeType codeType) {
        if (factorKeys.knowledgeUsedNext) {
            activation.setKnowledgeFactorKey(activation.getKnowledgeFactorKeyNext());
            activation.setKnowledgeFactorKeyNext(null);
        }
        if (factorKeys.biometryUsedNext) {
            activation.setBiometricFactorKey(activation.getBiometricFactorKeyNext());
            activation.setBiometricFactorKeyNext(null);
        }
        if (!factorKeys.knowledgeUsedNext && hasKnowledgeComponent(codeType)) {
            activation.setKnowledgeFactorKeyNext(null);
        }
        if (!factorKeys.biometryUsedNext && hasBiometryComponent(codeType)) {
            activation.setBiometricFactorKeyNext(null);
        }
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
                logger.info("action: handleInvalidApplicationVersion, state: blocked, activationId: {}, reason: max failed attempts reached", activation.getActivationId());
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

        // Set the activation numeric counter to next valid counter value
        activation.setCounter(verificationResponse.getCtrNext());

        // Set the activation counter data for V4 to next counter data value
        activation.setCtrDataV4Base64(Base64.getEncoder().encodeToString(verificationResponse.getCtrDataNext()));

        // Reset failed attempt count
        if (notPossessionFactorAuthentication(verificationResponse.getUsedAuthenticationCodeType())) {
            activation.setFailedAttempts(0L);
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record with activation values of ctrDataBase64 and counter before calculating next ones.
        auditingServiceBehavior.logAuthenticationAuditRecord(activationDto, authenticationData, verificationResponse.getUsedAuthenticationCodeType(), true, activation.getVersion(), "authentication_ok", currentTimestamp);
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
            logger.info("action: handleInvalidAuthentication, state: blocked, activationId: {}, reason: max failed attempts reached", activation.getActivationId());
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
                activation.getVersion(), "authentication_code_does_not_match", currentTimestamp);

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
        logger.info("action: handleInactiveActivationWithMismatchAuthentication, state: blocked, activationId: {}, reason: max failed attempts reached", activation.getActivationId());
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
                .ctrDataBase64(activation.getCtrDataV4Base64())
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
     * Get whether the authentication code type has a knowledge component.
     * @param codeType Authentication code type.
     * @return Knowledge component present.
     */
    private boolean hasKnowledgeComponent(AuthenticationCodeType codeType) {
        return codeType == AuthenticationCodeType.KNOWLEDGE ||
                codeType == AuthenticationCodeType.POSSESSION_KNOWLEDGE ||
                codeType == AuthenticationCodeType.POSSESSION_KNOWLEDGE_BIOMETRY;
    }

    /**
     * Get whether the authentication code type has a biometry component.
     * @param codeType Authentication code type.
     * @return Biometry component present.
     */
    private boolean hasBiometryComponent(AuthenticationCodeType codeType) {
        return codeType == AuthenticationCodeType.BIOMETRY ||
                codeType == AuthenticationCodeType.POSSESSION_BIOMETRY ||
                codeType == AuthenticationCodeType.POSSESSION_KNOWLEDGE_BIOMETRY;
    }

    /**
     * Get all factor key combinations.
     * @param codeType Authentication code type.
     * @param activation Activation entity.
     * @param keyActivationSecret Activation secret key.
     * @return List of all factor key combinations.
     * @throws GenericCryptoException In case key conversion fails.
     */
    private List<FactorKeys> getAllFactorKeyCombinations(AuthenticationCodeType codeType, ActivationRecordEntity activation, SecretKey keyActivationSecret) throws GenericCryptoException {
        final SecretKey possessionKey = authenticationKeyFactory.generatePossessionFactorKey(keyActivationSecret);

        final String knowledgeKeyCurrent = activation.getKnowledgeFactorKey();
        final String knowledgeKeyNext = activation.getKnowledgeFactorKeyNext();
        final SecretKey knowledgeSecretCurrent = KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(knowledgeKeyCurrent));
        final SecretKey knowledgeSecretNext = knowledgeKeyNext != null ? KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(knowledgeKeyNext)) : null;

        final boolean biometryEnabled = activation.isBiometricFactorEnabled();
        final String biometryKeyCurrent = biometryEnabled ? activation.getBiometricFactorKey() : null;
        final String biometryKeyNext = biometryEnabled ? activation.getBiometricFactorKeyNext() : null;
        final SecretKey biometrySecretCurrent = biometryKeyCurrent != null ? KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(biometryKeyCurrent)) : null;
        final SecretKey biometrySecretNext = biometryKeyNext != null ? KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(biometryKeyNext)) : null;

        final List<FactorKeys> result = new java.util.ArrayList<>();
        final boolean needsKnowledge = hasKnowledgeComponent(codeType);
        final boolean needsBiometry = hasBiometryComponent(codeType);

        if (!needsKnowledge && !needsBiometry) {
            result.add(FactorKeys.builder()
                    .possessionKey(possessionKey)
                    .build());
        } else if (needsKnowledge && !needsBiometry) {
            if (knowledgeSecretCurrent != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .knowledgeKey(knowledgeSecretCurrent)
                        .knowledgeUsedNext(false)
                        .build());
            if (knowledgeSecretNext != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .knowledgeKey(knowledgeSecretNext)
                        .knowledgeUsedNext(true)
                        .build());
        } else if (!needsKnowledge) {
            if (biometrySecretCurrent != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .biometryKey(biometrySecretCurrent)
                        .biometryUsedNext(false)
                        .build());
            if (biometrySecretNext != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .biometryKey(biometrySecretNext)
                        .biometryUsedNext(true)
                        .build());
        } else {
            if (knowledgeSecretCurrent != null && biometrySecretCurrent != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .knowledgeKey(knowledgeSecretCurrent)
                        .knowledgeUsedNext(false)
                        .biometryKey(biometrySecretCurrent)
                        .biometryUsedNext(false)
                        .build());
            if (knowledgeSecretCurrent != null && biometrySecretNext != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .knowledgeKey(knowledgeSecretCurrent)
                        .knowledgeUsedNext(false)
                        .biometryKey(biometrySecretNext)
                        .biometryUsedNext(true)
                        .build());
            if (knowledgeSecretNext != null && biometrySecretCurrent != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .knowledgeKey(knowledgeSecretNext)
                        .knowledgeUsedNext(true)
                        .biometryKey(biometrySecretCurrent)
                        .biometryUsedNext(false)
                        .build());
            if (knowledgeSecretNext != null && biometrySecretNext != null)
                result.add(FactorKeys.builder()
                        .possessionKey(possessionKey)
                        .knowledgeKey(knowledgeSecretNext)
                        .knowledgeUsedNext(true)
                        .biometryKey(biometrySecretNext)
                        .biometryUsedNext(true)
                        .build());
        }
        return result;
    }

    /**
     * Model class for dynamic factor keys.
     */
    @Getter
    @Builder
    private static class FactorKeys {
        private final SecretKey possessionKey;
        private final SecretKey knowledgeKey;
        private final boolean knowledgeUsedNext;
        private final SecretKey biometryKey;
        private final boolean biometryUsedNext;

        List<SecretKey> toSecretKeyList() {
            if (knowledgeKey != null && biometryKey != null) {
                return List.of(possessionKey, knowledgeKey, biometryKey);
            } else if (knowledgeKey != null) {
                return List.of(possessionKey, knowledgeKey);
            } else if (biometryKey != null) {
                return List.of(possessionKey, biometryKey);
            } else {
                return List.of(possessionKey);
            }
        }
    }

}
