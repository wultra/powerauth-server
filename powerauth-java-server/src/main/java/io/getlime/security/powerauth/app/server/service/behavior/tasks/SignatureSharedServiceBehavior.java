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

import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.converter.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.signature.OfflineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.OnlineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.signature.PowerAuthServerSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Service behaviour with shared methods for both online and offline signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class SignatureSharedServiceBehavior {

    private static final Logger logger = LoggerFactory.getLogger(SignatureSharedServiceBehavior.class);

    private final RepositoryCatalogue repositoryCatalogue;
    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final AuditingServiceBehavior auditingServiceBehavior;
    private final CallbackUrlBehavior callbackUrlBehavior;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationContextValidator activationValidator;

    private ServerPrivateKeyConverter serverPrivateKeyConverter;

    private final PowerAuthServerSignature powerAuthServerSignature = new PowerAuthServerSignature();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();

    /**
     * Constuctor for shared signature service behavior.
     * @param repositoryCatalogue Repository catalogue.
     * @param activationHistoryServiceBehavior Activation history service behavior.
     * @param auditingServiceBehavior Auditing service behavior.
     * @param callbackUrlBehavior Callback URL behavior.
     * @param localizationProvider Localization provider for error handling.
     * @param powerAuthServiceConfiguration PowerAuth service configuration.
     * @param activationValidator
     */
    @Autowired
    public SignatureSharedServiceBehavior(RepositoryCatalogue repositoryCatalogue, ActivationHistoryServiceBehavior activationHistoryServiceBehavior, AuditingServiceBehavior auditingServiceBehavior, CallbackUrlBehavior callbackUrlBehavior, LocalizationProvider localizationProvider, PowerAuthServiceConfiguration powerAuthServiceConfiguration, ActivationContextValidator activationValidator) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.activationHistoryServiceBehavior = activationHistoryServiceBehavior;
        this.auditingServiceBehavior = auditingServiceBehavior;
        this.callbackUrlBehavior = callbackUrlBehavior;
        this.localizationProvider = localizationProvider;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.activationValidator = activationValidator;
    }

    /**
     * Set private key converter.
     * @param serverPrivateKeyConverter Private key converter.
     */
    @Autowired
    public void setServerPrivateKeyConverter(ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    /**
     * Verify online signature.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Online signature verification request.
     * @param keyConversionUtilities Key convertor.
     * @return Signature verification response.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider initialization fails.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    public SignatureResponse verifySignature(ActivationRecordEntity activation, OnlineSignatureRequest signatureRequest, KeyConvertor keyConversionUtilities) throws InvalidKeyException, InvalidKeySpecException, GenericServiceException, CryptoProviderException, GenericCryptoException {
        final List<SignatureType> signatureTypes = Collections.singletonList(signatureRequest.getSignatureType());
        return verifySignatureImpl(activation, signatureRequest.getSignatureData(), signatureTypes, keyConversionUtilities);
    }

    /**
     * Verify offline signature.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Offline signature verification request.
     * @param keyConversionUtilities Key convertor.
     * @return Signature verification response.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider initialization fails.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    public SignatureResponse verifySignature(ActivationRecordEntity activation, OfflineSignatureRequest signatureRequest, KeyConvertor keyConversionUtilities) throws InvalidKeyException, InvalidKeySpecException, GenericServiceException, CryptoProviderException, GenericCryptoException {
        return verifySignatureImpl(activation, signatureRequest.getSignatureData(), signatureRequest.getSignatureTypes(), keyConversionUtilities);
    }

    /**
     * Handle invalid application version for online signature.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Online signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInvalidApplicationVersion(ActivationRecordEntity activation, OnlineSignatureRequest signatureRequest, Date currentTimestamp) {
        handleInvalidApplicationVersionImpl(activation, signatureRequest.getSignatureData(), signatureRequest.getSignatureType(), currentTimestamp);
    }

    /**
     * Handle invalid application version for offline signature.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Offline signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInvalidApplicationVersion(ActivationRecordEntity activation, OfflineSignatureRequest signatureRequest, Date currentTimestamp) {
        final SignatureType signatureType = signatureRequest.getSignatureTypes().iterator().next();
        handleInvalidApplicationVersionImpl(activation, signatureRequest.getSignatureData(), signatureType, currentTimestamp);
    }

    /**
     * Handle valid signature verification event for online signatures.
     * @param activation Activation used for signature verification.
     * @param verificationResponse Signature verification response.
     * @param onlineSignatureRequest Online signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleValidSignature(ActivationRecordEntity activation, SignatureResponse verificationResponse, OnlineSignatureRequest onlineSignatureRequest, Date currentTimestamp) {
        handleValidSignatureImpl(activation, verificationResponse, onlineSignatureRequest.getSignatureData(), currentTimestamp);
    }

    /**
     * Handle valid signature verification event for offline signatures.
     * @param activation Activation used for signature verification.
     * @param verificationResponse Signature verification response.
     * @param offlineSignatureRequest Offline signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleValidSignature(ActivationRecordEntity activation, SignatureResponse verificationResponse, OfflineSignatureRequest offlineSignatureRequest, Date currentTimestamp) {
        handleValidSignatureImpl(activation, verificationResponse, offlineSignatureRequest.getSignatureData(), currentTimestamp);
    }

    /**
     * Handle invalid signature verification event for online signatures.
     * @param activation Activation used for signature verification.
     * @param verificationResponse Signature verification response.
     * @param signatureRequest Online signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInvalidSignature(ActivationRecordEntity activation, SignatureResponse verificationResponse, OnlineSignatureRequest signatureRequest, Date currentTimestamp) {
        handleInvalidSignatureImpl(activation, verificationResponse, signatureRequest.getSignatureData(), signatureRequest.getSignatureType(), currentTimestamp, false);
    }

    /**
     * Handle invalid signature verification event for offline signatures.
     * @param activation Activation used for signature verification.
     * @param verificationResponse Signature verification response.
     * @param signatureRequest Offline signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInvalidSignature(ActivationRecordEntity activation, SignatureResponse verificationResponse, OfflineSignatureRequest signatureRequest, Date currentTimestamp) {
        final SignatureType signatureType = signatureRequest.getSignatureTypes().iterator().next();
        final boolean biometryAllowedInOfflineMode = signatureRequest.getSignatureTypes().size() > 1 && signatureRequest.getSignatureTypes().contains(SignatureType.POSSESSION_BIOMETRY);
        handleInvalidSignatureImpl(activation, verificationResponse, signatureRequest.getSignatureData(), signatureType, currentTimestamp, biometryAllowedInOfflineMode);
    }

    /**
     * Handle online signature verification for an inactive activation.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Online signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInactiveActivationSignature(ActivationRecordEntity activation, OnlineSignatureRequest signatureRequest, Date currentTimestamp) {
        handleInactiveActivationSignatureImpl(activation, signatureRequest.getSignatureData(), signatureRequest.getSignatureType(), currentTimestamp);
    }

    /**
     * Handle online signature verification for an inactive activation with a mismatch between status and counter.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Online signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInactiveActivationWithMismatchSignature(ActivationRecordEntity activation, OnlineSignatureRequest signatureRequest, Date currentTimestamp) {
        handleInactiveActivationWithMismatchSignatureImpl(activation, signatureRequest.getSignatureData(), signatureRequest.getSignatureType(), currentTimestamp);
    }

    /**
     * Handle offline signature verification for an inactive activation.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Offline signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInactiveActivationSignature(ActivationRecordEntity activation, OfflineSignatureRequest signatureRequest, Date currentTimestamp) {
        final SignatureType signatureType = signatureRequest.getSignatureTypes().iterator().next();
        handleInactiveActivationSignatureImpl(activation, signatureRequest.getSignatureData(), signatureType, currentTimestamp);
    }

    /**
     * Handle offline signature verification for an inactive activation with a mismatch between status and counter.
     * @param activation Activation used for signature verification.
     * @param signatureRequest Offline signature verification request.
     * @param currentTimestamp Signature verification timestamp.
     */
    public void handleInactiveActivationWithMismatchSignature(ActivationRecordEntity activation, OfflineSignatureRequest signatureRequest, Date currentTimestamp) {
        final SignatureType signatureType = signatureRequest.getSignatureTypes().iterator().next();
        handleInactiveActivationWithMismatchSignatureImpl(activation, signatureRequest.getSignatureData(), signatureType, currentTimestamp);
    }

    /**
     * Implementation of signature verification for both online and offline signatures.
     * @param activation Activation used for signature verification.
     * @param signatureData Data related to the signature.
     * @param signatureTypes Signature types to try to use for signature verification. List with one signature type is used for online signatures. List with multiple signature types is used for offline signatures.
     * @param keyConversionUtilities Key convertor.
     * @return Signature verification response.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    private SignatureResponse verifySignatureImpl(ActivationRecordEntity activation, SignatureData signatureData, List<SignatureType> signatureTypes, KeyConvertor keyConversionUtilities) throws InvalidKeyException, InvalidKeySpecException, GenericServiceException, CryptoProviderException, GenericCryptoException {
        activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

        // Get the server private and device public keys

        // Decrypt server private key (depending on encryption mode)
        final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
        final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
        final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
        final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());

        // Decode the keys to byte[]
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
        final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
        final PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
        final PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

        // Compute the master secret key
        final SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

        // Resolve signature version based on activation version and request
        final Integer signatureVersion = resolveSignatureVersion(activation, signatureData.getForcedSignatureVersion());

        // Verify the signature with given lookahead
        boolean signatureValid = false;
        // Current numeric counter value
        long ctr = activation.getCounter();
        // Next numeric counter value used in case signature is valid
        long ctrNext = ctr;
        // Current hash based counter value
        byte[] ctrData = null;
        // Hash of current counter data (incremented value)
        byte[] ctrHash = null;
        // Next hash based counter value used in case signature is valid
        byte[] ctrDataNext = null;
        final HashBasedCounter hashBasedCounter = new HashBasedCounter();
        // Get counter data from activation for version 3
        if (signatureVersion == 3) {
            ctrHash = Base64.getDecoder().decode(activation.getCtrDataBase64());
        }
        // Signature type which was used to verify signature succesfully
        SignatureType usedSignatureType = null;

        counterLoop:
        for (long iteratedCounter = ctr; iteratedCounter < ctr + powerAuthServiceConfiguration.getSignatureValidationLookahead(); iteratedCounter++) {
            switch (signatureVersion) {
                case 2 ->
                    // Use numeric counter for counter data
                        ctrData = ByteBuffer.allocate(16).putLong(8, iteratedCounter).array();
                case 3 -> {
                    // Set ctrData for current iteration
                    ctrData = ctrHash;
                    // Increment the hash based counter
                    ctrHash = hashBasedCounter.next(ctrHash);
                }
            }
            // Check all signature types for each counter value in case there are multiple signature types
            for (SignatureType signatureType : signatureTypes) {
                // Get the signature keys according to the signature type
                final PowerAuthSignatureTypes powerAuthSignatureTypes = signatureTypeConverter.convertFrom(signatureType);
                final List<SecretKey> signatureKeys = powerAuthServerKeyFactory.keysForSignatureType(powerAuthSignatureTypes, masterSecretKey);

                signatureValid = powerAuthServerSignature.verifySignatureForData(signatureData.getData(), signatureData.getSignature(), signatureKeys, ctrData, signatureData.getSignatureConfiguration());
                if (signatureValid) {
                    // Set the next valid value of numeric counter based on current iteration counter +1
                    ctrNext = iteratedCounter + 1;
                    // Set the next valid value of hash based counter (ctrHash is already incremented by +1)
                    ctrDataNext = ctrHash;
                    // Store signature type which was used to verify signature successfully
                    usedSignatureType = signatureType;
                    break counterLoop;
                }
            }
        }
        if (usedSignatureType == null) {
            // In case multiple signature types are used, use the first one as signature type
            usedSignatureType = signatureTypes.iterator().next();
        }
        return new SignatureResponse(signatureValid, ctrNext, ctrDataNext, signatureVersion, usedSignatureType);
    }

    /**
     * Implementation of handle invalid application version.
     * @param activation Activation used for signature verification.
     * @param signatureData Data related to the signature.
     * @param signatureType Signature type used for signature verification.
     * @param currentTimestamp Signature verification timestamp.
     */
    private void handleInvalidApplicationVersionImpl(ActivationRecordEntity activation, SignatureData signatureData, SignatureType signatureType, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        // By default do not notify listeners
        boolean notifyCallbackListeners = false;

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Update failed attempts and block the activation, if necessary
        if (notPossessionFactorSignature(signatureType)) {
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
                signatureData.getAdditionalInfo().add(entry);
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
        auditingServiceBehavior.logSignatureAuditRecord(activationDto, signatureData, signatureType, false, activation.getVersion(),
                "activation_invalid_application", currentTimestamp);

        // Notify callback listeners, if needed
        if (notifyCallbackListeners) {
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        }
    }

    /**
     * Implementation of handle valid signature.
     * @param activation Activation used for signature verification.
     * @param verificationResponse Signature verification response.
     * @param signatureData Data related to the signature.
     * @param currentTimestamp Signature verification timestamp.
     */
    private void handleValidSignatureImpl(ActivationRecordEntity activation, SignatureResponse verificationResponse, SignatureData signatureData, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // Keep unchanged values of ctrDataBase64 and counter before calculating next ones.
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        if (verificationResponse.getForcedSignatureVersion() == 3) {
            // Set the ctrData to next valid ctrData value
            activation.setCtrDataBase64(Base64.getEncoder().encodeToString(verificationResponse.getCtrDataNext()));
        }

        // Set the activation record counter to next valid counter value
        activation.setCounter(verificationResponse.getCtrNext());

        // Reset failed attempt count
        if (notPossessionFactorSignature(verificationResponse.getUsedSignatureType())) {
            activation.setFailedAttempts(0L);
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record with activation values of ctrDataBase64 and counter before calculating next ones.
        auditingServiceBehavior.logSignatureAuditRecord(activationDto, signatureData, verificationResponse.getUsedSignatureType(), true, verificationResponse.getForcedSignatureVersion(), "signature_ok", currentTimestamp);
    }

    /**
     * Implementation of handle invalid signature.
     * @param activation Activation used for signature verification.
     * @param verificationResponse Signature verification response.
     * @param signatureData Data related to the signature.
     * @param currentTimestamp Signature verification timestamp.
     */
    private void handleInvalidSignatureImpl(ActivationRecordEntity activation, SignatureResponse verificationResponse, SignatureData signatureData, SignatureType signatureType,
                                            Date currentTimestamp, boolean biometryAllowedInOfflineMode) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        // By default do not notify listeners
        boolean notifyCallbackListeners = false;

        // Update failed attempts and block the activation, if necessary
        if (notPossessionFactorSignature(verificationResponse.getUsedSignatureType())) {
            activation.setFailedAttempts(activation.getFailedAttempts() + 1);
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Add information whether POSSESSION_BIOMETRY signature type was used into additional info.
        // This is useful when multiple signature types are used for signature verification in offline mode
        // and it is unclear which signature type was used to generate the signature because the signature
        // verification failed.
        if (biometryAllowedInOfflineMode) {
            final KeyValue entryBiometry = new KeyValue();
            entryBiometry.setKey(AdditionalInformation.Key.BIOMETRY_ALLOWED);
            entryBiometry.setValue("TRUE");
            signatureData.getAdditionalInfo().add(entryBiometry);
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
            signatureData.getAdditionalInfo().add(entry);
            // notify callback listeners
            notifyCallbackListeners = true;
        } else {
            // Save the activation
            activationRepository.save(activation);
        }

        // Create the audit log record.
        auditingServiceBehavior.logSignatureAuditRecord(activationDto, signatureData, signatureType,false,
                verificationResponse.getForcedSignatureVersion(), "signature_does_not_match", currentTimestamp);

        // Notify callback listeners, if needed
        if (notifyCallbackListeners) {
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
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
        auditingServiceBehavior.logSignatureAuditRecord(activationDto, signatureData, signatureType, false,
                activation.getVersion(), "activation_invalid_state", currentTimestamp);
    }

    /**
     * Implementation of handle inactive activation with mismatch in counter and activation status during signature verification.
     * @param activation Activation used for signature verification.
     * @param signatureData Data related to the signature.
     * @param signatureType Used signature type.
     * @param currentTimestamp Signature verification timestamp.
     */
    private void handleInactiveActivationWithMismatchSignatureImpl(ActivationRecordEntity activation, SignatureData signatureData, SignatureType signatureType, Date currentTimestamp) {
        final AuditingServiceBehavior.ActivationRecordDto activationDto = createActivationDtoFrom(activation);

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Enforce the blocked status on activation
        activation.setActivationStatus(ActivationStatus.BLOCKED);
        activation.setBlockedReason(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);

        // Save the activation and log change
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation);

        // Prepare data for the signature audit log
        final KeyValue entry = new KeyValue();
        entry.setKey(AdditionalInformation.Key.BLOCKED_REASON);
        entry.setValue(AdditionalInformation.Reason.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
        signatureData.getAdditionalInfo().add(entry);

        // Create the audit log record
        auditingServiceBehavior.logSignatureAuditRecord(activationDto, signatureData, signatureType, false,
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
     * Get whether signature type is not possession factor.
     * @param signatureType Signature type.
     * @return Whether signature type is not possession factor.
     */
    private boolean notPossessionFactorSignature(SignatureType signatureType) {
        return signatureType != null && !signatureType.equals(SignatureType.POSSESSION);
    }

    /**
     * Resolve signature version based on activation version and forced signature version from request.
     * @param activation Activation entity.
     * @param forcedSignatureVersion Forced signature version from request.
     * @return Resolved signature version.
     * @throws GenericServiceException Thrown in case activation state is invalid.
     */
    private Integer resolveSignatureVersion(ActivationRecordEntity activation, Integer forcedSignatureVersion) throws GenericServiceException {
        // Validate activation version
        activationValidator.validateVersionValid(activation.getVersion(), localizationProvider);

        // Set signature version based on activation version as default
        Integer signatureVersion = activation.getVersion();

        // Handle upgrade from version 2 to version 3, the version is forced during upgrade commit
        if (forcedSignatureVersion != null && forcedSignatureVersion == 3
                && activation.getVersion() == 2 && activation.getCtrDataBase64() != null) {
            // Version 3 is forced by client during upgrade from version 2, ctr_data already exists -> switch signature to version 3
            signatureVersion = 3;
        }
        return signatureVersion;
    }
}
