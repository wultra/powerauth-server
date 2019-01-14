/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.KeyEncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.signature.PowerAuthServerSignature;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import io.getlime.security.powerauth.v3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Behavior class implementing the signature validation related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class SignatureServiceBehavior {

    private static final String OFFLINE_MODE = "offline";
    private static final String KEY_MASTER_SERVER_PRIVATE_INDICATOR = "0";
    private static final String KEY_SERVER_PRIVATE_INDICATOR = "1";

    private RepositoryCatalogue repositoryCatalogue;

    private AuditingServiceBehavior auditingServiceBehavior;

    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    private CallbackUrlBehavior callbackUrlBehavior;

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private LocalizationProvider localizationProvider;

    // Prepare converters
    private SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();
    private ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private ServerPrivateKeyConverter serverPrivateKeyConverter;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(SignatureServiceBehavior.class);

    @Autowired
    public SignatureServiceBehavior(RepositoryCatalogue repositoryCatalogue, PowerAuthServiceConfiguration powerAuthServiceConfiguration, LocalizationProvider localizationProvider) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.localizationProvider = localizationProvider;
    }

    @Autowired
    public void setAuditingServiceBehavior(AuditingServiceBehavior auditingServiceBehavior) {
        this.auditingServiceBehavior = auditingServiceBehavior;
    }

    @Autowired
    public void setActivationServiceBehavior(ActivationHistoryServiceBehavior activationHistoryServiceBehavior) {
        this.activationHistoryServiceBehavior = activationHistoryServiceBehavior;
    }

    @Autowired
    public void setCallbackUrlBehavior(CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    @Autowired
    public void setServerPrivateKeyConverter(ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    private final PowerAuthServerSignature powerAuthServerSignature = new PowerAuthServerSignature();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    /**
     * Validate activation version.
     * @param activationVersion Version of activation.
     * @throws GenericServiceException Thrown when activation version is invalid.
     */
    private void validateActivationVersion(Integer activationVersion) throws GenericServiceException {
        if (activationVersion == null || activationVersion < 2 || activationVersion > 3) {
            logger.warn("Invalid activation version: {}", activationVersion);
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }
    }

    /**
     * Resovle signature version based on activation version and forced signature version from request.
     * @param activation Activation entity.
     * @param forcedSignatureVersion Forced signature version from request.
     * @return Resolved signature version.
     * @throws GenericServiceException Thrown in case activation state is invalid.
     */
    private Integer resolveSignatureVersion(ActivationRecordEntity activation, Integer forcedSignatureVersion) throws GenericServiceException {
        // Validate activation version
        validateActivationVersion(activation.getVersion());

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

    /**
     * Verify signature for given activation and provided data in online mode. Log every validation attempt in the audit log.
     *
     * @param activationId           Activation ID.
     * @param signatureType          Provided signature type.
     * @param signature              Provided signature.
     * @param additionalInfo         Additional information about operation.
     * @param dataString             String with data used to compute the signature.
     * @param applicationKey         Associated application key.
     * @param forcedSignatureVersion       Forced signature version during upgrade.
     * @param keyConversionUtilities Conversion utility class.
     * @return Response with the signature validation result object.
     * @throws GenericServiceException      In case server private key decryption fails.
     */
    public VerifySignatureResponse verifySignature(String activationId, SignatureType signatureType, String signature, KeyValueMap additionalInfo,
                                                   String dataString, String applicationKey, Integer forcedSignatureVersion, CryptoProviderUtil keyConversionUtilities)
            throws GenericServiceException {
        try {
            return verifySignature(activationId, signatureType, signature, additionalInfo, dataString, applicationKey, forcedSignatureVersion, keyConversionUtilities, false);
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Verify signature for given activation and provided data in offline mode. Log every validation attempt in the audit log.
     *
     * @param activationId           Activation ID.
     * @param signatureType          Provided signature type.
     * @param signature              Provided signature.
     * @param dataString             String with data used to compute the signature.
     * @param keyConversionUtilities Conversion utility class.
     * @return Response with the signature validation result object.
     * @throws GenericServiceException      In case server private key decryption fails.
     */
    public VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, SignatureType signatureType, String signature,
                                                                 String dataString, CryptoProviderUtil keyConversionUtilities)
            throws GenericServiceException {
        try {
            final VerifySignatureResponse verifySignatureResponse = verifySignature(activationId, signatureType, signature, null, dataString, null, null, keyConversionUtilities, true);
            VerifyOfflineSignatureResponse response = new VerifyOfflineSignatureResponse();
            response.setActivationId(verifySignatureResponse.getActivationId());
            response.setActivationStatus(verifySignatureResponse.getActivationStatus());
            response.setBlockedReason(verifySignatureResponse.getBlockedReason());
            response.setApplicationId(verifySignatureResponse.getApplicationId());
            response.setRemainingAttempts(verifySignatureResponse.getRemainingAttempts());
            response.setSignatureType(verifySignatureResponse.getSignatureType());
            response.setSignatureValid(verifySignatureResponse.isSignatureValid());
            response.setUserId(verifySignatureResponse.getUserId());
            return response;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    private VerifySignatureResponse verifySignature(String activationId, SignatureType signatureType, String signature, KeyValueMap additionalInfo,
                                                    String dataString, String applicationKey, Integer forcedSignatureVersion, CryptoProviderUtil keyConversionUtilities, boolean isOffline)
            throws InvalidKeySpecException, InvalidKeyException, GenericServiceException, GenericCryptoException, CryptoProviderException {
        // Prepare current timestamp in advance
        Date currentTimestamp = new Date();

        // Fetch related activation
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);

        // Only validate signature for existing ACTIVE activation records
        if (activation != null) {

            String applicationSecret;

            Long applicationId = activation.getApplication().getId();

            if (isOffline) {

                applicationSecret = OFFLINE_MODE;

            } else {
                // Check the activation - application relationship and version support
                ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(applicationKey);

                if (applicationVersion == null || !applicationVersion.getSupported() || !Objects.equals(applicationVersion.getApplication().getId(), applicationId)) {
                    logger.warn("Application version is incorrect, application key: {}", applicationKey);
                    // Get the data and append application KEY in this case, just for auditing reasons
                    byte[] data = (dataString + "&" + applicationKey).getBytes(StandardCharsets.UTF_8);
                    SignatureRequest signatureRequest = new SignatureRequest(data, signature, signatureType, additionalInfo, forcedSignatureVersion);
                    boolean notifyCallbackListeners = handleInvalidApplicationVersion(activation, signatureRequest, currentTimestamp);

                    // Notify callback listeners, if needed
                    if (notifyCallbackListeners) {
                        callbackUrlBehavior.notifyCallbackListeners(applicationId, activationId);
                    }

                    // return the data
                    return invalidStateResponse(activation.getActivationStatus());
                }

                applicationSecret = applicationVersion.getApplicationSecret();
            }

            byte[] data = (dataString + "&" + applicationSecret).getBytes(StandardCharsets.UTF_8);
            SignatureRequest signatureRequest = new SignatureRequest(data, signature, signatureType, additionalInfo, forcedSignatureVersion);

            if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

                ValidateSignatureResponse validationResponse = validateSignature(activation, signatureRequest, keyConversionUtilities);

                // Check if the signature is valid
                if (validationResponse.isSignatureValid()) {

                    handleValidSignature(activation, validationResponse, signatureRequest, currentTimestamp);

                    return validSignatureResponse(activation, applicationId, signatureRequest);

                } else {

                    boolean notifyCallbackListeners = handleInvalidSignature(activation, validationResponse, signatureRequest, currentTimestamp);

                    // Notify callback listeners, if needed
                    if (notifyCallbackListeners) {
                        callbackUrlBehavior.notifyCallbackListeners(applicationId, activationId);
                    }

                    Long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
                    return invalidSignatureResponse(activation, applicationId, signatureRequest, remainingAttempts);

                }
            } else {

                handleInactiveActivationSignature(activation, signatureRequest, currentTimestamp);

                // return the data
                return invalidStateResponse(activation.getActivationStatus());

            }
        } else { // Activation does not exist

            return invalidStateResponse(ActivationStatus.REMOVED);

        }
    }

    /**
     * Generates an invalid signature reponse when state is invalid (invalid applicationVersion, activation is not active, activation does not exist, etc.).
     *
     * @return Invalid signature response.
     */
    private VerifySignatureResponse invalidStateResponse(ActivationStatus activationStatus) {
        VerifySignatureResponse response = new VerifySignatureResponse();
        response.setSignatureValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activationStatus));
        return response;

    }

    /**
     * Generates a valid signature response when signature validation succeeded.
     * @param activation Activation ID.
     * @param applicationId Application ID.
     * @param signatureRequest Signature request.
     * @return Valid signature response.
     */
    private VerifySignatureResponse validSignatureResponse(ActivationRecordEntity activation, Long applicationId, SignatureRequest signatureRequest) {
        // return the data
        VerifySignatureResponse response = new VerifySignatureResponse();
        response.setSignatureValid(true);
        response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.ACTIVE));
        response.setBlockedReason(null);
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.setSignatureType(signatureRequest.getSignatureType());
        return response;
    }

    /**
     * Generates an invalid signature response when signature validation failed.
     * @param activation Activation ID.
     * @param applicationId Application ID.
     * @param signatureRequest Signature request.
     * @param remainingAttempts Count of remaining attempts.
     * @return Invalid signature response.
     */
    private VerifySignatureResponse invalidSignatureResponse(ActivationRecordEntity activation, Long applicationId, SignatureRequest signatureRequest, Long remainingAttempts) {
        // return the data
        VerifySignatureResponse response = new VerifySignatureResponse();
        response.setSignatureValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        response.setBlockedReason(activation.getBlockedReason());
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.setSignatureType(signatureRequest.getSignatureType());
        return response;
    }

    private ValidateSignatureResponse validateSignature(ActivationRecordEntity activation, SignatureRequest signatureRequest, CryptoProviderUtil keyConversionUtilities) throws InvalidKeyException, InvalidKeySpecException, GenericServiceException, CryptoProviderException, GenericCryptoException {
        // Get the server private and device public keys

        // Decrypt server private key (depending on encryption mode)
        String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
        KeyEncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
        String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity, activation.getUserId(), activation.getActivationId());

        // Decode the keys to byte[]
        byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(serverPrivateKeyBase64);
        byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
        PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

        // Compute the master secret key
        SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

        // Get the signature keys according to the signature type
        final PowerAuthSignatureTypes powerAuthSignatureTypes = signatureTypeConverter.convertFrom(signatureRequest.getSignatureType());
        List<SecretKey> signatureKeys = powerAuthServerKeyFactory.keysForSignatureType(powerAuthSignatureTypes, masterSecretKey);

        // Resolve signature version based on activation version and request
        Integer signatureVersion = resolveSignatureVersion(activation, signatureRequest.getForcedSignatureVersion());

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
        HashBasedCounter hashBasedCounter = new HashBasedCounter();
        // Get counter data from activation for version 3
        if (signatureVersion == 3) {
            ctrHash = BaseEncoding.base64().decode(activation.getCtrDataBase64());
        }

        for (long iteratedCounter = ctr; iteratedCounter < ctr + powerAuthServiceConfiguration.getSignatureValidationLookahead(); iteratedCounter++) {
            switch (signatureVersion) {
                case 2:
                    // Use numeric counter for counter data
                    ctrData = ByteBuffer.allocate(16).putLong(8, iteratedCounter).array();
                    break;
                case 3:
                    // Set ctrData for current iteration
                    ctrData = ctrHash;
                    // Increment the hash based counter
                    ctrHash = hashBasedCounter.next(ctrHash);
                    break;
            }
            signatureValid = powerAuthServerSignature.verifySignatureForData(signatureRequest.getData(), signatureRequest.getSignature(), signatureKeys, ctrData);
            if (signatureValid) {
                // Set the next valid value of numeric counter based on current iteration counter +1
                ctrNext = iteratedCounter + 1;
                // Set the next valid value of hash based counter (ctrHash is already incremented by +1)
                ctrDataNext = ctrHash;
                break;
            }
        }
        return new ValidateSignatureResponse(signatureValid, ctrNext, ctrDataNext, signatureVersion);
    }

    private boolean handleInvalidApplicationVersion(ActivationRecordEntity activation, SignatureRequest signatureRequest, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // By default do not notify listeners
        boolean notifyCallbackListeners = false;

        // Update failed attempts and block the activation, if necessary
        if (notPossessionFactorSignature(signatureRequest.getSignatureType())) {
            activation.setFailedAttempts(activation.getFailedAttempts() + 1);
            Long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
            if (remainingAttempts <= 0) {
                activation.setActivationStatus(ActivationStatus.BLOCKED);
                activation.setBlockedReason(AdditionalInformation.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
                // Activation is persisted together with activation history using Cascade.PERSIST on ActivationHistoryEntity
                activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
                KeyValueMap additionalInfo = signatureRequest.getAdditionalInfo();
                KeyValueMap.Entry entry = new KeyValueMap.Entry();
                entry.setKey(AdditionalInformation.BLOCKED_REASON);
                entry.setValue(AdditionalInformation.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
                additionalInfo.getEntry().add(entry);
                // notify callback listeners
                notifyCallbackListeners = true;
            }
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record
        auditingServiceBehavior.logSignatureAuditRecord(activation, signatureRequest.getSignatureType(), signatureRequest.getSignature(), signatureRequest.getAdditionalInfo(), signatureRequest.getData(),
                false, activation.getVersion(), "activation_invalid_application", currentTimestamp);

        return notifyCallbackListeners;
    }

    private void handleValidSignature(ActivationRecordEntity activation, ValidateSignatureResponse validationResponse, SignatureRequest signatureRequest, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        if (validationResponse.getForcedSignatureVersion() == 3) {
            // Set the ctrData to next valid ctrData value
            activation.setCtrDataBase64(BaseEncoding.base64().encode(validationResponse.getCtrDataNext()));
        }

        // Set the activation record counter to next valid counter value
        activation.setCounter(validationResponse.getCtrNext());

        // Reset failed attempt count
        if (notPossessionFactorSignature(signatureRequest.getSignatureType())) {
            activation.setFailedAttempts(0L);
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record.
        auditingServiceBehavior.logSignatureAuditRecord(activation, signatureRequest.getSignatureType(), signatureRequest.getSignature(), signatureRequest.getAdditionalInfo(),
                signatureRequest.getData(), true, validationResponse.getForcedSignatureVersion(), "signature_ok", currentTimestamp);
    }

    private boolean handleInvalidSignature(ActivationRecordEntity activation, ValidateSignatureResponse validationResponse, SignatureRequest signatureRequest, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // By default do not notify listeners
        boolean notifyCallbackListeners = false;

        // Update failed attempts and block the activation, if necessary
        if (notPossessionFactorSignature(signatureRequest.getSignatureType())) {
            activation.setFailedAttempts(activation.getFailedAttempts() + 1);
        }

        Long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        if (remainingAttempts <= 0) {
            activation.setActivationStatus(ActivationStatus.BLOCKED);
            activation.setBlockedReason(AdditionalInformation.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
            // Activation is persisted together with activation history using Cascade.PERSIST on ActivationHistoryEntity
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            KeyValueMap additionalInfo = signatureRequest.getAdditionalInfo();
            KeyValueMap.Entry entry = new KeyValueMap.Entry();
            entry.setKey(AdditionalInformation.BLOCKED_REASON);
            entry.setValue(AdditionalInformation.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
            additionalInfo.getEntry().add(entry);
            // notify callback listeners
            notifyCallbackListeners = true;
        }

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record.
        auditingServiceBehavior.logSignatureAuditRecord(activation, signatureRequest.getSignatureType(), signatureRequest.getSignature(), signatureRequest.getAdditionalInfo(), signatureRequest.getData(),
                false, validationResponse.getForcedSignatureVersion(), "signature_does_not_match", currentTimestamp);

        return notifyCallbackListeners;
    }

    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data, CryptoProviderUtil keyConversionUtilities) throws GenericServiceException {

        // Fetch activation details from the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // Proceed and compute the results
        try {

            // Generate nonce
            final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
            String nonce = BaseEncoding.base64().encode(nonceBytes);

            // Decrypt server private key (depending on encryption mode)
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final KeyEncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity, activation.getUserId(), activationId);

            // Decode the private key - KEY_SERVER_PRIVATE is used for personalized offline signatures
            final PrivateKey privateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(serverPrivateKeyBase64));

            // Compute ECDSA signature of '{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}'
            final SignatureUtils signatureUtils = new SignatureUtils();
            final byte[] signatureBase = (data + "\n" + nonce + "\n" + KEY_SERVER_PRIVATE_INDICATOR).getBytes(StandardCharsets.UTF_8);
            final byte[] ecdsaSignatureBytes = signatureUtils.computeECDSASignature(signatureBase, privateKey);
            final String ecdsaSignature = BaseEncoding.base64().encode(ecdsaSignatureBytes);

            // Construct complete offline data as '{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}'
            final String offlineData = (data + "\n" + nonce + "\n" + KEY_SERVER_PRIVATE_INDICATOR + ecdsaSignature);

            // Return the result
            CreatePersonalizedOfflineSignaturePayloadResponse response = new CreatePersonalizedOfflineSignaturePayloadResponse();
            response.setOfflineData(offlineData);
            response.setNonce(nonce);
            return response;

        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data, CryptoProviderUtil keyConversionUtilities) throws GenericServiceException {
        // Fetch associated master key pair data from the repository
        final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
        final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPair == null) {
            logger.error("No master key pair found for application ID: {}", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }

        // Proceed and compute the results
        try {

            // Generate nonce
            final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
            String nonce = BaseEncoding.base64().encode(nonceBytes);

            // Prepare the private key - KEY_MASTER_SERVER_PRIVATE is used for non-personalized offline signatures
            final String keyPrivateBase64 = masterKeyPair.getMasterKeyPrivateBase64();
            final PrivateKey privateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(keyPrivateBase64));

            // Compute ECDSA signature of '{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}'
            final SignatureUtils signatureUtils = new SignatureUtils();
            final byte[] signatureBase = (data + "\n" + nonce + "\n" + KEY_MASTER_SERVER_PRIVATE_INDICATOR).getBytes(StandardCharsets.UTF_8);
            final byte[] ecdsaSignatureBytes = signatureUtils.computeECDSASignature(signatureBase, privateKey);
            final String ecdsaSignature = BaseEncoding.base64().encode(ecdsaSignatureBytes);

            // Construct complete offline data as '{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}'
            final String offlineData = (data + "\n" + nonce + "\n" + KEY_MASTER_SERVER_PRIVATE_INDICATOR + ecdsaSignature);

            // Return the result
            CreateNonPersonalizedOfflineSignaturePayloadResponse response = new CreateNonPersonalizedOfflineSignaturePayloadResponse();
            response.setOfflineData(offlineData);
            response.setNonce(nonce);
            return response;

        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    private boolean notPossessionFactorSignature(SignatureType signatureType) {
        return signatureType != null && !signatureType.equals(SignatureType.POSSESSION);
    }

    private void handleInactiveActivationSignature(ActivationRecordEntity activation, SignatureRequest signatureRequest, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // Update the last used date
        activation.setTimestampLastUsed(currentTimestamp);

        // Save the activation
        activationRepository.save(activation);

        // Create the audit log record.
        auditingServiceBehavior.logSignatureAuditRecord(activation, signatureRequest.getSignatureType(), signatureRequest.getSignature(), signatureRequest.getAdditionalInfo(), signatureRequest.getData(),
                false, activation.getVersion(), "activation_invalid_state", currentTimestamp);
    }

    private static class SignatureRequest {

        private final byte[] data;
        private final String signature;
        private final SignatureType signatureType;
        private final KeyValueMap additionalInfo;
        private final Integer forcedSignatureVersion;

        /**
         * Signature request constructur.
         * @param data Signed data.
         * @param signature Data signature.
         * @param signatureType Signature type.
         * @param additionalInfo Additional information related to the signature.
         * @param forcedSignatureVersion Forced signature version during upgrade.
         */
        SignatureRequest(byte[] data, String signature, SignatureType signatureType, KeyValueMap additionalInfo, Integer forcedSignatureVersion) {
            this.data = data;
            this.signature = signature;
            this.signatureType = signatureType;
            if (additionalInfo == null) {
                this.additionalInfo = new KeyValueMap();
            } else {
                this.additionalInfo = additionalInfo;
            }
            this.forcedSignatureVersion = forcedSignatureVersion;
        }

        /**
         * Get signed data.
         * @return Signed data.
         */
        byte[] getData() {
            return data;
        }

        /**
         * Get data signature.
         * @return Data signature.
         */
        String getSignature() {
            return signature;
        }

        /**
         * Get signature type.
         * @return Signature type.
         */
        SignatureType getSignatureType() {
            return signatureType;
        }

        /**
         * Get additional information related to the signature.
         * @return Additional information related to the signature.
         */
        KeyValueMap getAdditionalInfo() {
            return additionalInfo;
        }

        /**
         * Get forced signature version.
         * @return Forced signature version.
         */
        public Integer getForcedSignatureVersion() {
            return forcedSignatureVersion;
        }
    }

    private static class ValidateSignatureResponse {

        private final boolean signatureValid;
        private final long ctrNext;
        private final byte[] ctrDataNext;
        private final Integer forcedSignatureVersion;

        /**
         * Validate signature response constructor.
         * @param signatureValid Whether signature is valid.
         * @param ctrNext Next numeric counter value in case signature is valid.
         * @param ctrDataNext Next hash based counter data in case signature is valid.
         * @param forcedSignatureVersion Signature version which may differ from activation version during upgrade.
         */
        ValidateSignatureResponse(boolean signatureValid, long ctrNext, byte[] ctrDataNext, Integer forcedSignatureVersion) {
            this.signatureValid = signatureValid;
            this.ctrNext = ctrNext;
            this.ctrDataNext = ctrDataNext;
            this.forcedSignatureVersion = forcedSignatureVersion;
        }

        /**
         * Get whether signature is valid.
         * @return Whether signature is valid.
         */
        boolean isSignatureValid() {
            return signatureValid;
        }

        /**
         * Get next numeric counter value in case signature is valid.
         * @return Next numeric counter value.
         */
        long getCtrNext() {
            return ctrNext;
        }

        /**
         * Get next hash based counter value in case signature is valid.
         * @return Next hash based counter value.
         */
        byte[] getCtrDataNext() {
            return ctrDataNext;
        }

        /**
         * Get signature version.
         * @return Signature version.
         */
        Integer getForcedSignatureVersion() {
            return forcedSignatureVersion;
        }
    }
}
