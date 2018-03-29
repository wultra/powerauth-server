/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.signature.PowerAuthServerSignature;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Behavior class implementing the signature validation related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class SignatureServiceBehavior {

    private static final String OFFLINE_MODE = "offline";

    private RepositoryCatalogue repositoryCatalogue;

    private AuditingServiceBehavior auditingServiceBehavior;

    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    private CallbackUrlBehavior callbackUrlBehavior;

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private LocalizationProvider localizationProvider;

    // Prepare converters
    private SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();
    private ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

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

    private final PowerAuthServerSignature powerAuthServerSignature = new PowerAuthServerSignature();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    /**
     * Verify signature for given activation and provided data in online mode. Log every validation attempt in the audit log.
     *
     * @param activationId           Activation ID.
     * @param signatureType          Provided signature type.
     * @param signature              Provided signature.
     * @param additionalInfo         Additional information about operation.
     * @param dataString             String with data used to compute the signature.
     * @param applicationKey         Associated application key.
     * @param keyConversionUtilities Conversion utility class.
     * @return Response with the signature validation result object.
     * @throws UnsupportedEncodingException In case UTF-8 is not supported on the system.
     * @throws InvalidKeySpecException      In case invalid key is provided.
     * @throws InvalidKeyException          In case invalid key is provided.
     */
    public VerifySignatureResponse verifySignature(String activationId, SignatureType signatureType, String signature, KeyValueMap additionalInfo,
                                                   String dataString, String applicationKey, CryptoProviderUtil keyConversionUtilities)
            throws UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException {
        return verifySignature(activationId, signatureType, signature, additionalInfo, dataString, applicationKey, keyConversionUtilities, false);
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
     * @throws UnsupportedEncodingException In case UTF-8 is not supported on the system.
     * @throws InvalidKeySpecException      In case invalid key is provided.
     * @throws InvalidKeyException          In case invalid key is provided.
     */
    public VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, SignatureType signatureType, String signature,
                                                                 String dataString, CryptoProviderUtil keyConversionUtilities)
            throws UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException {

        final VerifySignatureResponse verifySignatureResponse = verifySignature(activationId, signatureType, signature, null, dataString, null, keyConversionUtilities, true);
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
    }

    private VerifySignatureResponse verifySignature(String activationId, SignatureType signatureType, String signature, KeyValueMap additionalInfo,
                                                    String dataString, String applicationKey, CryptoProviderUtil keyConversionUtilities, boolean isOffline)
            throws UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException {
        // Prepare current timestamp in advance
        Date currentTimestamp = new Date();

        // Fetch related activation
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivation(activationId);

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

                    // Get the data and append application KEY in this case, just for auditing reasons
                    byte[] data = (dataString + "&" + applicationKey).getBytes("UTF-8");
                    SignatureRequest signatureRequest = new SignatureRequest(data, signature, signatureType, additionalInfo);
                    boolean notifyCallbackListeners = handleInvalidApplicationVersion(activation, signatureRequest, currentTimestamp);

                    // Notify callback listeners, if needed
                    if (notifyCallbackListeners) {
                        callbackUrlBehavior.notifyCallbackListeners(applicationId, activationId);
                    }

                    // return the data
                    return invalidStateResponse();
                }

                applicationSecret = applicationVersion.getApplicationSecret();
            }

            byte[] data = (dataString + "&" + applicationSecret).getBytes("UTF-8");
            SignatureRequest signatureRequest = new SignatureRequest(data, signature, signatureType, additionalInfo);

            if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

                ValidateSignatureResponse validationResponse = validateSignature(activation, signatureRequest, keyConversionUtilities);

                // Check if the signature is valid
                if (validationResponse.isSignatureValid()) {

                    handleValidSignature(activation, validationResponse, signatureRequest, currentTimestamp);

                    return validSignatureResponse(activation, applicationId, signatureRequest);

                } else {

                    boolean notifyCallbackListeners = handleInvalidSignature(activation, signatureRequest, currentTimestamp);

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
                return invalidStateResponse();

            }
        } else { // Activation does not exist

            return invalidStateResponse();

        }
    }

    /**
     * Generates an invalid signature reponse when state is invalid (invalid applicationVersion, activation is not active, activation does not exist, etc.).
     *
     * @return Invalid signature response.
     */
    private VerifySignatureResponse invalidStateResponse() {
        VerifySignatureResponse response = new VerifySignatureResponse();
        response.setSignatureValid(false);
        response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.REMOVED));
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

    private ValidateSignatureResponse validateSignature(ActivationRecordEntity activation, SignatureRequest signatureRequest, CryptoProviderUtil keyConversionUtilities) throws InvalidKeyException, InvalidKeySpecException {
        // Get the server private and device public keys
        byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(activation.getServerPrivateKeyBase64());
        byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
        PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

        // Compute the master secret key
        SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

        // Get the signature keys according to the signature type
        final PowerAuthSignatureTypes powerAuthSignatureTypes = signatureTypeConverter.convertFrom(signatureRequest.getSignatureType());
        List<SecretKey> signatureKeys = powerAuthServerKeyFactory.keysForSignatureType(powerAuthSignatureTypes, masterSecretKey);

        // Verify the signature with given lookahead
        boolean signatureValid = false;
        long ctr = activation.getCounter();
        long lowestValidCounter = ctr;
        for (long iteratedCounter = ctr; iteratedCounter < ctr + powerAuthServiceConfiguration.getSignatureValidationLookahead(); iteratedCounter++) {
            signatureValid = powerAuthServerSignature.verifySignatureForData(signatureRequest.getData(), signatureRequest.getSignature(), signatureKeys, iteratedCounter);
            if (signatureValid) {
                // set the lowest valid counter and break at the lowest
                // counter where signature validates
                lowestValidCounter = iteratedCounter;
                break;
            }
        }
        return new ValidateSignatureResponse(signatureValid, lowestValidCounter);
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
                activationHistoryServiceBehavior.logActivationStatusChange(activation);
                activation.setBlockedReason(AdditionalInformation.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
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
                false, "activation_invalid_application", currentTimestamp);

        return notifyCallbackListeners;
    }

    private void handleValidSignature(ActivationRecordEntity activation, ValidateSignatureResponse validationResponse, SignatureRequest signatureRequest, Date currentTimestamp) {
        // Get ActivationRepository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // Set the activation record counter to the lowest counter
        // (+1, since the client has incremented the counter)
        activation.setCounter(validationResponse.getLowestValidCounter() + 1);

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
                signatureRequest.getData(), true, "signature_ok", currentTimestamp);
    }

    private boolean handleInvalidSignature(ActivationRecordEntity activation, SignatureRequest signatureRequest, Date currentTimestamp) {
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
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            activation.setBlockedReason(AdditionalInformation.BLOCKED_REASON_MAX_FAILED_ATTEMPTS);
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
                false, "signature_does_not_match", currentTimestamp);

        return notifyCallbackListeners;
    }

    public CreateOfflineSignaturePayloadResponse createOfflineSignaturePayload(String activationId, String data, String message, CryptoProviderUtil keyConversionUtilities) throws GenericServiceException {

        // Fetch activation details from the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final ActivationRecordEntity activation = activationRepository.findActivation(activationId);
        if (activation == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // Fetch associated master key pair data from the repository
        final Long applicationId = activation.getApplication().getId();
        final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
        final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPair == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }

        // Proceed and compute the results
        try {

            // Generate nonce
            final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
            String nonce = BaseEncoding.base64().encode(nonceBytes);

            // Compute data hash
            final byte[] dataHashBytes = Hash.sha256(data);
            String dataHash = BaseEncoding.base64().encode(dataHashBytes);

            // Prepare the private key
            final String keyPrivateBase64 = masterKeyPair.getMasterKeyPrivateBase64();
            final PrivateKey privateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(keyPrivateBase64));

            // Compute ECDSA signature of 'dataHash + "&" + nonce + "&" + message'
            final SignatureUtils signatureUtils = new SignatureUtils();
            final byte[] signatureBase = (activationId + "&" + dataHash + "&" + nonce + "&" + message).getBytes("UTF-8");
            final byte[] ecdsaSignatureBytes = signatureUtils.computeECDSASignature(signatureBase, privateKey);
            final String ecdsaSignature = BaseEncoding.base64().encode(ecdsaSignatureBytes);

            // Return the result
            CreateOfflineSignaturePayloadResponse response = new CreateOfflineSignaturePayloadResponse();
            response.setData(data);
            response.setMessage(message);
            response.setDataHash(dataHash);
            response.setNonce(nonce);
            response.setSignature(ecdsaSignature);
            return response;

        } catch (InvalidKeyException | InvalidKeySpecException e) {
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (SignatureException e) {
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (UnsupportedEncodingException e) {
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, e.getMessage(), e.getLocalizedMessage());
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
                false, "activation_invalid_state", currentTimestamp);
    }

    private class SignatureRequest {

        private final byte[] data;
        private final String signature;
        private final SignatureType signatureType;
        private final KeyValueMap additionalInfo;

        SignatureRequest(byte[] data, String signature, SignatureType signatureType, KeyValueMap additionalInfo) {
            this.data = data;
            this.signature = signature;
            this.signatureType = signatureType;
            if (additionalInfo == null) {
                this.additionalInfo = new KeyValueMap();
            } else {
                this.additionalInfo = additionalInfo;
            }
        }

        byte[] getData() {
            return data;
        }

        String getSignature() {
            return signature;
        }

        SignatureType getSignatureType() {
            return signatureType;
        }

        KeyValueMap getAdditionalInfo() {
            return additionalInfo;
        }
    }

    private class ValidateSignatureResponse {

        private final boolean signatureValid;
        private final long lowestValidCounter;

        ValidateSignatureResponse(boolean signatureValid, long lowestValidCounter) {
            this.signatureValid = signatureValid;
            this.lowestValidCounter = lowestValidCounter;
        }

        boolean isSignatureValid() {
            return signatureValid;
        }

        long getLowestValidCounter() {
            return lowestValidCounter;
        }
    }
}
