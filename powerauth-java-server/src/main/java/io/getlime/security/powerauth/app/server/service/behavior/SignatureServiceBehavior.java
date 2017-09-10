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

package io.getlime.security.powerauth.app.server.service.behavior;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.SignatureType;
import io.getlime.security.powerauth.VerifySignatureResponse;
import io.getlime.security.powerauth.app.server.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.repository.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.repository.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.repository.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.service.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.service.util.ModelUtil;
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

    private ActivationRepository powerAuthRepository;

    private ApplicationVersionRepository applicationVersionRepository;

    private AuditingServiceBehavior auditingServiceBehavior;

    private CallbackUrlBehavior callbackUrlBehavior;

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    @Autowired
    public SignatureServiceBehavior(ActivationRepository powerAuthRepository, ApplicationVersionRepository applicationVersionRepository, PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.powerAuthRepository = powerAuthRepository;
        this.applicationVersionRepository = applicationVersionRepository;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
    }

    @Autowired
    public void setAuditingServiceBehavior(AuditingServiceBehavior auditingServiceBehavior) {
        this.auditingServiceBehavior = auditingServiceBehavior;
    }

    @Autowired
    public void setCallbackUrlBehavior(CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    private final PowerAuthServerSignature powerAuthServerSignature = new PowerAuthServerSignature();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    /**
     * Verify signature for given activation and provided data. Log every validation attempt in the audit log.
     *
     * @param activationId           Activation ID.
     * @param signatureType          Provided signature type.
     * @param signature              Provided signature.
     * @param dataString             String with data used to compute the signature.
     * @param applicationKey         Associated application key.
     * @param keyConversionUtilities Conversion utility class.
     * @return Response with the signature validation result object.
     * @throws UnsupportedEncodingException In case UTF-8 is not supported on the system.
     * @throws InvalidKeySpecException      In case invalid key is provided.
     * @throws InvalidKeyException          In case invalid key is provided.
     */
    public VerifySignatureResponse verifySignature(String activationId, SignatureType signatureType, String signature, String dataString, String applicationKey, CryptoProviderUtil keyConversionUtilities) throws UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException {
        // Prepare current timestamp in advance
        Date currentTimestamp = new Date();

        // Store flag in case callback listeners should be updated
        boolean notifyCallbackListeners = false;

        // Fetch related activation
        ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);

        // Only validate signature for existing ACTIVE activation records
        if (activation != null) {

            // Check the activation - application relationship and version support
            ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);

            if (applicationVersion == null || !applicationVersion.getSupported() || !Objects.equals(applicationVersion.getApplication().getId(), activation.getApplication().getId())) {

                // Get the data and append application KEY in this case, just for auditing reasons
                byte[] data = (dataString + "&" + applicationKey).getBytes("UTF-8");

                // Increment the counter
                activation.setCounter(activation.getCounter() + 1);

                // Update failed attempts and block the activation, if necessary
                if (notPossessionFactorSignature(signatureType)) {
                    activation.setFailedAttempts(activation.getFailedAttempts() + 1);
                    Long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
                    if (remainingAttempts <= 0) {
                        activation.setActivationStatus(ActivationStatus.BLOCKED);
                        notifyCallbackListeners = true;
                    }
                }

                // Update the last used date
                activation.setTimestampLastUsed(currentTimestamp);

                // Save the activation
                powerAuthRepository.save(activation);

                // Create the audit log record.
                auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, false, "activation_invalid_application", currentTimestamp);

                // Notify callback listeners, if needed
                if (notifyCallbackListeners && applicationVersion != null) {
                    callbackUrlBehavior.notifyCallbackListeners(applicationVersion.getId(), activationId);
                }

                // return the data
                VerifySignatureResponse response = new VerifySignatureResponse();
                response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
                response.setSignatureValid(false);

                return response;
            }

            String applicationSecret = applicationVersion.getApplicationSecret();
            byte[] data = (dataString + "&" + applicationSecret).getBytes("UTF-8");

            if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

                // Get the server private and device public keys
                byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(activation.getServerPrivateKeyBase64());
                byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
                PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
                PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

                // Compute the master secret key
                SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

                // Get the signature keys according to the signature type
                List<SecretKey> signatureKeys = powerAuthServerKeyFactory.keysForSignatureType(ModelUtil.fromServiceSignatureType(signatureType), masterSecretKey);

                // Verify the signature with given lookahead
                boolean signatureValid = false;
                long ctr = activation.getCounter();
                long lowestValidCounter = ctr;
                for (long iteratedCounter = ctr; iteratedCounter < ctr + powerAuthServiceConfiguration.getSignatureValidationLookahead(); iteratedCounter++) {
                    signatureValid = powerAuthServerSignature.verifySignatureForData(data, signature, signatureKeys, iteratedCounter);
                    if (signatureValid) {
                        // set the lowest valid counter and break at the lowest
                        // counter where signature validates
                        lowestValidCounter = iteratedCounter;
                        break;
                    }
                }

                // Check if the signature is valid
                if (signatureValid) {

                    // Set the activation record counter to the lowest counter
                    // (+1, since the client has incremented the counter)
                    activation.setCounter(lowestValidCounter + 1);

                    // Reset failed attempt count
                    if (notPossessionFactorSignature(signatureType)) {
                        activation.setFailedAttempts(0L);
                    }

                    // Update the last used date
                    activation.setTimestampLastUsed(currentTimestamp);

                    // Save the activation
                    powerAuthRepository.save(activation);

                    // Create the audit log record.
                    auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, true, "signature_ok", currentTimestamp);

                    // return the data
                    VerifySignatureResponse response = new VerifySignatureResponse();
                    response.setSignatureValid(true);
                    response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.ACTIVE));
                    response.setActivationId(activationId);
                    response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
                    response.setUserId(activation.getUserId());
                    response.setApplicationId(applicationVersion.getId());
                    response.setSignatureType(signatureType);

                    return response;

                } else {

                    // Increment the activation record counter
                    activation.setCounter(activation.getCounter() + 1);

                    // Update failed attempts and block the activation, if necessary
                    if (notPossessionFactorSignature(signatureType)) {
                        activation.setFailedAttempts(activation.getFailedAttempts() + 1);
                    }

                    Long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
                    if (remainingAttempts <= 0) {
                        activation.setActivationStatus(ActivationStatus.BLOCKED);
                        notifyCallbackListeners = true;
                    }

                    // Update the last used date
                    activation.setTimestampLastUsed(currentTimestamp);

                    // Save the activation
                    powerAuthRepository.save(activation);

                    // Create the audit log record.
                    auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, false, "signature_does_not_match", currentTimestamp);

                    // Notify callback listeners, if needed
                    if (notifyCallbackListeners) {
                        callbackUrlBehavior.notifyCallbackListeners(applicationVersion.getId(), activationId);
                    }

                    // return the data
                    VerifySignatureResponse response = new VerifySignatureResponse();
                    response.setSignatureValid(false);
                    response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
                    response.setActivationId(activationId);
                    response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
                    response.setUserId(activation.getUserId());
                    response.setApplicationId(applicationVersion.getId());
                    response.setSignatureType(signatureType);

                    return response;

                }

            } else {

                // Activation is not in active state, increase the counter anyway
                activation.setCounter(activation.getCounter() + 1);

                // Update the last used date
                activation.setTimestampLastUsed(currentTimestamp);

                // Save the activation
                powerAuthRepository.save(activation);

                // Create the audit log record.
                auditingServiceBehavior.logSignatureAuditRecord(activation, signatureType, signature, data, false, "activation_invalid_state", currentTimestamp);

                // return the data
                VerifySignatureResponse response = new VerifySignatureResponse();
                response.setSignatureValid(false);
                response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));

                return response;

            }

        } else { // Activation does not exist

            VerifySignatureResponse response = new VerifySignatureResponse();
            response.setSignatureValid(false);
            response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
            return response;

        }
    }

    private boolean notPossessionFactorSignature(SignatureType signatureType) {
        return signatureType != null && !signatureType.equals(SignatureType.POSSESSION);
    }

}
