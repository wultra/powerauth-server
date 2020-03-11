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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v2;

import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.v3.ActivationHistoryServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.v3.CallbackUrlBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.v2.CreateActivationResponse;
import io.getlime.security.powerauth.v2.PrepareActivationResponse;
import io.getlime.security.powerauth.v3.ActivationOtpValidation;
import io.getlime.security.powerauth.v3.InitActivationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

/**
 * Behavior class implementing processes related with activations. Used to move the
 * implementation outside of the main service implementation.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component("activationServiceBehaviorV2")
public class ActivationServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;

    private CallbackUrlBehavior callbackUrlBehavior;

    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    private io.getlime.security.powerauth.app.server.service.behavior.tasks.v3.ActivationServiceBehavior activationServiceBehaviorV3;

    private LocalizationProvider localizationProvider;


    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(ActivationServiceBehavior.class);

    @Autowired
    public ActivationServiceBehavior(RepositoryCatalogue repositoryCatalogue) {
        this.repositoryCatalogue = repositoryCatalogue;
    }

    @Autowired
    public void setCallbackUrlBehavior(CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    @Autowired
    public void setActivationHistoryServiceBehavior(ActivationHistoryServiceBehavior activationHistoryServiceBehavior) {
        this.activationHistoryServiceBehavior = activationHistoryServiceBehavior;
    }

    @Autowired
    public void setActivationActivationServiceBehaviorV3(io.getlime.security.powerauth.app.server.service.behavior.tasks.v3.ActivationServiceBehavior activationServiceBehaviorV3) {
        this.activationServiceBehaviorV3 = activationServiceBehaviorV3;
    }

    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();

    /**
     * Deactivate the activation in CREATED or OTP_USED if it's activation expiration timestamp
     * is below the given timestamp.
     *
     * @param timestamp  Timestamp to check activations against.
     * @param activation Activation to check.
     */
    private void deactivatePendingActivation(Date timestamp, ActivationRecordEntity activation) {
        if ((activation.getActivationStatus().equals(ActivationStatus.CREATED) || activation.getActivationStatus().equals(ActivationStatus.OTP_USED)) && (timestamp.getTime() > activation.getTimestampActivationExpire().getTime())) {
            activation.setActivationStatus(ActivationStatus.REMOVED);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
        }
    }

    /**
     * Handle case when public key is invalid. Remove provided activation (mark as REMOVED),
     * notify callback listeners, and throw an exception.
     *
     * @param activation Activation to be removed.
     * @throws GenericServiceException Error caused by invalid public key.
     */
    private void handleInvalidPublicKey(ActivationRecordEntity activation) throws GenericServiceException {
        activation.setActivationStatus(ActivationStatus.REMOVED);
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
        callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
        logger.warn("Invalid public key, activation ID: {}", activation.getActivationId());
        // Exception must not be rollbacking, otherwise data written to database in this method would be lost
        throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
    }

    /**
     * Validate activation in prepare or create activation step: it should be in CREATED state, it should be linked to correct
     * application and the activation code should have valid length.
     *
     * @param activation Activation used in prepare activation step.
     * @param application Application used in prepare activation step.
     * @param rollbackInCaseOfError Whether transaction should be rolled back in case of validation error.
     * @throws GenericServiceException In case activation state is invalid.
     */
    private void validateCreatedActivation(ActivationRecordEntity activation, ApplicationEntity application, boolean rollbackInCaseOfError) throws GenericServiceException {
        // If there is no such activation or application does not match the activation application, fail validation
        if (activation == null
                || !ActivationStatus.CREATED.equals(activation.getActivationStatus())
                || !Objects.equals(activation.getApplication().getId(), application.getId())) {
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
     * Prepare activation with given parameters
     *
     * @param activationIdShort              Short activation ID
     * @param activationNonceBase64          Activation nonce encoded as Base64
     * @param clientEphemeralPublicKeyBase64 Client ephemeral public key encoded as Base64
     * @param cDevicePublicKeyBase64         Encrypted device public key encoded as Base64
     * @param activationName                 Activation name
     * @param extras                         Extra parameter
     * @param applicationKey                 Application key
     * @param applicationSignature           Application signature
     * @param keyConversionUtilities         Utility class for key conversion
     * @return Prepared activation information
     * @throws GenericServiceException      In case prepare activation fails
     */
    public PrepareActivationResponse prepareActivation(String activationIdShort, String activationNonceBase64, String clientEphemeralPublicKeyBase64, String cDevicePublicKeyBase64, String activationName, String extras, String applicationKey, String applicationSignature, KeyConvertor keyConversionUtilities) throws GenericServiceException {
        try {
            // Get current timestamp
            Date timestamp = new Date();

            // Get the repository
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();

            ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            // If there is no such activation version or activation version is unsupported, exit
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            ApplicationEntity application = applicationVersion.getApplication();
            // If there is no such application, exit
            if (application == null) {
                logger.warn("Application does not exist, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Fetch the current activation by short activation ID
            Set<ActivationStatus> states = ImmutableSet.of(ActivationStatus.CREATED);
            // Search for activation without lock to avoid potential deadlocks
            ActivationRecordEntity activation = activationRepository.findCreatedActivationByShortIdWithoutLock(application.getId(), activationIdShort, states, timestamp);

            if (activation == null) {
                logger.warn("Activation does not exist for short activation ID: {}", activationIdShort);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Make sure to deactivate the activation if it is expired
            // Search for activation again to aquire PESSIMISTIC_WRITE lock for activation row
            activation = activationRepository.findActivationWithLock(activation.getActivationId());
            deactivatePendingActivation(timestamp, activation);

            // Validate that the activation is in correct state for the prepare step
            validateCreatedActivation(activation, application, false);

            // Extract activation OTP from activation code
            String activationOtp = activation.getActivationCode().substring(12);

            // Get master private key
            String masterPrivateKeyBase64 = activation.getMasterKeyPair().getMasterKeyPrivateBase64();
            byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterPrivateKeyBase64);
            PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);

            // Get client ephemeral public key
            PublicKey clientEphemeralPublicKey = null;
            if (clientEphemeralPublicKeyBase64 != null) { // additional encryption is used
                byte[] clientEphemeralPublicKeyBytes = BaseEncoding.base64().decode(clientEphemeralPublicKeyBase64);
                clientEphemeralPublicKey = keyConversionUtilities.convertBytesToPublicKey(clientEphemeralPublicKeyBytes);
            }

            // Decrypt the device public key
            byte[] C_devicePublicKey = BaseEncoding.base64().decode(cDevicePublicKeyBase64);
            byte[] activationNonce = BaseEncoding.base64().decode(activationNonceBase64);

            PublicKey devicePublicKey = null;
            try {
                devicePublicKey = powerAuthServerActivation.decryptDevicePublicKey(
                        C_devicePublicKey,
                        activationIdShort,
                        masterPrivateKey,
                        clientEphemeralPublicKey,
                        activationOtp,
                        activationNonce
                );
            } catch (GenericCryptoException ex) {
                handleInvalidPublicKey(activation);
            }

            byte[] applicationSignatureBytes = BaseEncoding.base64().decode(applicationSignature);

            if (!powerAuthServerActivation.validateApplicationSignature(
                    activationIdShort,
                    activationNonce,
                    C_devicePublicKey,
                    BaseEncoding.base64().decode(applicationKey),
                    BaseEncoding.base64().decode(applicationVersion.getApplicationSecret()),
                    applicationSignatureBytes)) {
                logger.warn("Activation signature is invalid, activation ID short: {}", activationIdShort);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Generate response data before writing to database to avoid rollbacks
            byte[] activationNonceServer = powerAuthServerActivation.generateActivationNonce();
            String serverPublicKeyBase64 = activation.getServerPublicKeyBase64();
            PublicKey serverPublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));
            KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();
            PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
            PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
            byte[] ephemeralPublicKeyBytes = keyConversionUtilities.convertPublicKeyToBytes(ephemeralPublicKey);

            // Encrypt the public key
            byte[] C_serverPublicKey = powerAuthServerActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, activationIdShort, activationNonceServer);

            // Get encrypted public key signature
            byte[] C_serverPubKeySignature = powerAuthServerActivation.computeServerDataSignature(activation.getActivationId(), C_serverPublicKey, masterPrivateKey);
            if (C_serverPubKeySignature == null) { // in case there is a technical error with signing and null is returned, return random bytes
                C_serverPubKeySignature = new KeyGenerator().generateRandomBytes(71);
            }

            // Update and persist the activation record
            activation.setActivationStatus(ActivationStatus.OTP_USED);
            activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversionUtilities.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(activationName);
            activation.setExtras(extras);
            // PowerAuth protocol version 2.0 and 2.1 uses 0x2 as version in activation status
            activation.setVersion(2);
            // Counter data is null, numeric counter is used in this version
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());

            // Compute the response
            PrepareActivationResponse response = new PrepareActivationResponse();
            response.setActivationId(activation.getActivationId());
            response.setActivationNonce(BaseEncoding.base64().encode(activationNonceServer));
            response.setEncryptedServerPublicKey(BaseEncoding.base64().encode(C_serverPublicKey));
            response.setEncryptedServerPublicKeySignature(BaseEncoding.base64().encode(C_serverPubKeySignature));
            response.setEphemeralPublicKey(BaseEncoding.base64().encode(ephemeralPublicKeyBytes));

            return response;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Create activation with given parameters
     *
     * @param userId                         User ID
     * @param maxFailedCount                 Maximum failed attempt count (5)
     * @param activationExpireTimestamp      Timestamp after which activation can no longer be completed
     * @param identity                       A string representing the provided identity
     * @param activationOtp                  Activation OTP parameter
     * @param activationNonceBase64          Activation nonce encoded as Base64
     * @param clientEphemeralPublicKeyBase64 Client ephemeral public key encoded as Base64
     * @param cDevicePublicKeyBase64         Encrypted device public key encoded as Base64
     * @param activationName                 Activation name
     * @param extras                         Extra parameter
     * @param applicationKey                 Application key
     * @param applicationSignature           Application signature
     * @param keyConversionUtilities         Utility class for key conversion
     * @return Prepared activation information
     * @throws GenericServiceException      In case create activation fails
     */
    public CreateActivationResponse createActivation(
            String applicationKey,
            String userId,
            Long maxFailedCount,
            Date activationExpireTimestamp,
            String identity,
            String activationOtp,
            String activationNonceBase64,
            String clientEphemeralPublicKeyBase64,
            String cDevicePublicKeyBase64,
            String activationName,
            String extras,
            String applicationSignature,
            KeyConvertor keyConversionUtilities) throws GenericServiceException {
        try {
            // Get current timestamp
            Date timestamp = new Date();

            // Get the repository
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();

            ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            // If there is no such activation version or activation version is unsupported, exit
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            ApplicationEntity application = applicationVersion.getApplication();
            // If there is no such application, exit
            if (application == null) {
                logger.warn("Application is incorrect, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Create an activation record and obtain the activation database record
            InitActivationResponse initResponse = activationServiceBehaviorV3.initActivation(
                    application.getId(),
                    userId,
                    maxFailedCount,
                    activationExpireTimestamp,
                    ActivationOtpValidation.NONE,
                    null,
                    keyConversionUtilities);
            String activationId = initResponse.getActivationId();
            ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);

            if (activation == null) { // this should not happen - activation was just created above by calling "init" method
                logger.warn("Activation does not exist for activation ID: {}", activationId);
                // The whole transaction is rolled back in case of this unexpected state
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Make sure to deactivate the activation if it is expired
            deactivatePendingActivation(timestamp, activation);

            // Validate that the activation is in correct state for the create step.
            // Transaction is rolled back in case validation fails, because this state is very suspicious, the activation
            // was just created using init, so it should not be invalid.
            validateCreatedActivation(activation, application, true);

            // Get master private key
            String masterPrivateKeyBase64 = activation.getMasterKeyPair().getMasterKeyPrivateBase64();
            byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterPrivateKeyBase64);
            PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);

            // Get client ephemeral public key
            PublicKey clientEphemeralPublicKey = null;
            if (clientEphemeralPublicKeyBase64 != null) { // additional encryption is used
                byte[] clientEphemeralPublicKeyBytes = BaseEncoding.base64().decode(clientEphemeralPublicKeyBase64);
                clientEphemeralPublicKey = keyConversionUtilities.convertBytesToPublicKey(clientEphemeralPublicKeyBytes);
            }

            // Decrypt the device public key
            byte[] C_devicePublicKey = BaseEncoding.base64().decode(cDevicePublicKeyBase64);
            byte[] activationNonce = BaseEncoding.base64().decode(activationNonceBase64);

            PublicKey devicePublicKey = null;
            try {
                devicePublicKey = powerAuthServerActivation.decryptDevicePublicKey(
                        C_devicePublicKey,
                        identity,
                        masterPrivateKey,
                        clientEphemeralPublicKey,
                        activationOtp,
                        activationNonce
                );
            } catch (GenericCryptoException ex) {
                logger.warn("Device public key is invalid, activation ID: {}", activationId);
                // Device public key is invalid, rollback this transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            byte[] applicationSignatureBytes = BaseEncoding.base64().decode(applicationSignature);

            if (!powerAuthServerActivation.validateApplicationSignature(
                    identity,
                    activationNonce,
                    C_devicePublicKey,
                    BaseEncoding.base64().decode(applicationKey),
                    BaseEncoding.base64().decode(applicationVersion.getApplicationSecret()),
                    applicationSignatureBytes)) {
                logger.warn("Activation signature is invalid, activation ID: {}", activationId);
                // Activation signature is invalid, rollback this transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Update and persist the activation record
            activation.setActivationStatus(ActivationStatus.OTP_USED);
            activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversionUtilities.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(activationName);
            activation.setExtras(extras);
            // PowerAuth protocol version 2.0 and 2.1 uses 0x2 as version
            activation.setVersion(2);
            // Hash based counter is not used in this version
            activation.setCtrDataBase64(null);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());

            // Generate response data
            byte[] activationNonceServer = powerAuthServerActivation.generateActivationNonce();
            String serverPublicKeyBase64 = activation.getServerPublicKeyBase64();
            PublicKey serverPublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));
            KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();
            PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
            PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
            byte[] ephemeralPublicKeyBytes = keyConversionUtilities.convertPublicKeyToBytes(ephemeralPublicKey);

            // Encrypt the public key
            byte[] C_serverPublicKey = powerAuthServerActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, identity, activationNonceServer);

            // Get encrypted public key signature
            byte[] C_serverPubKeySignature = powerAuthServerActivation.computeServerDataSignature(activation.getActivationId(), C_serverPublicKey, masterPrivateKey);
            if (C_serverPubKeySignature == null) { // in case there is a technical error with signing and null is returned, return random bytes
                C_serverPubKeySignature = new KeyGenerator().generateRandomBytes(71);
            }

            // Compute the response
            CreateActivationResponse response = new CreateActivationResponse();
            response.setActivationId(activation.getActivationId());
            response.setActivationNonce(BaseEncoding.base64().encode(activationNonceServer));
            response.setEncryptedServerPublicKey(BaseEncoding.base64().encode(C_serverPublicKey));
            response.setEncryptedServerPublicKeySignature(BaseEncoding.base64().encode(C_serverPubKeySignature));
            response.setEphemeralPublicKey(BaseEncoding.base64().encode(ephemeralPublicKeyBytes));

            return response;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

}
