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

package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.*;
import io.getlime.security.powerauth.GetActivationListForUserResponse.Activations;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.converter.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.KeyEncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Behavior class implementing processes related with activations. Used to move the
 * implementation outside of the main service implementation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class ActivationServiceBehavior {

    /**
     * Current PowerAuth protocol major version. Activations created with lower version will be upgraded to this version.
     */
    private static final byte POWERAUTH_PROTOCOL_VERSION = 0x3;

    private RepositoryCatalogue repositoryCatalogue;

    private CallbackUrlBehavior callbackUrlBehavior;

    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    private LocalizationProvider localizationProvider;

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    // Prepare converters
    private ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    private ServerPrivateKeyConverter serverPrivateKeyConverter;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(ActivationServiceBehavior.class);

    @Autowired
    public ActivationServiceBehavior(RepositoryCatalogue repositoryCatalogue, PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
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
    public void setServerPrivateKeyConverter(ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();

    /**
     * Deactivate the activation in CREATED or OTP_USED if it's activation expiration timestamp
     * is below the given timestamp.
     *
     * @param timestamp  Timestamp to check activations against.
     * @param activation Activation to check.
     */
    private void deactivatePendingActivation(Date timestamp, ActivationRecordEntity activation) {
        if ((activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED) || activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.OTP_USED)) && (timestamp.getTime() > activation.getTimestampActivationExpire().getTime())) {
            activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.REMOVED);
            repositoryCatalogue.getActivationRepository().save(activation);
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
        }
    }

    /**
     * Validate provided public key and if the key is null, remove provided activation
     * (mark as REMOVED), notify callback listeners, and throw exception.
     *
     * @param activation Activation to be removed in case the device public key is not valid.
     * @param devicePublicKey Device public key to be checked.
     * @throws GenericServiceException In case provided public key is null.
     */
    private void validateNotNullPublicKey(ActivationRecordEntity activation, PublicKey devicePublicKey) throws GenericServiceException {
        if (devicePublicKey == null) { // invalid key was sent, return error
            activation.setActivationStatus(ActivationStatus.REMOVED);
            repositoryCatalogue.getActivationRepository().save(activation);
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
    }

    /**
     * Get activations for application ID and user ID
     *
     * @param applicationId Application ID
     * @param userId        User ID
     * @return Response with list of matching activations
     * @throws DatatypeConfigurationException If calendar conversion fails.
     */
    public GetActivationListForUserResponse getActivationList(Long applicationId, String userId) throws DatatypeConfigurationException {

        // Generate timestamp in advance
        Date timestamp = new Date();

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        List<ActivationRecordEntity> activationsList;
        if (applicationId == null) {
            activationsList = activationRepository.findByUserId(userId);
        } else {
            activationsList = activationRepository.findByApplicationIdAndUserId(applicationId, userId);
        }

        GetActivationListForUserResponse response = new GetActivationListForUserResponse();
        response.setUserId(userId);
        if (activationsList != null) {
            for (ActivationRecordEntity activation : activationsList) {

                deactivatePendingActivation(timestamp, activation);

                // Map between database object and service objects
                Activations activationServiceItem = new Activations();
                activationServiceItem.setActivationId(activation.getActivationId());
                activationServiceItem.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                activationServiceItem.setBlockedReason(activation.getBlockedReason());
                activationServiceItem.setActivationName(activation.getActivationName());
                activationServiceItem.setExtras(activation.getExtras());
                activationServiceItem.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampCreated()));
                activationServiceItem.setTimestampLastUsed(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastUsed()));
                activationServiceItem.setUserId(activation.getUserId());
                activationServiceItem.setApplicationId(activation.getApplication().getId());
                activationServiceItem.setApplicationName(activation.getApplication().getName());
                response.getActivations().add(activationServiceItem);
            }
        }
        return response;
    }

    /**
     * Get activation status for given activation ID
     *
     * @param activationId           Activation ID
     * @param keyConversionUtilities Key conversion utility class
     * @return Activation status response
     * @throws DatatypeConfigurationException Thrown when calendar conversion fails.
     * @throws InvalidKeySpecException        Thrown when invalid key is provided.
     * @throws InvalidKeyException            Thrown when invalid key is provided.
     * @throws GenericServiceException        Thrown when any other error occurs.
     */
    public GetActivationStatusResponse getActivationStatus(String activationId, CryptoProviderUtil keyConversionUtilities) throws DatatypeConfigurationException, InvalidKeySpecException, InvalidKeyException, GenericServiceException {

        // Generate timestamp in advance
        Date timestamp = new Date();

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();

        ActivationRecordEntity activation = activationRepository.findActivation(activationId);

        // Check if the activation exists
        if (activation != null) {

            // Deactivate old pending activations first
            deactivatePendingActivation(timestamp, activation);

            // Handle CREATED activation
            if (activation.getActivationStatus() == io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED) {

                // Created activations are not able to transfer valid status blob to the client
                // since both keys were not exchanged yet and transport cannot be secured.
                byte[] randomStatusBlob = new KeyGenerator().generateRandomBytes(16);

                // Activation signature
                String masterPrivateKeyBase64 = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(activation.getApplication().getId()).getMasterKeyPrivateBase64();
                byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterPrivateKeyBase64);
                byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(
                        activation.getActivationIdShort(),
                        activation.getActivationOTP(),
                        keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes)
                );

                // Happens only when there is a crypto provider setup issue (SignatureException).
                if (activationSignature == null) {
                    throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
                }

                // return the data
                GetActivationStatusResponse response = new GetActivationStatusResponse();
                response.setActivationId(activationId);
                response.setUserId(activation.getUserId());
                response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                response.setBlockedReason(activation.getBlockedReason());
                response.setActivationName(activation.getActivationName());
                response.setExtras(activation.getExtras());
                response.setApplicationId(activation.getApplication().getId());
                response.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampCreated()));
                response.setTimestampLastUsed(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastUsed()));
                response.setEncryptedStatusBlob(BaseEncoding.base64().encode(randomStatusBlob));
                response.setActivationIdShort(activation.getActivationIdShort());
                response.setActivationOTP(activation.getActivationOTP());
                response.setActivationSignature(BaseEncoding.base64().encode(activationSignature));
                response.setDevicePublicKeyFingerprint(null);
                return response;

            } else {

                // Get the server private and device public keys to compute the transport key
                String devicePublicKeyBase64 = activation.getDevicePublicKeyBase64();

                // Decrypt server private key (depending on encryption mode)
                String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
                KeyEncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
                String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity, activation.getUserId(), activationId);

                // If an activation was turned to REMOVED directly from CREATED state,
                // there is not device public key in the database - we need to handle
                // that case by defaulting the C_statusBlob to random value...
                byte[] C_statusBlob = new KeyGenerator().generateRandomBytes(16);

                // Prepare a value for the device public key fingerprint
                String activationFingerPrint = null;

                // There is a device public key available, therefore we can compute
                // the real C_statusBlob value.
                if (devicePublicKeyBase64 != null) {

                    PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(serverPrivateKeyBase64));
                    PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(devicePublicKeyBase64));

                    SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                    SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);

                    // Encrypt the status blob
                    C_statusBlob = powerAuthServerActivation.encryptedStatusBlob(
                            activation.getActivationStatus().getByte(),
                            activation.getVersion().byteValue(),
                            POWERAUTH_PROTOCOL_VERSION,
                            activation.getFailedAttempts().byteValue(),
                            activation.getMaxFailedAttempts().byteValue(),
                            transportKey
                    );

                    // Assign the activation fingerprint
                    activationFingerPrint = powerAuthServerActivation.computeDevicePublicKeyFingerprint(devicePublicKey);

                }

                // return the data
                GetActivationStatusResponse response = new GetActivationStatusResponse();
                response.setActivationId(activationId);
                response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                response.setBlockedReason(activation.getBlockedReason());
                response.setActivationName(activation.getActivationName());
                response.setUserId(activation.getUserId());
                response.setExtras(activation.getExtras());
                response.setApplicationId(activation.getApplication().getId());
                response.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampCreated()));
                response.setTimestampLastUsed(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastUsed()));
                response.setEncryptedStatusBlob(BaseEncoding.base64().encode(C_statusBlob));
                response.setActivationIdShort(null);
                response.setActivationOTP(null);
                response.setActivationSignature(null);
                response.setDevicePublicKeyFingerprint(activationFingerPrint);

                return response;

            }
        } else {

            // Activations that do not exist should return REMOVED state and
            // a random status blob
            byte[] randomStatusBlob = new KeyGenerator().generateRandomBytes(16);

            // Generate date
            XMLGregorianCalendar zeroDate = XMLGregorianCalendarConverter.convertFrom(new Date(0));

            // return the data
            GetActivationStatusResponse response = new GetActivationStatusResponse();
            response.setActivationId(activationId);
            response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.REMOVED));
            response.setBlockedReason(null);
            response.setActivationName("unknown");
            response.setUserId("unknown");
            response.setApplicationId(0L);
            response.setExtras(null);
            response.setTimestampCreated(zeroDate);
            response.setTimestampLastUsed(zeroDate);
            response.setEncryptedStatusBlob(BaseEncoding.base64().encode(randomStatusBlob));
            response.setActivationIdShort(null);
            response.setActivationOTP(null);
            response.setActivationSignature(null);
            response.setDevicePublicKeyFingerprint(null);
            return response;
        }
    }

    /**
     * Init activation with given parameters
     *
     * @param applicationId             Application ID
     * @param userId                    User ID
     * @param maxFailedCount            Maximum failed attempt count (5)
     * @param activationExpireTimestamp Timestamp after which activation can no longer be completed
     * @param keyConversionUtilities    Utility class for key conversion
     * @return Response with activation initialization data
     * @throws GenericServiceException If invalid values are provided.
     * @throws InvalidKeySpecException If invalid key is provided
     * @throws InvalidKeyException     If invalid key is provided
     */
    public InitActivationResponse initActivation(Long applicationId, String userId, Long maxFailedCount, Date activationExpireTimestamp, CryptoProviderUtil keyConversionUtilities) throws GenericServiceException, InvalidKeySpecException, InvalidKeyException {
        // Generate timestamp in advance
        Date timestamp = new Date();

        if (userId == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_USER_ID);
        }

        if (applicationId == 0L) {
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_APPLICATION_ID);
        }

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();

        // Get number of max attempts from request or from constants, if not provided
        Long maxAttempt = maxFailedCount;
        if (maxAttempt == null) {
            maxAttempt = powerAuthServiceConfiguration.getSignatureMaxFailedAttempts();
        }

        // Get activation expiration date from request or from constants, if not provided
        Date timestampExpiration = activationExpireTimestamp;
        if (timestampExpiration == null) {
            timestampExpiration = new Date(timestamp.getTime() + powerAuthServiceConfiguration.getActivationValidityBeforeActive());
        }

        // Fetch the latest master private key
        MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPair == null) {
            GenericServiceException ex = localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            logger.error("No master key pair found for application ID: {}", applicationId, ex);
            throw ex;
        }
        byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterKeyPair.getMasterKeyPrivateBase64());
        PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);
        if (masterPrivateKey == null) {
            GenericServiceException ex = localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
            logger.error("Master private key is invalid for application ID {} ", applicationId, ex);
            throw ex;
        }

        // Generate new activation data, generate a unique activation ID
        String activationId = null;
        for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationIdIterations(); i++) {
            String tmpActivationId = powerAuthServerActivation.generateActivationId();
            ActivationRecordEntity record = activationRepository.findActivation(tmpActivationId);
            if (record == null) {
                activationId = tmpActivationId;
                break;
            } // ... else this activation ID has a collision, reset it and try to find another one
        }
        if (activationId == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_ID);
        }

        // Generate a unique short activation ID for created and OTP used states
        String activationIdShort = null;
        Set<io.getlime.security.powerauth.app.server.database.model.ActivationStatus> states = ImmutableSet.of(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED, io.getlime.security.powerauth.app.server.database.model.ActivationStatus.OTP_USED);
        for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationShortIdIterations(); i++) {
            String tmpActivationIdShort = powerAuthServerActivation.generateActivationIdShort();
            ActivationRecordEntity record = activationRepository.findCreatedActivation(applicationId, tmpActivationIdShort, states, timestamp);
            // this activation short ID has a collision, reset it and find
            // another one
            if (record == null) {
                activationIdShort = tmpActivationIdShort;
                break;
            }
        }
        if (activationIdShort == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_SHORT_ACTIVATION_ID);
        }

        // Generate activation OTP
        String activationOtp = powerAuthServerActivation.generateActivationOTP();

        // Compute activation signature
        byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(activationIdShort, activationOtp, masterPrivateKey);

        // Happens only when there is a crypto provider setup issue (SignatureException).
        if (activationSignature == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        }

        // Encode the signature
        String activationSignatureBase64 = BaseEncoding.base64().encode(activationSignature);

        // Generate server key pair
        KeyPair serverKeyPair = powerAuthServerActivation.generateServerKeyPair();
        byte[] serverKeyPrivateBytes = keyConversionUtilities.convertPrivateKeyToBytes(serverKeyPair.getPrivate());
        byte[] serverKeyPublicBytes = keyConversionUtilities.convertPublicKeyToBytes(serverKeyPair.getPublic());

        // Store the new activation
        ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setActivationId(activationId);
        activation.setActivationIdShort(activationIdShort);
        activation.setActivationName(null);
        activation.setActivationOTP(activationOtp);
        activation.setActivationStatus(ActivationStatus.CREATED);
        activation.setCounter(0L);
        activation.setDevicePublicKeyBase64(null);
        activation.setExtras(null);
        activation.setFailedAttempts(0L);
        activation.setApplication(masterKeyPair.getApplication());
        activation.setMasterKeyPair(masterKeyPair);
        activation.setMaxFailedAttempts(maxAttempt);
        activation.setServerPublicKeyBase64(BaseEncoding.base64().encode(serverKeyPublicBytes));
        activation.setTimestampActivationExpire(timestampExpiration);
        activation.setTimestampCreated(timestamp);
        activation.setTimestampLastUsed(timestamp);
        activation.setUserId(userId);

        // Convert server private key to DB columns serverPrivateKeyEncryption specifying encryption mode and serverPrivateKey with base64-encoded key.
        ServerPrivateKey serverPrivateKey = serverPrivateKeyConverter.toDBValue(serverKeyPrivateBytes, userId, activationId);
        activation.setServerPrivateKeyEncryption(serverPrivateKey.getKeyEncryptionMode());
        activation.setServerPrivateKeyBase64(serverPrivateKey.getServerPrivateKeyBase64());

        // A reference to saved ActivationRecordEntity is required when logging activation status change, otherwise issue #57 occurs on Oracle.
        activation = activationRepository.save(activation);
        activationHistoryServiceBehavior.logActivationStatusChange(activation);
        callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());

        // Return the server response
        InitActivationResponse response = new InitActivationResponse();
        response.setActivationId(activationId);
        response.setActivationIdShort(activationIdShort);
        response.setUserId(userId);
        response.setActivationOTP(activationOtp);
        response.setActivationSignature(activationSignatureBase64);
        response.setApplicationId(activation.getApplication().getId());

        return response;
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
     * @throws GenericServiceException      In case invalid data is provided
     * @throws InvalidKeySpecException      If invalid key was provided
     * @throws InvalidKeyException          If invalid key was provided
     * @throws UnsupportedEncodingException If UTF-8 is not supported on the system
     */
    public PrepareActivationResponse prepareActivation(String activationIdShort, String activationNonceBase64, String clientEphemeralPublicKeyBase64, String cDevicePublicKeyBase64, String activationName, String extras, String applicationKey, String applicationSignature, CryptoProviderUtil keyConversionUtilities) throws GenericServiceException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException {

        // Get current timestamp
        Date timestamp = new Date();

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();

        ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
        // if there is no such application, exit
        if (applicationVersion == null || !applicationVersion.getSupported()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        ApplicationEntity application = applicationVersion.getApplication();
        // if there is no such application, exit
        if (application == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        // Fetch the current activation by short activation ID
        Set<io.getlime.security.powerauth.app.server.database.model.ActivationStatus> states = ImmutableSet.of(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED);
        ActivationRecordEntity activation = activationRepository.findCreatedActivation(application.getId(), activationIdShort, states, timestamp);

        // Make sure to deactivate the activation if it is expired
        if (activation != null) {
            deactivatePendingActivation(timestamp, activation);
        }

        // if there is no such activation or application does not match the activation application, exit
        if (activation == null
                || !io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED.equals(activation.getActivationStatus())
                || !Objects.equals(activation.getApplication().getId(), application.getId())) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

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
        PublicKey devicePublicKey = powerAuthServerActivation.decryptDevicePublicKey(
                C_devicePublicKey,
                activationIdShort,
                masterPrivateKey,
                clientEphemeralPublicKey,
                activation.getActivationOTP(),
                activationNonce
        );

        validateNotNullPublicKey(activation, devicePublicKey);

        byte[] applicationSignatureBytes = BaseEncoding.base64().decode(applicationSignature);

        if (!powerAuthServerActivation.validateApplicationSignature(
                activationIdShort,
                activationNonce,
                C_devicePublicKey,
                BaseEncoding.base64().decode(applicationKey),
                BaseEncoding.base64().decode(applicationVersion.getApplicationSecret()),
                applicationSignatureBytes)) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        // Update and persist the activation record
        activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.OTP_USED);
        activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversionUtilities.convertPublicKeyToBytes(devicePublicKey)));
        activation.setActivationName(activationName);
        activation.setExtras(extras);
        activationRepository.save(activation);
        activationHistoryServiceBehavior.logActivationStatusChange(activation);
        callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());

        // Generate response data
        byte[] activationNonceServer = powerAuthServerActivation.generateActivationNonce();
        String serverPublicKeyBase64 = activation.getServerPublicKeyBase64();
        PublicKey serverPublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));
        KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();
        PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
        PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
        byte[] ephemeralPublicKeyBytes = keyConversionUtilities.convertPublicKeyToBytes(ephemeralPublicKey);
        String activationOtp = activation.getActivationOTP();

        // Encrypt the public key
        byte[] C_serverPublicKey = powerAuthServerActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, activationIdShort, activationNonceServer);

        // Get encrypted public key signature
        byte[] C_serverPubKeySignature = powerAuthServerActivation.computeServerDataSignature(activation.getActivationId(), C_serverPublicKey, masterPrivateKey);
        if (C_serverPubKeySignature == null) { // in case there is a technical error with signing and null is returned, return random bytes
            C_serverPubKeySignature = new KeyGenerator().generateRandomBytes(71);
        }

        // Compute the response
        PrepareActivationResponse response = new PrepareActivationResponse();
        response.setActivationId(activation.getActivationId());
        response.setActivationNonce(BaseEncoding.base64().encode(activationNonceServer));
        response.setEncryptedServerPublicKey(BaseEncoding.base64().encode(C_serverPublicKey));
        response.setEncryptedServerPublicKeySignature(BaseEncoding.base64().encode(C_serverPubKeySignature));
        response.setEphemeralPublicKey(BaseEncoding.base64().encode(ephemeralPublicKeyBytes));

        return response;
    }

    /**
     * Prepare activation with given parameters
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
     * @throws GenericServiceException      In case invalid data is provided
     * @throws InvalidKeySpecException      If invalid key was provided
     * @throws InvalidKeyException          If invalid key was provided
     * @throws UnsupportedEncodingException If UTF-8 is not supported on the system
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
            CryptoProviderUtil keyConversionUtilities) throws GenericServiceException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException {

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();

        ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
        // if there is no such application, exit
        if (applicationVersion == null || !applicationVersion.getSupported()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        ApplicationEntity application = applicationVersion.getApplication();
        // if there is no such application, exit
        if (application == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        // Create an activation record and obtain the activation database record
        InitActivationResponse initActivationResponse = this.initActivation(application.getId(), userId, maxFailedCount, activationExpireTimestamp, keyConversionUtilities);
        ActivationRecordEntity activation = activationRepository.findActivation(initActivationResponse.getActivationId());

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
        PublicKey devicePublicKey = powerAuthServerActivation.decryptDevicePublicKey(
                C_devicePublicKey,
                identity,
                masterPrivateKey,
                clientEphemeralPublicKey,
                activationOtp,
                activationNonce
        );

        validateNotNullPublicKey(activation, devicePublicKey);

        byte[] applicationSignatureBytes = BaseEncoding.base64().decode(applicationSignature);

        if (!powerAuthServerActivation.validateApplicationSignature(
                identity,
                activationNonce,
                C_devicePublicKey,
                BaseEncoding.base64().decode(applicationKey),
                BaseEncoding.base64().decode(applicationVersion.getApplicationSecret()),
                applicationSignatureBytes)) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        // Update and persist the activation record
        activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.OTP_USED);
        activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversionUtilities.convertPublicKeyToBytes(devicePublicKey)));
        activation.setActivationName(activationName);
        activation.setExtras(extras);
        activationRepository.save(activation);
        activationHistoryServiceBehavior.logActivationStatusChange(activation);
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
    }

    /**
     * Commit activation with given ID
     *
     * @param activationId Activation ID
     * @return Response with activation commit confirmation
     * @throws GenericServiceException In case invalid data is provided or activation is not found, in invalid state or already expired
     */
    public CommitActivationResponse commitActivation(String activationId) throws GenericServiceException {

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        ActivationRecordEntity activation = activationRepository.findActivation(activationId);

        // Get current timestamp
        Date timestamp = new Date();

        // Does the activation exist?
        if (activation != null) {

            // Check already deactivated activation
            deactivatePendingActivation(timestamp, activation);
            if (activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.REMOVED)) {
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Activation is in correct state
            if (activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.OTP_USED)) {
                activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.ACTIVE);
                activationRepository.save(activation);
                activationHistoryServiceBehavior.logActivationStatusChange(activation);
                callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());

                CommitActivationResponse response = new CommitActivationResponse();
                response.setActivationId(activationId);
                response.setActivated(true);
                return response;
            } else {
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

        } else {
            // Activation does not exist
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
    }

    /**
     * Remove activation with given ID
     *
     * @param activationId Activation ID
     * @return Response with confirmation of removal
     * @throws GenericServiceException In case activation does not exist
     */
    public RemoveActivationResponse removeActivation(String activationId) throws GenericServiceException {
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivation(activationId);
        if (activation != null) { // does the record even exist?
            activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.REMOVED);
            repositoryCatalogue.getActivationRepository().save(activation);
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
            RemoveActivationResponse response = new RemoveActivationResponse();
            response.setActivationId(activationId);
            response.setRemoved(true);
            return response;
        } else {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
    }

    /**
     * Block activation with given ID
     *
     * @param activationId Activation ID
     * @param reason Reason why activation is being blocked.
     * @return Response confirming that activation was blocked
     * @throws GenericServiceException In case activation does not exist.
     */
    public BlockActivationResponse blockActivation(String activationId, String reason) throws GenericServiceException {
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivation(activationId);
        if (activation == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // does the record even exist, is it in correct state?
        // early null check done above, no null check needed here
        if (activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.ACTIVE)) {
            activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.BLOCKED);
            if (reason == null) {
                activation.setBlockedReason(AdditionalInformation.BLOCKED_REASON_NOT_SPECIFIED);
            } else {
                activation.setBlockedReason(reason);
            }
            repositoryCatalogue.getActivationRepository().save(activation);
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
        }
        BlockActivationResponse response = new BlockActivationResponse();
        response.setActivationId(activationId);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        response.setBlockedReason(activation.getBlockedReason());
        return response;
    }

    /**
     * Unblock activation with given ID
     *
     * @param activationId Activation ID
     * @return Response confirming that activation was unblocked
     * @throws GenericServiceException In case activation does not exist.
     */
    public UnblockActivationResponse unblockActivation(String activationId) throws GenericServiceException {
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivation(activationId);
        if (activation == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // does the record even exist, is it in correct state?
        // early null check done above, no null check needed here
        if (activation.getActivationStatus().equals(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.BLOCKED)) {
            // Update and store new activation
            activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.ACTIVE);
            activation.setBlockedReason(null);
            activation.setFailedAttempts(0L);
            repositoryCatalogue.getActivationRepository().save(activation);
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
        }
        UnblockActivationResponse response = new UnblockActivationResponse();
        response.setActivationId(activationId);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        return response;
    }

}
