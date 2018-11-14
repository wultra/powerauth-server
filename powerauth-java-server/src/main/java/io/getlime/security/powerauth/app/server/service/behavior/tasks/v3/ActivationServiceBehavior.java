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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.converter.v3.XMLGregorianCalendarConverter;
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
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.app.server.service.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import io.getlime.security.powerauth.v3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
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
@Component("ActivationServiceBehavior")
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

    // Helper classes
    private final EciesFactory eciesFactory = new EciesFactory();
    private final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private final ObjectMapper objectMapper = new ObjectMapper();

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
     * Handle case when public key is invalid. Remove provided activation (mark as REMOVED),
     * notify callback listeners, and throw an exception.
     *
     * @param activation Activation to be removed.
     * @throws GenericServiceException Error caused by invalid public key.
     */
    private void handleInvalidPublicKey(ActivationRecordEntity activation) throws GenericServiceException {
        activation.setActivationStatus(ActivationStatus.REMOVED);
        repositoryCatalogue.getActivationRepository().save(activation);
        activationHistoryServiceBehavior.logActivationStatusChange(activation);
        callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());
        logger.warn("Invalid public key, activation ID: {}", activation.getActivationId());
        throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
    }

    /**
     * Validate activation in prepare or create activation step: it should be in CREATED state, it should be linked to correct
     * application and the activation code should have valid length.
     *
     * @param activation Activation used in prepare activation step.
     * @param application Application used in prepare activation step.
     * @throws GenericServiceException In case activation state is invalid.
     */
    private void validateCreatedActivation(ActivationRecordEntity activation, ApplicationEntity application) throws GenericServiceException {
        // If there is no such activation or application does not match the activation application, fail validation
        if (activation == null
                || !ActivationStatus.CREATED.equals(activation.getActivationStatus())
                || !Objects.equals(activation.getApplication().getId(), application.getId())) {
            logger.info("Activation state is invalid, activation ID: {}", activation != null ? activation.getActivationId() : "unknown");
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        // Make sure activation code has 23 characters
        if (activation.getActivationCode().length() != 23) {
            logger.info("Activation code is invalid, activation ID: {}", activation.getActivationId());
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
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
                GetActivationListForUserResponse.Activations activationServiceItem = new GetActivationListForUserResponse.Activations();
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
                // Unknown version is converted to 0 in SOAP
                activationServiceItem.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
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
     * @throws GenericServiceException        Thrown when cryptography error occurs.
     */
    public GetActivationStatusResponse getActivationStatus(String activationId, CryptoProviderUtil keyConversionUtilities) throws DatatypeConfigurationException, GenericServiceException {
        try {
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
                    MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(activation.getApplication().getId());
                    if (masterKeyPairEntity == null) {
                        logger.error("Missing key pair for application ID: {}", activation.getApplication().getId());
                        throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                    }
                    String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
                    byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterPrivateKeyBase64);
                    byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(
                            activation.getActivationCode(),
                            keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes)
                    );

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
                    response.setActivationCode(activation.getActivationCode());
                    response.setActivationSignature(BaseEncoding.base64().encode(activationSignature));
                    response.setDevicePublicKeyFingerprint(null);
                    // Unknown version is converted to 0 in SOAP
                    response.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                    return response;

                } else {

                    // Get the server private and device public keys to compute the transport key
                    String devicePublicKeyBase64 = activation.getDevicePublicKeyBase64();

                    // Get the server public key for the fingerprint
                    String serverPublicKeyBase64 = activation.getServerPublicKeyBase64();

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
                        PublicKey serverPublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));

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
                        switch (activation.getVersion()) {
                            case 2:
                                activationFingerPrint = powerAuthServerActivation.computeActivationFingerprint(devicePublicKey);
                                break;

                            case 3:
                                activationFingerPrint = powerAuthServerActivation.computeActivationFingerprint(devicePublicKey, serverPublicKey, activation.getActivationId());
                                break;

                            default:
                                logger.error("Unsupported activation version: {}", activation.getVersion());
                                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
                        }

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
                    response.setActivationCode(null);
                    response.setActivationSignature(null);
                    response.setDevicePublicKeyFingerprint(activationFingerPrint);
                    // Unknown version is converted to 0 in SOAP
                    response.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
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
                response.setActivationCode(null);
                response.setActivationSignature(null);
                response.setDevicePublicKeyFingerprint(null);
                // Use 0 as version when version is undefined
                response.setVersion(0L);
                return response;
            }
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Init activation with given parameters
     *
     * @param applicationId             Application ID
     * @param userId                    User ID
     * @param maxFailureCount            Maximum failed attempt count (5)
     * @param activationExpireTimestamp Timestamp after which activation can no longer be completed
     * @param keyConversionUtilities    Utility class for key conversion
     * @return Response with activation initialization data
     * @throws GenericServiceException If invalid values are provided.
     */
    public InitActivationResponse initActivation(Long applicationId, String userId, Long maxFailureCount, Date activationExpireTimestamp, CryptoProviderUtil keyConversionUtilities) throws GenericServiceException {
        try {
            // Generate timestamp in advance
            Date timestamp = new Date();

            if (userId == null) {
                logger.warn("User ID not specified");
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_USER_ID);
            }

            if (applicationId == 0L) {
                logger.warn("Application ID not specified");
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_APPLICATION_ID);
            }

            // Application version is not being checked in initActivation, it is checked later in prepareActivation or createActivation.

            // Get the repository
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();

            // Get number of max attempts from request or from constants, if not provided
            Long maxAttempt = maxFailureCount;
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
                logger.error("No master key pair found for application ID: {}", applicationId);
                throw ex;
            }
            byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterKeyPair.getMasterKeyPrivateBase64());
            PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);

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
                logger.error("Unable to generate activation ID");
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_ID);
            }

            // Generate a unique short activation ID for created and OTP used states
            String activationCode = null;
            Set<io.getlime.security.powerauth.app.server.database.model.ActivationStatus> states = ImmutableSet.of(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED, io.getlime.security.powerauth.app.server.database.model.ActivationStatus.OTP_USED);
            for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationShortIdIterations(); i++) {
                String tmpActivationCode = powerAuthServerActivation.generateActivationCode();
                ActivationRecordEntity record = activationRepository.findCreatedActivation(applicationId, tmpActivationCode, states, timestamp);
                // this activation short ID has a collision, reset it and find
                // another one
                if (record == null) {
                    activationCode = tmpActivationCode;
                    break;
                }
            }
            if (activationCode == null) {
                logger.error("Unable to generate short activation ID");
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_SHORT_ACTIVATION_ID);
            }


            // Compute activation signature
            byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(activationCode, masterPrivateKey);

            // Encode the signature
            String activationSignatureBase64 = BaseEncoding.base64().encode(activationSignature);

            // Generate server key pair
            KeyPair serverKeyPair = powerAuthServerActivation.generateServerKeyPair();
            byte[] serverKeyPrivateBytes = keyConversionUtilities.convertPrivateKeyToBytes(serverKeyPair.getPrivate());
            byte[] serverKeyPublicBytes = keyConversionUtilities.convertPublicKeyToBytes(serverKeyPair.getPublic());

            // Store the new activation
            ActivationRecordEntity activation = new ActivationRecordEntity();
            activation.setActivationId(activationId);
            activation.setActivationCode(activationCode);
            activation.setActivationName(null);
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
            // Activation version is not known yet
            activation.setVersion(null);
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
            response.setActivationCode(activationCode);
            response.setUserId(userId);
            response.setActivationSignature(activationSignatureBase64);
            response.setApplicationId(activation.getApplication().getId());

            return response;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Prepare activation with given parameters.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param activationCode Activation code.
     * @param applicationKey Application key.
     * @param eciesCryptogram Ecies cryptogram.
     * @return ECIES encrypted activation information.
     * @throws GenericServiceException If invalid values are provided.
     */
    public PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, EciesCryptogram eciesCryptogram) throws GenericServiceException {
        try {
            // Get current timestamp
            Date timestamp = new Date();

            // Get required repositories
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

            // Find application by application key
            ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, activation code: {}", activationCode);
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
            ApplicationEntity application = applicationVersion.getApplication();
            if (application == null) {
                logger.warn("Application does not exist, activation code: {}", activationCode);
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Get master server private key
            MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
            if (masterKeyPairEntity == null) {
                logger.error("Missing key pair for application ID: {}", application.getId());
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            }

            String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
            PrivateKey privateKey = keyConversion.convertBytesToPrivateKey(BaseEncoding.base64().decode(masterPrivateKeyBase64));

            // Get application secret
            byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

            // Get ecies decryptor
            EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptorForApplication((ECPrivateKey) privateKey, applicationSecret, EciesSharedInfo1.ACTIVATION_LAYER_2);

            // Decrypt activation data
            byte[] activationData = eciesDecryptor.decryptRequest(eciesCryptogram);

            // Convert JSON data to activation layer 2 request object
            ActivationLayer2Request request;
            try {
                request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, activation code: {}", activationCode);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Fetch the current activation by activation code
            Set<ActivationStatus> states = ImmutableSet.of(ActivationStatus.CREATED);
            ActivationRecordEntity activation = activationRepository.findCreatedActivation(application.getId(), activationCode, states, timestamp);

            // Make sure to deactivate the activation if it is expired
            if (activation != null) {
                deactivatePendingActivation(timestamp, activation);
            }

            // Validate that the activation is in correct state for the prepare step
            validateCreatedActivation(activation, application);

            // Extract the device public key from request
            byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(request.getDevicePublicKey());
            PublicKey devicePublicKey = null;

            try {
                devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                handleInvalidPublicKey(activation);
            }

            // Initialize hash based counter
            HashBasedCounter counter = new HashBasedCounter();
            byte[] ctrData = counter.init();
            String ctrDataBase64 = BaseEncoding.base64().encode(ctrData);

            // Update and persist the activation record
            activation.setActivationStatus(ActivationStatus.OTP_USED);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(request.getActivationName());
            activation.setExtras(request.getExtras());
            // PowerAuth protocol version 3.0 uses 0x3 as version in activation status
            activation.setVersion(3);
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);
            activationRepository.save(activation);
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());

            // Generate activation layer 2 response
            ActivationLayer2Response response = new ActivationLayer2Response();
            response.setActivationId(activation.getActivationId());
            response.setCtrData(ctrDataBase64);
            response.setServerPublicKey(activation.getServerPublicKeyBase64());
            byte[] responseData = objectMapper.writeValueAsBytes(response);

            // Encrypt response data
            EciesCryptogram responseCryptogram = eciesDecryptor.encryptResponse(responseData);
            String encryptedData = BaseEncoding.base64().encode(responseCryptogram.getEncryptedData());
            String mac = BaseEncoding.base64().encode(responseCryptogram.getMac());

            // Generate encrypted response
            PrepareActivationResponse encryptedResponse = new PrepareActivationResponse();
            encryptedResponse.setActivationId(activation.getActivationId());
            encryptedResponse.setEncryptedData(encryptedData);
            encryptedResponse.setMac(mac);
            return encryptedResponse;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException | JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Create activation with given parameters.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param userId                         User ID
     * @param activationExpireTimestamp      Timestamp after which activation can no longer be completed
     * @param maxFailureCount                Maximum failed attempt count (default = 5)
     * @param applicationKey                 Application key
     * @param eciesCryptogram                ECIES cryptogram
     * @param keyConversionUtilities         Utility class for key conversion
     * @return ECIES encrypted activation information
     * @throws GenericServiceException       In case create activation fails
     */
    public CreateActivationResponse createActivation(
            String userId,
            Date activationExpireTimestamp,
            Long maxFailureCount,
            String applicationKey,
            EciesCryptogram eciesCryptogram,
            CryptoProviderUtil keyConversionUtilities) throws GenericServiceException {
        try {
            // Get current timestamp
            Date timestamp = new Date();

            // Get required repositories
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();

            ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            // If there is no such activation version or activation version is unsupported, exit
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            ApplicationEntity application = applicationVersion.getApplication();
            // If there is no such application, exit
            if (application == null) {
                logger.warn("Application is incorrect, application key: {}", applicationKey);
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Create an activation record and obtain the activation database record
            InitActivationResponse initResponse = this.initActivation(application.getId(), userId, maxFailureCount, activationExpireTimestamp, keyConversionUtilities);
            String activationId = initResponse.getActivationId();
            ActivationRecordEntity activation = activationRepository.findActivation(activationId);

            // Make sure to deactivate the activation if it is expired
            if (activation != null) {
                deactivatePendingActivation(timestamp, activation);
            }

            validateCreatedActivation(activation, application);

            // Get master server private key
            MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
            if (masterKeyPairEntity == null) {
                logger.error("Missing key pair for application ID: {}", application.getId());
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            }

            String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
            PrivateKey privateKey = keyConversion.convertBytesToPrivateKey(BaseEncoding.base64().decode(masterPrivateKeyBase64));

            // Get application secret
            byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

            // Get ecies decryptor
            EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptorForApplication((ECPrivateKey) privateKey, applicationSecret, EciesSharedInfo1.ACTIVATION_LAYER_2);

            // Decrypt activation data
            byte[] activationData = eciesDecryptor.decryptRequest(eciesCryptogram);

            // Convert JSON data to activation layer 2 request object
            ActivationLayer2Request request;
            try {
                request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, activation ID: {}", activationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Extract the device public key from request
            byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(request.getDevicePublicKey());
            PublicKey devicePublicKey = null;

            try {
                devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                handleInvalidPublicKey(activation);
            }

            // Initialize hash based counter
            HashBasedCounter counter = new HashBasedCounter();
            byte[] ctrData = counter.init();
            String ctrDataBase64 = BaseEncoding.base64().encode(ctrData);

            // Update and persist the activation record
            activation.setActivationStatus(ActivationStatus.OTP_USED);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(request.getActivationName());
            activation.setExtras(request.getExtras());
            // PowerAuth protocol version 3.0 uses 0x3 as version in activation status
            activation.setVersion(3);
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);
            activationRepository.save(activation);
            activationHistoryServiceBehavior.logActivationStatusChange(activation);
            callbackUrlBehavior.notifyCallbackListeners(activation.getApplication().getId(), activation.getActivationId());

            // Generate activation layer 2 response
            ActivationLayer2Response response = new ActivationLayer2Response();
            response.setActivationId(activation.getActivationId());
            response.setCtrData(ctrDataBase64);
            response.setServerPublicKey(activation.getServerPublicKeyBase64());
            byte[] responseData = objectMapper.writeValueAsBytes(response);

            // Encrypt response data
            EciesCryptogram responseCryptogram = eciesDecryptor.encryptResponse(responseData);
            String encryptedData = BaseEncoding.base64().encode(responseCryptogram.getEncryptedData());
            String mac = BaseEncoding.base64().encode(responseCryptogram.getMac());

            // Generate encrypted response
            CreateActivationResponse encryptedResponse = new CreateActivationResponse();
            encryptedResponse.setActivationId(activation.getActivationId());
            encryptedResponse.setEncryptedData(encryptedData);
            encryptedResponse.setMac(mac);
            return encryptedResponse;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException | JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
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
                logger.info("Activation is already REMOVED, activation ID: {}", activationId);
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
                logger.info("Activation is not ACTIVE, activation ID: {}", activationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

        } else {
            // Activation does not exist
            logger.info("Activation does not exist, activation ID: {}", activationId);
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
            logger.info("Activation does not exist, activation ID: {}", activationId);
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
            logger.info("Activation does not exist, activation ID: {}", activationId);
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
            logger.info("Activation does not exist, activation ID: {}", activationId);
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
