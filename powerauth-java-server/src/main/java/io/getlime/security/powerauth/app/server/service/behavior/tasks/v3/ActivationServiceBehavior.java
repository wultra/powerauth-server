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
import com.wultra.security.powerauth.client.v3.ActivationOtpValidation;
import com.wultra.security.powerauth.client.v3.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationOtpValidationConverter;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.*;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus;
import io.getlime.security.powerauth.app.server.database.model.*;
import io.getlime.security.powerauth.app.server.database.model.entity.*;
import io.getlime.security.powerauth.app.server.database.repository.*;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ActivationRecovery;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.app.server.service.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.model.RecoveryInfo;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.PasswordHash;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
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
import java.util.*;
import java.util.stream.Collectors;

/**
 * Behavior class implementing processes related with activations. Used to move the
 * implementation outside of the main service implementation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component("activationServiceBehavior")
public class ActivationServiceBehavior {

    /**
     * Current PowerAuth protocol major version. Activations created with lower version will be upgraded to this version.
     */
    private static final byte POWERAUTH_PROTOCOL_VERSION = 0x3;

    private final RepositoryCatalogue repositoryCatalogue;

    private CallbackUrlBehavior callbackUrlBehavior;

    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    private LocalizationProvider localizationProvider;

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final ActivationOtpValidationConverter activationOtpValidationConverter = new ActivationOtpValidationConverter();
    private ServerPrivateKeyConverter serverPrivateKeyConverter;
    private RecoveryPukConverter recoveryPukConverter;

    // Helper classes
    private final EciesFactory eciesFactory = new EciesFactory();
    private final ObjectMapper objectMapper;
    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(ActivationServiceBehavior.class);

    @Autowired
    public ActivationServiceBehavior(RepositoryCatalogue repositoryCatalogue, PowerAuthServiceConfiguration powerAuthServiceConfiguration, ObjectMapper objectMapper) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.objectMapper = objectMapper;
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

    @Autowired
    public void setRecoveryPukConverter(RecoveryPukConverter recoveryPukConverter) {
        this.recoveryPukConverter = recoveryPukConverter;
    }

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();

    /**
     * Deactivate the activation in CREATED or PENDING_COMMIT if it's activation expiration timestamp
     * is below the given timestamp.
     *
     * @param timestamp  Timestamp to check activations against.
     * @param activation Activation to check.
     */
    private void deactivatePendingActivation(Date timestamp, ActivationRecordEntity activation, boolean isActivationLocked) {
        if ((activation.getActivationStatus().equals(ActivationStatus.CREATED) || activation.getActivationStatus().equals(ActivationStatus.PENDING_COMMIT)) && (timestamp.getTime() > activation.getTimestampActivationExpire().getTime())) {
            if (!isActivationLocked) {
                // Make sure activation is locked until the end of transaction in case it was not locked yet
                activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activation.getActivationId());
            }
            activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.REMOVED);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
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
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
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
                // Rollback is used during createActivation and createActivationUsingRecoveryCode, because activation has just been initialized and it is invalid
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
                // Rollback is used during createActivation and createActivationUsingRecoveryCode, because activation has just been initialized and it is invalid
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            } else {
                // Regular exception is used during prepareActivation
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
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
        final Date timestamp = new Date();

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

                deactivatePendingActivation(timestamp, activation, false);

                // Map between database object and service objects
                GetActivationListForUserResponse.Activations activationServiceItem = new GetActivationListForUserResponse.Activations();
                activationServiceItem.setActivationId(activation.getActivationId());
                activationServiceItem.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                activationServiceItem.setBlockedReason(activation.getBlockedReason());
                activationServiceItem.setActivationName(activation.getActivationName());
                activationServiceItem.setExtras(activation.getExtras());
                activationServiceItem.setPlatform(activation.getPlatform());
                activationServiceItem.setDeviceInfo(activation.getDeviceInfo());
                activationServiceItem.getActivationFlags().addAll(activation.getFlags());
                activationServiceItem.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampCreated()));
                activationServiceItem.setTimestampLastUsed(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastUsed()));
                activationServiceItem.setTimestampLastChange(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastChange()));
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
     * Lookup activations using various query parameters.
     *
     * @param userIds User IDs to be used in the activations query.
     * @param applicationIds Application IDs to be used in the activations query (optional).
     * @param timestampLastUsedBefore Last used timestamp to be used in the activations query, return all records where timestampLastUsed &lt; timestampLastUsedBefore.
     * @param timestampLastUsedAfter Last used timestamp to be used in the activations query, return all records where timestampLastUsed &gt;= timestampLastUsedAfter.
     * @param activationStatus Activation status to be used in the activations query (optional).
     * @return Response with list of matching activations.
     * @throws DatatypeConfigurationException If calendar conversion fails.
     */
    public LookupActivationsResponse lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) throws DatatypeConfigurationException {
        final LookupActivationsResponse response = new LookupActivationsResponse();
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        if (applicationIds != null && applicationIds.isEmpty()) {
            // Make sure application ID list is null in case no application ID is specified
            applicationIds = null;
        }
        List<ActivationStatus> statuses = new ArrayList<>();
        if (activationStatus == null) {
            // In case activation status is not specified, consider all statuses
            statuses.addAll(Arrays.asList(ActivationStatus.values()));
        } else {
            statuses.add(activationStatus);
        }
        List<ActivationRecordEntity> activationsList = activationRepository.lookupActivations(userIds, applicationIds, timestampLastUsedBefore, timestampLastUsedAfter, statuses);
        if (activationsList.isEmpty()) {
            return response;
        }

        List<ActivationRecordEntity> filteredActivationList = new ArrayList<>();
        // Filter activation by activation flags in case they are specified
        if (activationFlags != null && !activationFlags.isEmpty()) {
            List<ActivationRecordEntity> activationsWithFlags = activationsList.stream().filter(activation ->
                    activation.getFlags().containsAll(activationFlags)).collect(Collectors.toList());
            filteredActivationList.addAll(activationsWithFlags);
        } else {
            filteredActivationList.addAll(activationsList);
        }

        for (ActivationRecordEntity activation : filteredActivationList) {
            // Map between database object and service objects
            LookupActivationsResponse.Activations activationServiceItem = new LookupActivationsResponse.Activations();
            activationServiceItem.setActivationId(activation.getActivationId());
            activationServiceItem.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            activationServiceItem.setBlockedReason(activation.getBlockedReason());
            activationServiceItem.setActivationName(activation.getActivationName());
            activationServiceItem.setExtras(activation.getExtras());
            activationServiceItem.setPlatform(activation.getPlatform());
            activationServiceItem.setDeviceInfo(activation.getDeviceInfo());
            activationServiceItem.getActivationFlags().addAll(activation.getFlags());
            activationServiceItem.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampCreated()));
            activationServiceItem.setTimestampLastUsed(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastUsed()));
            activationServiceItem.setTimestampLastChange(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastChange()));
            activationServiceItem.setUserId(activation.getUserId());
            activationServiceItem.setApplicationId(activation.getApplication().getId());
            activationServiceItem.setApplicationName(activation.getApplication().getName());
            // Unknown version is converted to 0 in SOAP
            activationServiceItem.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
            response.getActivations().add(activationServiceItem);
        }

        return response;
    }

    /**
     * Update status for activations.
     * @param activationIds Identifiers of activations to update.
     * @param activationStatus Activation status to use.
     * @return Response with indication whether status update succeeded.
     */
    public UpdateStatusForActivationsResponse updateStatusForActivation(List<String> activationIds, ActivationStatus activationStatus) {
        final UpdateStatusForActivationsResponse response = new UpdateStatusForActivationsResponse();
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        activationIds.forEach(activationId -> {
            ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
            if (!activation.getActivationStatus().equals(activationStatus)) {
                // Update activation status, persist change and notify callback listeners
                activation.setActivationStatus(activationStatus);
                activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
                callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
            }
        });

        response.setUpdated(true);

        return response;
    }

    /**
     * Get activation status for given activation ID
     *
     * @param activationId           Activation ID
     * @param challenge              Challenge for activation status blob encryption (since protocol V3.1)
     * @param keyConversionUtilities Key conversion utility class
     * @return Activation status response
     * @throws DatatypeConfigurationException Thrown when calendar conversion fails.
     * @throws GenericServiceException        Thrown when cryptography error occurs.
     */
    public GetActivationStatusResponse getActivationStatus(String activationId, String challenge, KeyConvertor keyConversionUtilities) throws DatatypeConfigurationException, GenericServiceException {
        try {
            // Generate timestamp in advance
            final Date timestamp = new Date();

            // Get the repository
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();

            // Prepare key generator
            final KeyGenerator keyGenerator = new KeyGenerator();

            ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId);

            // Check if the activation exists
            if (activation != null) {

                // Deactivate old pending activations first
                deactivatePendingActivation(timestamp, activation, false);

                // Handle CREATED activation
                if (activation.getActivationStatus() == io.getlime.security.powerauth.app.server.database.model.ActivationStatus.CREATED) {

                    // Created activations are not able to transfer valid status blob to the client
                    // since both keys were not exchanged yet and transport cannot be secured.
                    byte[] randomStatusBlob = keyGenerator.generateRandomBytes(32);
                    // Use random nonce in case that challenge was provided.
                    String randomStatusBlobNonce = challenge == null ? null : BaseEncoding.base64().encode(keyGenerator.generateRandomBytes(16));

                    // Activation signature
                    MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(activation.getApplication().getId());
                    if (masterKeyPairEntity == null) {
                        logger.error("Missing key pair for application ID: {}", activation.getApplication().getId());
                        // Rollback is not required, database is not used for writing
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
                    response.setActivationOtpValidation(activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setActivationName(activation.getActivationName());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(activation.getApplication().getId());
                    response.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampCreated()));
                    response.setTimestampLastUsed(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastUsed()));
                    response.setTimestampLastChange(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastChange()));
                    response.setEncryptedStatusBlob(BaseEncoding.base64().encode(randomStatusBlob));
                    response.setEncryptedStatusBlobNonce(randomStatusBlobNonce);
                    response.setActivationCode(activation.getActivationCode());
                    response.setActivationSignature(BaseEncoding.base64().encode(activationSignature));
                    response.setDevicePublicKeyFingerprint(null);
                    response.setPlatform(activation.getPlatform());
                    response.setDeviceInfo(activation.getDeviceInfo());
                    response.getActivationFlags().addAll(activation.getFlags());
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
                    EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
                    final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
                    String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);

                    // If an activation was turned to REMOVED directly from CREATED state,
                    // there is not device public key in the database - we need to handle
                    // that case by defaulting the encryptedStatusBlob to random value...
                    byte[] encryptedStatusBlob = keyGenerator.generateRandomBytes(32);
                    String encryptedStatusBlobNonce = null;

                    // Prepare a value for the device public key fingerprint
                    String activationFingerPrint = null;

                    // There is a device public key available, therefore we can compute
                    // the real encryptedStatusBlob value.
                    if (devicePublicKeyBase64 != null) {

                        PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(serverPrivateKeyBase64));
                        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(devicePublicKeyBase64));
                        PublicKey serverPublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));

                        SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                        SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);

                        String ctrDataBase64 = activation.getCtrDataBase64();
                        byte[] ctrDataHashForStatusBlob;
                        if (ctrDataBase64 != null) {
                            // In crypto v3 counter data is stored with activation. We have to calculate hash from
                            // the counter value, before it's encoded into the status blob. The value might be replaced
                            // in `encryptedStatusBlob()` function that injects random data, depending on the version
                            // of the status blob encryption.
                            final byte[] ctrData = BaseEncoding.base64().decode(ctrDataBase64);
                            ctrDataHashForStatusBlob = powerAuthServerActivation.calculateHashFromHashBasedCounter(ctrData, transportKey);
                        } else {
                            // In crypto v2 counter data is not present, so use an array of zero bytes. This might be
                            // replaced in `encryptedStatusBlob()` function that injects random data automatically,
                            // depending on the version of the status blob encryption.
                            ctrDataHashForStatusBlob = new byte[16];
                        }
                        byte[] statusChallenge;
                        byte[] statusNonce;
                        if (challenge != null) {
                            // If challenge is present, then also generate a new nonce. Protocol V3.1+
                            statusChallenge = BaseEncoding.base64().decode(challenge);
                            statusNonce = keyGenerator.generateRandomBytes(16);
                            encryptedStatusBlobNonce = BaseEncoding.base64().encode(statusNonce);
                        } else {
                            // Older protocol versions, where IV derivation is not available.
                            statusChallenge = null;
                            statusNonce = null;
                        }

                        // Encrypt the status blob
                        ActivationStatusBlobInfo statusBlobInfo = new ActivationStatusBlobInfo();
                        statusBlobInfo.setActivationStatus(activation.getActivationStatus().getByte());
                        statusBlobInfo.setCurrentVersion(activation.getVersion().byteValue());
                        statusBlobInfo.setUpgradeVersion(POWERAUTH_PROTOCOL_VERSION);
                        statusBlobInfo.setFailedAttempts(activation.getFailedAttempts().byteValue());
                        statusBlobInfo.setMaxFailedAttempts(activation.getMaxFailedAttempts().byteValue());
                        statusBlobInfo.setCtrLookAhead((byte)powerAuthServiceConfiguration.getSignatureValidationLookahead());
                        statusBlobInfo.setCtrByte(activation.getCounter().byteValue());
                        statusBlobInfo.setCtrDataHash(ctrDataHashForStatusBlob);
                        encryptedStatusBlob = powerAuthServerActivation.encryptedStatusBlob(statusBlobInfo, statusChallenge, statusNonce, transportKey);

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
                                // Rollback is not required, database is not used for writing
                                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
                        }

                    }

                    // return the data
                    GetActivationStatusResponse response = new GetActivationStatusResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    response.setActivationOtpValidation(activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setActivationName(activation.getActivationName());
                    response.setUserId(activation.getUserId());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(activation.getApplication().getId());
                    response.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampCreated()));
                    response.setTimestampLastUsed(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastUsed()));
                    response.setTimestampLastChange(XMLGregorianCalendarConverter.convertFrom(activation.getTimestampLastChange()));
                    response.setEncryptedStatusBlob(BaseEncoding.base64().encode(encryptedStatusBlob));
                    response.setEncryptedStatusBlobNonce(encryptedStatusBlobNonce);
                    response.setActivationCode(null);
                    response.setActivationSignature(null);
                    response.setDevicePublicKeyFingerprint(activationFingerPrint);
                    response.setPlatform(activation.getPlatform());
                    response.setDeviceInfo(activation.getDeviceInfo());
                    response.getActivationFlags().addAll(activation.getFlags());
                    // Unknown version is converted to 0 in SOAP
                    response.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                    return response;

                }
            } else {

                // Activations that do not exist should return REMOVED state and
                // a random status blob
                byte[] randomStatusBlob = keyGenerator.generateRandomBytes(32);
                // Use random nonce in case that challenge was provided.
                String randomStatusBlobNonce = challenge == null ? null : BaseEncoding.base64().encode(keyGenerator.generateRandomBytes(16));

                // Generate date
                XMLGregorianCalendar zeroDate = XMLGregorianCalendarConverter.convertFrom(new Date(0));

                // return the data
                GetActivationStatusResponse response = new GetActivationStatusResponse();
                response.setActivationId(activationId);
                response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.REMOVED));
                response.setActivationOtpValidation(ActivationOtpValidation.NONE);
                response.setBlockedReason(null);
                response.setActivationName("unknown");
                response.setUserId("unknown");
                response.setApplicationId(0L);
                response.setExtras(null);
                response.setPlatform(null);
                response.setDeviceInfo(null);
                // Initialize empty flags
                response.getActivationFlags();
                response.setTimestampCreated(zeroDate);
                response.setTimestampLastUsed(zeroDate);
                response.setTimestampLastChange(null);
                response.setEncryptedStatusBlob(BaseEncoding.base64().encode(randomStatusBlob));
                response.setEncryptedStatusBlobNonce(randomStatusBlobNonce);
                response.setActivationCode(null);
                response.setActivationSignature(null);
                response.setDevicePublicKeyFingerprint(null);
                // Use 0 as version when version is undefined
                response.setVersion(0L);
                return response;
            }
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            /// Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
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
     * @param activationOtpValidation   Activation OTP validation mode
     * @param activationOtp             Activation OTP
     * @return Response with activation initialization data
     * @throws GenericServiceException If invalid values are provided.
     */
    public InitActivationResponse initActivation(Long applicationId, String userId, Long maxFailureCount, Date activationExpireTimestamp,
                                                 ActivationOtpValidation activationOtpValidation, String activationOtp,
                                                 KeyConvertor keyConversionUtilities) throws GenericServiceException {
        try {
            // Generate timestamp in advance
            final Date timestamp = new Date();

            if (userId == null || userId.isEmpty() || userId.length() > 255) {
                logger.warn("User ID not specified or invalid");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_USER_ID);
            }

            if (applicationId == 0L) {
                logger.warn("Application ID not specified");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_APPLICATION_ID);
            }

            // Application version is not being checked in initActivation, it is checked later in prepareActivation or createActivation.

            // Get the repository
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();

            // Get number of max attempts from request or from constants, if not provided
            Long maxAttempt = maxFailureCount;
            if (maxAttempt == null) { // use the default value
                maxAttempt = powerAuthServiceConfiguration.getSignatureMaxFailedAttempts();
            } else if (maxFailureCount <= 0) { // only allow custom values > 0
                logger.warn("Activation cannot be created with the specified properties: maxFailureCount");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_CREATE_FAILED);
            }

            // Get activation expiration date from request or from constants, if not provided
            Date timestampExpiration = activationExpireTimestamp;
            if (timestampExpiration == null) {
                timestampExpiration = new Date(timestamp.getTime() + powerAuthServiceConfiguration.getActivationValidityBeforeActive());
            }

            // Validate combination of activation OTP and OTP validation mode.
            final boolean hasActivationOtp = activationOtp != null && !activationOtp.isEmpty();
            if (activationOtpValidation == null) {
                activationOtpValidation = ActivationOtpValidation.NONE;
            }
            if ((activationOtpValidation == ActivationOtpValidation.NONE && hasActivationOtp) ||
                    (activationOtpValidation != ActivationOtpValidation.NONE && !hasActivationOtp)) {
                logger.warn("Activation OTP doesn't match its validation mode.");
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            // Generate hash from activation OTP
            final String activationOtpHash = activationOtp == null ? null : PasswordHash.hash(activationOtp.getBytes(StandardCharsets.UTF_8));

            // Fetch the latest master private key
            MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
            if (masterKeyPair == null) {
                GenericServiceException ex = localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                // Rollback is not required, error occurs before writing to database
                logger.error("No master key pair found for application ID: {}", applicationId);
                throw ex;
            }
            byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterKeyPair.getMasterKeyPrivateBase64());
            PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);

            // Generate new activation data, generate a unique activation ID
            String activationId = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationIdIterations(); i++) {
                String tmpActivationId = powerAuthServerActivation.generateActivationId();
                Long activationCount = activationRepository.getActivationCount(tmpActivationId);
                if (activationCount == 0) {
                    activationId = tmpActivationId;
                    break;
                } // ... else this activation ID has a collision, reset it and try to find another one
            }
            if (activationId == null) {
                logger.error("Unable to generate activation ID");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_ID);
            }

            // Generate a unique activation code
            String activationCode = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationCodeIterations(); i++) {
                String tmpActivationCode = powerAuthServerActivation.generateActivationCode();
                Long activationCount = activationRepository.getActivationCountByActivationCode(applicationId, tmpActivationCode);
                // Check that the temporary short activation ID is unique, otherwise generate a different activation code
                if (activationCount == 0) {
                    activationCode = tmpActivationCode;
                    break;
                }
            }
            if (activationCode == null) {
                logger.error("Unable to generate activation code");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE);
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
            activation.setActivationOtpValidation(activationOtpValidationConverter.convertTo(activationOtpValidation));
            activation.setActivationOtp(activationOtpHash);
            activation.setActivationName(null);
            activation.setActivationStatus(ActivationStatus.CREATED);
            activation.setCounter(0L);
            activation.setCtrDataBase64(null);
            activation.setDevicePublicKeyBase64(null);
            activation.setExtras(null);
            activation.setPlatform(null);
            activation.setDeviceInfo(null);
            activation.setFailedAttempts(0L);
            activation.setApplication(masterKeyPair.getApplication());
            activation.setMasterKeyPair(masterKeyPair);
            activation.setMaxFailedAttempts(maxAttempt);
            activation.setServerPublicKeyBase64(BaseEncoding.base64().encode(serverKeyPublicBytes));
            activation.setTimestampActivationExpire(timestampExpiration);
            activation.setTimestampCreated(timestamp);
            activation.setTimestampLastUsed(timestamp);
            activation.setTimestampLastChange(null);
            // Activation version is not known yet
            activation.setVersion(null);
            activation.setUserId(userId);

            // Convert server private key to DB columns serverPrivateKeyEncryption specifying encryption mode and serverPrivateKey with base64-encoded key.
            ServerPrivateKey serverPrivateKey = serverPrivateKeyConverter.toDBValue(serverKeyPrivateBytes, userId, activationId);
            activation.setServerPrivateKeyEncryption(serverPrivateKey.getEncryptionMode());
            activation.setServerPrivateKeyBase64(serverPrivateKey.getServerPrivateKeyBase64());

            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

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
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Prepare activation with given parameters.
     *
     * <p><b>PowerAuth protocol versions:</b>
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
    public PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, EciesCryptogram eciesCryptogram, KeyConvertor keyConversion) throws GenericServiceException {
        try {
            // Get current timestamp
            final Date timestamp = new Date();

            // Get required repositories
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            // Find application by application key
            ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, activation code: {}", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }
            ApplicationEntity application = applicationVersion.getApplication();
            if (application == null) {
                logger.warn("Application does not exist, activation code: {}", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Get master server private key
            MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
            if (masterKeyPairEntity == null) {
                logger.error("Missing key pair for application ID: {}", application.getId());
                // Rollback is not required, error occurs before writing to database
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
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Fetch the current activation by activation code
            Set<ActivationStatus> states = ImmutableSet.of(ActivationStatus.CREATED);
            // Search for activation without lock to avoid potential deadlocks
            ActivationRecordEntity activation = activationRepository.findCreatedActivationWithoutLock(application.getId(), activationCode, states, timestamp);

            // Make sure to deactivate the activation if it is expired
            if (activation == null) {
                logger.warn("Activation with activation code: {} could not be obtained. It either does not exist or it already expired.", activationCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Search for activation again to acquire PESSIMISTIC_WRITE lock for activation row
            activation = activationRepository.findActivationWithLock(activation.getActivationId());
            deactivatePendingActivation(timestamp, activation, true);

            // Validate that the activation is in correct state for the prepare step
            validateCreatedActivation(activation, application, false);
            // Validate activation OTP
            validateActivationOtp(ActivationOtpValidation.ON_KEY_EXCHANGE, request.getActivationOtp(), activation, null);

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

            // If Activation OTP is available, then the status is set directly to "ACTIVE".
            // We don't need to commit such activation afterwards.
            final boolean isActive = request.getActivationOtp() != null;
            final ActivationStatus activationStatus = isActive ? ActivationStatus.ACTIVE : ActivationStatus.PENDING_COMMIT;

            // Update the activation record
            activation.setActivationStatus(activationStatus);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(request.getActivationName());
            activation.setExtras(request.getExtras());
            if (request.getPlatform() != null) {
                activation.setPlatform(request.getPlatform().toLowerCase());
            } else {
                activation.setPlatform("unknown");
            }
            activation.setDeviceInfo(request.getDeviceInfo());
            // PowerAuth protocol version 3.0 uses 0x3 as version in activation status
            activation.setVersion(3);
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);

            // Create a new recovery code and PUK for new activation if activation recovery is enabled.
            // Perform these operations before writing to database to avoid rollbacks.
            ActivationRecovery activationRecovery = null;
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(application.getId());
            if (recoveryConfigEntity != null && recoveryConfigEntity.getActivationRecoveryEnabled()) {
                activationRecovery = createRecoveryCodeForActivation(activation, isActive);
            }

            // Generate activation layer 2 response
            ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);
            layer2Response.setServerPublicKey(activation.getServerPublicKeyBase64());
            if (activationRecovery != null) {
                layer2Response.setActivationRecovery(activationRecovery);
            }
            byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            EciesCryptogram responseCryptogram = eciesDecryptor.encryptResponse(responseData);
            String encryptedData = BaseEncoding.base64().encode(responseCryptogram.getEncryptedData());
            String mac = BaseEncoding.base64().encode(responseCryptogram.getMac());

            // Persist activation report and notify listeners
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Generate encrypted response
            PrepareActivationResponse encryptedResponse = new PrepareActivationResponse();
            encryptedResponse.setActivationId(activation.getActivationId());
            encryptedResponse.setUserId(activation.getUserId());
            encryptedResponse.setApplicationId(application.getId());
            encryptedResponse.setEncryptedData(encryptedData);
            encryptedResponse.setMac(mac);
            encryptedResponse.setActivationStatus(activationStatusConverter.convert(activationStatus));
            return encryptedResponse;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException | JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Create activation with given parameters.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param userId                         User ID
     * @param activationExpireTimestamp      Timestamp after which activation can no longer be completed
     * @param maxFailureCount                Maximum failed attempt count (default = 5)
     * @param applicationKey                 Application key
     * @param eciesCryptogram                ECIES cryptogram
     * @param keyConversion                  Utility class for key conversion
     * @param activationOtp                  Additional activation OTP
     * @return ECIES encrypted activation information
     * @throws GenericServiceException       In case create activation fails
     */
    public CreateActivationResponse createActivation(
            String userId,
            Date activationExpireTimestamp,
            Long maxFailureCount,
            String applicationKey,
            EciesCryptogram eciesCryptogram,
            String activationOtp,
            KeyConvertor keyConversion) throws GenericServiceException {
        try {
            // Get current timestamp
            final Date timestamp = new Date();

            // Get required repositories
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

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

            // Prepare activation OTP mode
            final ActivationOtpValidation activationOtpValidation = activationOtp != null ? ActivationOtpValidation.ON_COMMIT : ActivationOtpValidation.NONE;

            // Create an activation record and obtain the activation database record
            InitActivationResponse initResponse = this.initActivation(application.getId(), userId, maxFailureCount, activationExpireTimestamp, activationOtpValidation, activationOtp, keyConversion);
            String activationId = initResponse.getActivationId();
            ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);

            if (activation == null) { // should not happen, activation was just created above via "init" call
                logger.warn("Activation not found for activation ID: {}", activationId);
                // The whole transaction is rolled back in case of this unexpected state
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Make sure to deactivate the activation if it is expired
            deactivatePendingActivation(timestamp, activation, true);

            validateCreatedActivation(activation, application, true);

            // Get master server private key
            MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
            if (masterKeyPairEntity == null) {
                logger.error("Missing key pair for application ID: {}", application.getId());
                // Master key pair is missing, rollback this transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
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
                // Activation failed due to invalid ECIES request, rollback transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Extract the device public key from request
            byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(request.getDevicePublicKey());
            PublicKey devicePublicKey;

            try {
                devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                logger.warn("Device public key is invalid, activation ID: {}", activationId);
                // Device public key is invalid, rollback this transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Initialize hash based counter
            HashBasedCounter counter = new HashBasedCounter();
            byte[] ctrData = counter.init();
            String ctrDataBase64 = BaseEncoding.base64().encode(ctrData);

            // Update and persist the activation record
            activation.setActivationStatus(ActivationStatus.PENDING_COMMIT);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(request.getActivationName());
            activation.setExtras(request.getExtras());
            if (request.getPlatform() != null) {
                activation.setPlatform(request.getPlatform().toLowerCase());
            } else {
                activation.setPlatform("unknown");
            }
            activation.setDeviceInfo(request.getDeviceInfo());
            // PowerAuth protocol version 3.0 uses 0x3 as version in activation status
            activation.setVersion(3);
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Create a new recovery code and PUK for new activation if activation recovery is enabled
            ActivationRecovery activationRecovery = null;
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(application.getId());
            if (recoveryConfigEntity != null && recoveryConfigEntity.getActivationRecoveryEnabled()) {
                activationRecovery = createRecoveryCodeForActivation(activation, false);
            }

            // Generate activation layer 2 response
            ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);
            layer2Response.setServerPublicKey(activation.getServerPublicKeyBase64());
            if (activationRecovery != null) {
                layer2Response.setActivationRecovery(activationRecovery);
            }
            byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            EciesCryptogram responseCryptogram = eciesDecryptor.encryptResponse(responseData);
            String encryptedData = BaseEncoding.base64().encode(responseCryptogram.getEncryptedData());
            String mac = BaseEncoding.base64().encode(responseCryptogram.getMac());

            // Generate encrypted response
            CreateActivationResponse encryptedResponse = new CreateActivationResponse();
            encryptedResponse.setActivationId(activation.getActivationId());
            encryptedResponse.setUserId(activation.getUserId());
            encryptedResponse.setApplicationId(application.getId());
            encryptedResponse.setEncryptedData(encryptedData);
            encryptedResponse.setMac(mac);
            encryptedResponse.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            return encryptedResponse;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException | JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.DECRYPTION_FAILED);
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

    /**
     * Commit activation with given ID.
     *
     * @param activationId Activation ID.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @param activationOtp Activation OTP.
     * @return Response with activation commit confirmation.
     * @throws GenericServiceException In case invalid data is provided or activation is not found, in invalid state or already expired.
     */
    public CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) throws GenericServiceException {

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // Find activation
        ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
        if (activation == null) {
            // Activation does not exist
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // Get current timestamp
        final Date timestamp = new Date();

        // Check already deactivated activation
        deactivatePendingActivation(timestamp, activation, true);
        if (activation.getActivationStatus() == ActivationStatus.REMOVED) {
            logger.info("Activation is already REMOVED, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }

        // Check whether Activation is in correct state
        if (activation.getActivationStatus() != ActivationStatus.PENDING_COMMIT) {
            logger.info("Activation is not in PENDING_COMMIT state during commit, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }

        // Validate activation OTP
        validateActivationOtp(ActivationOtpValidation.ON_COMMIT, activationOtp, activation, externalUserId);

        // Change activation state to ACTIVE
        activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.ACTIVE);
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

        // Update recovery code status in case a related recovery code exists in CREATED state
        RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
        List<RecoveryCodeEntity> recoveryCodeEntities = recoveryCodeRepository.findAllByApplicationIdAndActivationId(activation.getApplication().getId(), activation.getActivationId());
        for (RecoveryCodeEntity recoveryCodeEntity : recoveryCodeEntities) {
            if (RecoveryCodeStatus.CREATED.equals(recoveryCodeEntity.getStatus())) {
                recoveryCodeEntity.setStatus(RecoveryCodeStatus.ACTIVE);
                recoveryCodeEntity.setTimestampLastChange(new Date());
                recoveryCodeRepository.save(recoveryCodeEntity);
            }
        }

        CommitActivationResponse response = new CommitActivationResponse();
        response.setActivationId(activationId);
        response.setActivated(true);
        return response;
    }

    /**
     * Update activation OTP for given activation ID.
     *
     * @param activationId Activation ID.
     * @param externalUserId User ID of user who committed the activation. Use null value if activation owner caused the change.
     * @param activationOtp Activation OTP.
     * @return Response with activation UTP update result.
     * @throws GenericServiceException In case invalid data is provided or activation is not found, in invalid state or already expired.
     */
    public UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp) throws GenericServiceException {

        // Validate provided OTP
        if (activationOtp == null || activationOtp.isEmpty()) {
            logger.warn("Activation OTP not specified in update");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        // Get the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();

        // Find activation
        ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
        if (activation == null) {
            // Activation does not exist
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // Get current timestamp
        final Date timestamp = new Date();

        // Check already deactivated activation
        deactivatePendingActivation(timestamp, activation, true);

        // Check activation state
        if (activation.getActivationStatus() != ActivationStatus.PENDING_COMMIT) {
            logger.info("Activation is not in PENDING_COMMIT state during commit, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }

        // Check OTP validation mode
         if (activation.getActivationOtpValidation() == io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation.ON_KEY_EXCHANGE) {
            logger.info("Activation OTP update is not allowed for ON_KEY_EXCHANGE mode. Activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP_MODE);
        }

        final String activationOtpHash;
        try {
            activationOtpHash = PasswordHash.hash(activationOtp.getBytes(StandardCharsets.UTF_8));
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }

        // Change activation OTP and set mode to ON_COMMIT
        activation.setActivationOtp(activationOtpHash);
        activation.setActivationOtpValidation(io.getlime.security.powerauth.app.server.database.model.ActivationOtpValidation.ON_COMMIT);

        // Save activation record
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId, AdditionalInformation.ACTIVATION_OTP_VALUE_UPDATE);
        callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

        UpdateActivationOtpResponse response = new UpdateActivationOtpResponse();
        response.setActivationId(activationId);
        response.setUpdated(true);
        return response;
    }

    /**
     * Validate activation OTP against value set in the activation's record.
     *
     * @param currentStage      Determines in which step of the activation is this method called.
     * @param confirmationOtp   OTP value to be validated.
     * @param activation        Activation record.
     * @param externalUserId    User ID of user who is performing this validation. Use null value if activation owner caused the change.
     * @throws GenericServiceException In case invalid data is provided or activation OTP is invalid.
     */
    private void validateActivationOtp(ActivationOtpValidation currentStage, String confirmationOtp, ActivationRecordEntity activation, String externalUserId) throws GenericServiceException {

        final String activationId = activation.getActivationId();
        final ActivationOtpValidation expectedStage = activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation());
        final String expectedOtpHash = activation.getActivationOtp();

        if (currentStage == ActivationOtpValidation.NONE) {
            // This should never happen.
            logger.info("Internal error in activation OTP validation: {}", activationId);
            // Rollback is not required, database is not used for writing yet.
            throw localizationProvider.buildExceptionForCode(ServiceError.UNKNOWN_ERROR);
        }

        // Check whether activation OTP validation is turned OFF. In this case, the confirmation OTP must not
        // be provided.
        if (expectedStage == ActivationOtpValidation.NONE) {
            if (confirmationOtp != null) {
                logger.info("Activation OTP is not used, but is provided: {}", activationId);
                // Rollback is not required, database is not used for writing yet.
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
            }
            return;
        }
        // Check whether this is validation in the different step of activation. If yes, then the confirmation
        // OTP must not be provided.
        if (expectedStage != currentStage) {
            if (confirmationOtp != null) {
                logger.info("Activation OTP is not expected, but is provided: {}", activationId);
                // Rollback is not required, database is not used for writing yet.
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
            }
            return;
        }
        // We're in the right step, so the confirmation OTP must be provided.
        if (confirmationOtp == null) {
            logger.info("Activation OTP is expected, but is missing: {}", activationId);
            // Rollback is not required, database is not used for writing yet.
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
        }
        // The final test only checks, whether hash is present in the database.
        if (expectedOtpHash == null) {
            logger.info("Activation OTP is missing in activation data: {}", activationId);
            // Rollback is not required, database is not used for writing yet.
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
        }

        // Now verify OTP value
        try {
            if (PasswordHash.verify(confirmationOtp.getBytes(StandardCharsets.UTF_8), expectedOtpHash)) {
                // Everything looks fine. Reset the failed attempts counter.
                activation.setFailedAttempts(0L);
                return;
            }
        } catch (IOException e) {
            // This exception typically means that the hash stored in DB is in wrong format. The rest of this method
            // will treat this as an invalid OTP.
            logger.warn("Invalid activation OTP hash: {}", activationId);
        }

        // Confirmation OTP doesn't match value stored in the database.

        // Increase the number of failed attempts and validate the maximum number of failed attempts.
        activation.setFailedAttempts(activation.getFailedAttempts() + 1L);
        final boolean removeActivation = activation.getFailedAttempts() >= activation.getMaxFailedAttempts();

        // If activation should be removed then set its status to REMOVED.
        if (removeActivation) {
            activation.setActivationStatus(ActivationStatus.REMOVED);
        }

        // Save activation state with the reason.
        final String activationSaveReason = removeActivation ? AdditionalInformation.ACTIVATION_OTP_MAX_FAILED_ATTEMPTS : AdditionalInformation.ACTIVATION_OTP_FAILED_ATTEMPT;
        activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId, activationSaveReason);

        // Also notify the listeners in case that the state of the activation was changed.
        if (removeActivation) {
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        }

        // ...and finally throw an exception.
        logger.info("Invalid activation OTP: {}", activationId);
        // Exception must not be rollbacking, otherwise data written to database in this method would be lost.
        throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_ACTIVATION_OTP);
    }

    /**
     * Remove activation with given ID.
     *
     * @param activationId Activation ID.
     * @param externalUserId User ID of user who removed the activation. Use null value if activation owner caused the change.
     * @param revokeRecoveryCodes Flag that indicates if a recover codes associated with this activation should be also revoked.
     * @return Response with confirmation of removal.
     * @throws GenericServiceException In case activation does not exist.
     */
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId, boolean revokeRecoveryCodes) throws GenericServiceException {
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);
        if (activation != null) { // does the record even exist?
            activation.setActivationStatus(io.getlime.security.powerauth.app.server.database.model.ActivationStatus.REMOVED);
            if (revokeRecoveryCodes) {
                final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
                final List<RecoveryCodeEntity> recoveryCodeEntities = recoveryCodeRepository.findAllByActivationId(activationId);
                final Date now = new Date();
                for (RecoveryCodeEntity recoveryCode : recoveryCodeEntities) {
                    // revoke only codes that are not yet revoked, to avoid messing up with timestamp
                    if (!RecoveryCodeStatus.REVOKED.equals(recoveryCode.getStatus())) {
                        recoveryCode.setStatus(RecoveryCodeStatus.REVOKED);
                        recoveryCode.setTimestampLastChange(now);
                        // Change status of PUKs with status VALID to INVALID
                        for (RecoveryPukEntity puk : recoveryCode.getRecoveryPuks()) {
                            if (RecoveryPukStatus.VALID.equals(puk.getStatus())) {
                                puk.setStatus(RecoveryPukStatus.INVALID);
                                puk.setTimestampLastChange(now);
                            }
                        }
                        recoveryCodeRepository.save(recoveryCode);
                    }
                }
            }
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
            RemoveActivationResponse response = new RemoveActivationResponse();
            response.setActivationId(activationId);
            response.setRemoved(true);
            return response;
        } else {
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
    }

    /**
     * Block activation with given ID
     *
     * @param activationId Activation ID
     * @param reason Reason why activation is being blocked.
     * @param externalUserId User ID of user who blocked the activation. Use null value if activation owner caused the change.
     * @return Response confirming that activation was blocked
     * @throws GenericServiceException In case activation does not exist.
     */
    public BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) throws GenericServiceException {
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);
        if (activation == null) {
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // does the record even exist, is it in correct state?
        // early null check done above, no null check needed here
        if (activation.getActivationStatus().equals(ActivationStatus.ACTIVE)) {
            activation.setActivationStatus(ActivationStatus.BLOCKED);
            if (reason == null) {
                activation.setBlockedReason(AdditionalInformation.BLOCKED_REASON_NOT_SPECIFIED);
            } else {
                activation.setBlockedReason(reason);
            }
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        } else if (!activation.getActivationStatus().equals(ActivationStatus.BLOCKED)) {
            // In case activation status is not ACTIVE or BLOCKED, throw an exception
            logger.info("Activation cannot be blocked due to invalid status, activation ID: {}, status: {}", activationId, activation.getActivationStatus());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
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
     * @param externalUserId User ID of user who unblocked the activation. Use null value if activation owner caused the change.
     * @return Response confirming that activation was unblocked
     * @throws GenericServiceException In case activation does not exist.
     */
    public UnblockActivationResponse unblockActivation(String activationId, String externalUserId) throws GenericServiceException {
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);
        if (activation == null) {
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // does the record even exist, is it in correct state?
        // early null check done above, no null check needed here
        if (activation.getActivationStatus().equals(ActivationStatus.BLOCKED)) {
            // Update and store new activation
            activation.setActivationStatus(ActivationStatus.ACTIVE);
            activation.setBlockedReason(null);
            activation.setFailedAttempts(0L);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation, externalUserId);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);
        } else if (!activation.getActivationStatus().equals(ActivationStatus.ACTIVE)) {
            // In case activation status is not BLOCKED or ACTIVE, throw an exception
            logger.info("Activation cannot be unblocked due to invalid status, activation ID: {}, status: {}", activationId, activation.getActivationStatus());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }
        UnblockActivationResponse response = new UnblockActivationResponse();
        response.setActivationId(activationId);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        return response;
    }


    /**
     * Create activation using recovery code.
     * @param request Create activation using recovery code request.
     * @return Create activation using recovery code response.
     * @throws GenericServiceException In case of any error.
     */
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request, KeyConvertor keyConversion) throws GenericServiceException {
        try {
            // Extract request data
            final String recoveryCode = request.getRecoveryCode();
            final String puk = request.getPuk();
            final String applicationKey = request.getApplicationKey();
            final Long maxFailureCount = request.getMaxFailureCount();
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();
            final String activationOtp = request.getActivationOtp();

            // Prepare ECIES request cryptogram
            byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKey);
            byte[] encryptedDataBytes = BaseEncoding.base64().decode(encryptedData);
            byte[] macBytes = BaseEncoding.base64().decode(mac);
            byte[] nonceBytes = request.getNonce() != null ? BaseEncoding.base64().decode(request.getNonce()) : null;
            final EciesCryptogram eciesCryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes, nonceBytes);

            // Prepare repositories
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();
            final ApplicationVersionRepository applicationVersionRepository = repositoryCatalogue.getApplicationVersionRepository();
            final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
            final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

            // Find application by application key
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ApplicationEntity application = applicationVersion.getApplication();
            if (application == null) {
                logger.warn("Application does not exist, application key: {}", applicationKey);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Check whether activation recovery is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(application.getId());
            if (recoveryConfigEntity == null || !recoveryConfigEntity.getActivationRecoveryEnabled()) {
                logger.warn("Activation recovery is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Get master server private key
            MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
            if (masterKeyPairEntity == null) {
                logger.error("Missing key pair for application ID: {}", application.getId());
                // Rollback is not required, error occurs before writing to database
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
            ActivationLayer2Request layer2Request;
            try {
                layer2Request = objectMapper.readValue(activationData, ActivationLayer2Request.class);
            } catch (IOException ex) {
                logger.warn("Invalid activation request, recovery code: {}", recoveryCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Get recovery code entity
            RecoveryCodeEntity recoveryCodeEntity = recoveryCodeRepository.findByApplicationIdAndRecoveryCode(application.getId(), recoveryCode);
            if (recoveryCodeEntity == null) {
                logger.warn("Recovery code does not exist: {}", recoveryCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (!io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.ACTIVE.equals(recoveryCodeEntity.getStatus())) {
                logger.warn("Recovery code is not in ACTIVE state: {}", recoveryCode);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Verify recovery PUK
            boolean pukValid = false;
            RecoveryPukEntity pukUsedDuringActivation = null;
            RecoveryPukEntity firstValidPuk = null;
            List<RecoveryPukEntity> recoveryPukEntities = recoveryCodeEntity.getRecoveryPuks();
            for (RecoveryPukEntity recoveryPukEntity: recoveryPukEntities) {
                if (RecoveryPukStatus.VALID.equals(recoveryPukEntity.getStatus())) {
                    if (firstValidPuk == null) {
                        firstValidPuk = recoveryPukEntity;
                        // First valid PUK found, verify PUK hash
                        byte[] pukBytes = puk.getBytes(StandardCharsets.UTF_8);
                        String pukValueFromDB = recoveryPukEntity.getPuk();
                        EncryptionMode encryptionMode = recoveryPukEntity.getPukEncryption();
                        RecoveryPuk recoveryPuk = new RecoveryPuk(encryptionMode, pukValueFromDB);
                        String pukHash = recoveryPukConverter.fromDBValue(recoveryPuk, application.getId(), recoveryCodeEntity.getUserId(), recoveryCode, recoveryPukEntity.getPukIndex());
                        try {
                            if (PasswordHash.verify(pukBytes, pukHash)) {
                                pukValid = true;
                                pukUsedDuringActivation = recoveryPukEntity;
                                break;
                            }
                        } catch (IOException ex) {
                            logger.warn("Invalid PUK hash for recovery code: {}", recoveryCode);
                            // Rollback is not required, error occurs before writing to database
                            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                        }
                    }
                }
            }
            if (!pukValid) {
                // Log invalid PUK on info level, this may be a common user error
                logger.info("Received invalid recovery PUK for recovery code: {}", recoveryCodeEntity.getRecoveryCodeMasked());
                // Increment failed count
                recoveryCodeEntity.setFailedAttempts(recoveryCodeEntity.getFailedAttempts() + 1);
                recoveryCodeEntity.setTimestampLastChange(new Date());
                if (recoveryCodeEntity.getFailedAttempts() >= recoveryCodeEntity.getMaxFailedAttempts()) {
                    if (firstValidPuk != null) {
                        // In case max failed count is reached and valid PUK exists, block the recovery code and invalidate the PUK
                        recoveryCodeEntity.setStatus(RecoveryCodeStatus.BLOCKED);
                        recoveryCodeEntity.setTimestampLastChange(new Date());
                        firstValidPuk.setStatus(RecoveryPukStatus.INVALID);
                        firstValidPuk.setTimestampLastChange(new Date());
                    }
                }
                recoveryCodeRepository.save(recoveryCodeEntity);
                if (firstValidPuk != null && !RecoveryPukStatus.INVALID.equals(firstValidPuk.getStatus())) {
                    // Provide current recovery PUK index in error response in case PUK in VALID state exists.
                    // Exception must not be rollbacking, otherwise the data saved into DB would be lost.
                    throw localizationProvider.buildActivationRecoveryExceptionForCode(ServiceError.INVALID_RECOVERY_CODE, firstValidPuk.getPukIndex().intValue());
                } else {
                    // Exception must not be rollbacking, otherwise the data saved into DB would be lost.
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_RECOVERY_CODE);
                }
            }

            // Reset failed count, PUK was valid
            recoveryCodeEntity.setFailedAttempts(0L);

            // Change status of PUK which was used for recovery to USED
            pukUsedDuringActivation.setStatus(RecoveryPukStatus.USED);
            pukUsedDuringActivation.setTimestampLastChange(new Date());

            // If recovery code is bound to an existing activation, remove this activation
            if (recoveryCodeEntity.getActivationId() != null) {
                removeActivation(recoveryCodeEntity.getActivationId(), null, true);
            }

            // Persist recovery code changes
            recoveryCodeRepository.save(recoveryCodeEntity);

            // Prepare activation OTP mode
            final ActivationOtpValidation activationOtpValidation = activationOtp != null ? ActivationOtpValidation.ON_COMMIT : ActivationOtpValidation.NONE;

            // Initialize version 3 activation entity.
            // Parameter maxFailureCount can be customized, activationExpireTime is null because activation is committed immediately.
            InitActivationResponse initResponse = initActivation(
                    application.getId(),
                    recoveryCodeEntity.getUserId(),
                    maxFailureCount,
                    null,
                    activationOtpValidation,
                    activationOtp,
                    keyConversion);
            String activationId = initResponse.getActivationId();
            ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);

            // Validate created activation
            validateCreatedActivation(activation, application, true);

            // Extract the device public key from request
            byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(layer2Request.getDevicePublicKey());
            PublicKey devicePublicKey;

            try {
                devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            } catch (InvalidKeySpecException ex) {
                logger.warn("Device public key is invalid, activation ID: {}", activationId);
                // Device public key is invalid, rollback this transaction
                throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
            }

            // Initialize hash based counter
            HashBasedCounter counter = new HashBasedCounter();
            byte[] ctrData = counter.init();
            String ctrDataBase64 = BaseEncoding.base64().encode(ctrData);

            // Update and persist the activation record, activation is automatically committed in the next step in RESTful integration.
            activation.setActivationStatus(ActivationStatus.PENDING_COMMIT);
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversion.convertPublicKeyToBytes(devicePublicKey)));
            activation.setActivationName(layer2Request.getActivationName());
            activation.setExtras(layer2Request.getExtras());
            if (layer2Request.getPlatform() != null) {
                activation.setPlatform(layer2Request.getPlatform().toLowerCase());
            } else {
                activation.setPlatform("unknown");
            }
            activation.setDeviceInfo(layer2Request.getDeviceInfo());
            // PowerAuth protocol version 3.0 uses 0x3 as version in activation status
            activation.setVersion(3);
            // Set initial counter data
            activation.setCtrDataBase64(ctrDataBase64);
            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            // Activation has been successfully committed, set PUK state to USED and persist the change
            pukUsedDuringActivation.setStatus(RecoveryPukStatus.USED);
            pukUsedDuringActivation.setTimestampLastChange(new Date());
            recoveryCodeRepository.save(recoveryCodeEntity);

            // Create a new recovery code and PUK for new activation
            ActivationRecovery activationRecovery = createRecoveryCodeForActivation(activation, false);

            // Generate activation layer 2 response
            ActivationLayer2Response layer2Response = new ActivationLayer2Response();
            layer2Response.setActivationId(activation.getActivationId());
            layer2Response.setCtrData(ctrDataBase64);
            layer2Response.setServerPublicKey(activation.getServerPublicKeyBase64());
            layer2Response.setActivationRecovery(activationRecovery);
            byte[] responseData = objectMapper.writeValueAsBytes(layer2Response);

            // Encrypt response data
            final EciesCryptogram responseCryptogram = eciesDecryptor.encryptResponse(responseData);
            final String encryptedDataResponse = BaseEncoding.base64().encode(responseCryptogram.getEncryptedData());
            final String macResponse = BaseEncoding.base64().encode(responseCryptogram.getMac());

            final RecoveryCodeActivationResponse encryptedResponse = new RecoveryCodeActivationResponse();
            encryptedResponse.setActivationId(activation.getActivationId());
            encryptedResponse.setUserId(activation.getUserId());
            encryptedResponse.setApplicationId(application.getId());
            encryptedResponse.setEncryptedData(encryptedDataResponse);
            encryptedResponse.setMac(macResponse);
            encryptedResponse.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
            return encryptedResponse;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException | JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback transaction to avoid data inconsistency because of cryptography errors
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.DECRYPTION_FAILED);
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

    /**
     * Create recovery code for given activation and set its status to ACTIVE.
     * @param activationEntity Activation entity.
     * @param isActive Make recovery code active from the beginning.
     * @return Activation recovery code and PUK.
     * @throws GenericServiceException In case of any error.
     */
    private ActivationRecovery createRecoveryCodeForActivation(ActivationRecordEntity activationEntity, boolean isActive) throws GenericServiceException {
        final RecoveryConfigRepository recoveryConfigRepository = repositoryCatalogue.getRecoveryConfigRepository();

        try {
            // Check whether activation recovery is enabled
            final RecoveryConfigEntity recoveryConfigEntity = recoveryConfigRepository.findByApplicationId(activationEntity.getApplication().getId());
            if (recoveryConfigEntity == null || !recoveryConfigEntity.getActivationRecoveryEnabled()) {
                logger.warn("Activation recovery is disabled");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Note: the code below expects that application version for given activation has been verified.
            // We want to avoid checking application version twice (once during activation and second time in this method).
            // It is also expected that the activation is a valid activation which has just been created.
            // Prepare repositories
            final RecoveryCodeRepository recoveryCodeRepository = repositoryCatalogue.getRecoveryCodeRepository();

            final long applicationId = activationEntity.getApplication().getId();
            final String activationId = activationEntity.getActivationId();
            final String userId = activationEntity.getUserId();

            // Verify activation state
            if (!ActivationStatus.PENDING_COMMIT.equals(activationEntity.getActivationStatus()) && !ActivationStatus.ACTIVE.equals(activationEntity.getActivationStatus())) {
                logger.warn("Create recovery code failed because of invalid activation state, application ID: {}, activation ID: {}, activation state: {}", applicationId, activationId, activationEntity.getActivationStatus());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Check whether user has any recovery code in state CREATED or ACTIVE, in this case the recovery code needs to be revoked first
            List<RecoveryCodeEntity> existingRecoveryCodes = recoveryCodeRepository.findAllByApplicationIdAndActivationId(applicationId, activationId);
            for (RecoveryCodeEntity recoveryCodeEntity: existingRecoveryCodes) {
                if (recoveryCodeEntity.getStatus() == io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.CREATED || recoveryCodeEntity.getStatus() == io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus.ACTIVE) {
                    logger.warn("Create recovery code failed because of existing recovery codes, application ID: {}, activation ID: {}", applicationId, activationId);
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.RECOVERY_CODE_ALREADY_EXISTS);
                }
            }

            // Generate random secret key
            String recoveryCode = null;
            Map<Integer, String> puks = null;

            for (int i = 0; i < powerAuthServiceConfiguration.getGenerateRecoveryCodeIterations(); i++) {
                RecoveryInfo recoveryInfo = identifierGenerator.generateRecoveryCode();
                // Check that recovery code is unique
                boolean recoveryCodeExists = recoveryCodeRepository.getRecoveryCodeCount(applicationId, recoveryInfo.getRecoveryCode()) > 0;
                if (!recoveryCodeExists) {
                    recoveryCode = recoveryInfo.getRecoveryCode();
                    puks = recoveryInfo.getPuks();
                    break;
                }
            }

            // In case recovery code generation failed, throw an exception
            if (recoveryCode == null || puks == null || puks.size() != 1) {
                logger.error("Unable to generate recovery code");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_RECOVERY_CODE);
            }

            // Create and persist recovery code entity with PUK
            final RecoveryCodeEntity recoveryCodeEntity = new RecoveryCodeEntity();
            recoveryCodeEntity.setUserId(userId);
            recoveryCodeEntity.setApplicationId(applicationId);
            recoveryCodeEntity.setActivationId(activationId);
            recoveryCodeEntity.setFailedAttempts(0L);
            recoveryCodeEntity.setMaxFailedAttempts(powerAuthServiceConfiguration.getRecoveryMaxFailedAttempts());
            recoveryCodeEntity.setRecoveryCode(recoveryCode);
            recoveryCodeEntity.setStatus(isActive ? RecoveryCodeStatus.ACTIVE : RecoveryCodeStatus.CREATED);
            recoveryCodeEntity.setTimestampCreated(new Date());

            // Only one PUK was generated
            final String puk = puks.values().iterator().next();

            final RecoveryPukEntity recoveryPukEntity = new RecoveryPukEntity();
            recoveryPukEntity.setPukIndex(1L);
            String pukHash = PasswordHash.hash(puk.getBytes(StandardCharsets.UTF_8));
            RecoveryPuk recoveryPuk = recoveryPukConverter.toDBValue(pukHash, applicationId, userId, recoveryCode, recoveryPukEntity.getPukIndex());
            recoveryPukEntity.setPuk(recoveryPuk.getPukHash());
            recoveryPukEntity.setPukEncryption(recoveryPuk.getEncryptionMode());
            recoveryPukEntity.setStatus(RecoveryPukStatus.VALID);
            recoveryPukEntity.setRecoveryCode(recoveryCodeEntity);
            recoveryCodeEntity.getRecoveryPuks().add(recoveryPukEntity);

            recoveryCodeRepository.save(recoveryCodeEntity);

            return new ActivationRecovery(recoveryCode, puk);
        } catch (InvalidKeyException ex) {
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

}
