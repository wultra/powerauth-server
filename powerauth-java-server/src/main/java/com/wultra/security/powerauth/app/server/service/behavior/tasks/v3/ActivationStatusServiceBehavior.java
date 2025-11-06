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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.ActivationCommitPhaseConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationOtpValidationConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.*;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.client.model.request.v3.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.response.v3.GetActivationStatusResponse;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.server.activation.PowerAuthServerActivation;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Activation status service (V3).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("activationStatusServiceBehaviorV3")
@Slf4j
@AllArgsConstructor
public class ActivationStatusServiceBehavior {

    private final ActivationRemoveServiceBehavior activationRemoveServiceBehavior;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationQueryService activationQueryService;
    private final CryptographyServiceFactory cryptographyServiceFactory;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final ActivationOtpValidationConverter activationOtpValidationConverter = new ActivationOtpValidationConverter();
    private final ActivationCommitPhaseConverter activationCommitPhaseConverter = new ActivationCommitPhaseConverter();

    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();

    /**
     * Get activation status for given activation ID
     *
     * @param request Activation status request.
     * @return Activation status response
     * @throws GenericServiceException Thrown when cryptography error occurs.
     */
    @Transactional
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final String challenge = request.getChallenge();

            // Generate timestamp in advance
            final Date timestamp = new Date();

            // Prepare key generator
            final KeyGenerator keyGenerator = new KeyGenerator();

            final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);

            // Check if the activation exists
            if (activationOptional.isPresent()) {

                final ActivationRecordEntity activation = activationOptional.get();

                // Deactivate old pending activations first
                activationRemoveServiceBehavior.deactivatePendingActivation(timestamp, activation, false);

                final ApplicationEntity application = activation.getApplication();
                final String applicationId = application.getId();

                // Handle CREATED activation
                if (activation.getActivationStatus() == ActivationStatus.CREATED) {

                    // Created activations are not able to transfer valid status blob to the client
                    // since both keys were not exchanged yet and transport cannot be secured.
                    final byte[] randomStatusBlob = keyGenerator.generateRandomBytes(32);
                    // Use random nonce in case that challenge was provided.
                    final String randomStatusBlobNonce = challenge == null ? null : Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16));

                    final byte[] activationSignature = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256)
                            .generateSignatureForApplication(
                                    KeyType.ECDSA_P256,
                                    activation.getActivationCode().getBytes(StandardCharsets.UTF_8),
                                    application
                            );

                    // return the data
                    final GetActivationStatusResponse response = new GetActivationStatusResponse();
                    response.setActivationId(activationId);
                    response.setUserId(activation.getUserId());
                    response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    response.setActivationOtpValidation(activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation()));
                    response.setCommitPhase(activationCommitPhaseConverter.convertFrom(activation.getCommitPhase()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setActivationName(activation.getActivationName());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(applicationId);
                    response.setFailedAttempts(activation.getFailedAttempts());
                    response.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                    response.setTimestampCreated(activation.getTimestampCreated());
                    response.setTimestampLastUsed(activation.getTimestampLastUsed());
                    response.setTimestampLastChange(activation.getTimestampLastChange());
                    response.setEncryptedStatusBlob(Base64.getEncoder().encodeToString(randomStatusBlob));
                    response.setEncryptedStatusBlobNonce(randomStatusBlobNonce);
                    response.setActivationCode(activation.getActivationCode());
                    response.setActivationSignature(Base64.getEncoder().encodeToString(activationSignature));
                    response.setDevicePublicKeyFingerprint(null);
                    response.setPlatform(activation.getPlatform());
                    response.setProtocol(convertProtocol(activation.getProtocol()));
                    response.setExternalId(activation.getExternalId());
                    response.setDeviceInfo(activation.getDeviceInfo());
                    response.getActivationFlags().addAll(activation.getFlags());
                    response.getApplicationRoles().addAll(application.getRoles());
                    // Unknown version is converted to 0 in service
                    response.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                    response.setParentActivationId(activation.getParentActivation() == null ? null : activation.getParentActivation().getActivationId());
                    response.setTransferType(convertTransferType(activation.getTransferType()));
                    return response;
                } else {
                    // Get the server private and device public keys to compute the transport key
                    final String devicePublicKeyBase64 = activation.getDevicePublicKeyBase64();

                    // If an activation was turned to REMOVED directly from CREATED state,
                    // there is no device public key in the database - we need to handle
                    // that case by defaulting the encryptedStatusBlob to random value...
                    byte[] encryptedStatusBlob = keyGenerator.generateRandomBytes(32);
                    String encryptedStatusBlobNonce = null;

                    // Prepare a value for the device public key fingerprint
                    String activationFingerPrint = null;

                    // Derive values for different protocol versions depending on presence of challenge parameter
                    final byte[] statusChallenge;
                    final byte[] statusNonce;
                    final ProtocolVersion protocolVersion;
                    if (challenge != null) {
                        // If challenge is present, then also generate a new nonce. Protocol V3.1+
                        statusChallenge = Base64.getDecoder().decode(challenge);
                        statusNonce = keyGenerator.generateRandomBytes(16);
                        encryptedStatusBlobNonce = Base64.getEncoder().encodeToString(statusNonce);
                        protocolVersion = ProtocolVersion.V33;
                    } else {
                        // Older protocol versions, where IV derivation is not available.
                        statusChallenge = null;
                        statusNonce = null;
                        protocolVersion = ProtocolVersion.V30;
                    }

                    // There is a device public key available, therefore we can compute
                    // the real encryptedStatusBlob value.
                    if (devicePublicKeyBase64 != null) {

                        final SecretKey masterSecretKey = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).deriveSharedSecretKey(activation);
                        final SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);

                        final String ctrDataBase64 = activation.getCtrDataBase64();
                        byte[] ctrDataHashForStatusBlob;
                        if (ctrDataBase64 == null) {
                            logger.error("Invalid counter data for activation version: {}", activation.getVersion());
                            // Rollback is not required, database is not used for writing
                            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
                        }
                        // In crypto v3 counter data is stored with activation. We have to calculate hash from
                        // the counter value, before it's encoded into the status blob. The value might be replaced
                        // in `encryptedStatusBlob()` function that injects random data, depending on the version
                        // of the status blob encryption.
                        final byte[] ctrData = Base64.getDecoder().decode(ctrDataBase64);
                        ctrDataHashForStatusBlob = powerAuthServerActivation.calculateHashFromHashBasedCounter(ctrData, transportKey, protocolVersion);

                        // Encrypt the status blob
                        final ActivationStatusBlobInfo statusBlobInfo = new ActivationStatusBlobInfo();
                        statusBlobInfo.setActivationStatus(activation.getActivationStatus().getByte());
                        statusBlobInfo.setCurrentVersion(activation.getVersion().byteValue());
                        statusBlobInfo.setUpgradeVersion(PowerAuthServiceConfiguration.POWERAUTH_PROTOCOL_VERSION);
                        statusBlobInfo.setFailedAttempts(activation.getFailedAttempts().byteValue());
                        statusBlobInfo.setMaxFailedAttempts(activation.getMaxFailedAttempts().byteValue());
                        statusBlobInfo.setCtrLookAhead((byte)powerAuthServiceConfiguration.getAuthenticationCodeValidationLookahead());
                        statusBlobInfo.setCtrByte(activation.getCounter().byteValue());
                        statusBlobInfo.setCtrDataHash(ctrDataHashForStatusBlob);
                        encryptedStatusBlob = powerAuthServerActivation.encryptedStatusBlob(statusBlobInfo, statusChallenge, statusNonce, transportKey, protocolVersion);

                        // Assign the activation fingerprint
                        activationFingerPrint = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256).generateActivationFingerprint(activation);
                    }

                    // return the data
                    final GetActivationStatusResponse response = new GetActivationStatusResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    response.setActivationOtpValidation(activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation()));
                    response.setCommitPhase(activationCommitPhaseConverter.convertFrom(activation.getCommitPhase()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setActivationName(activation.getActivationName());
                    response.setUserId(activation.getUserId());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(applicationId);
                    response.setFailedAttempts(activation.getFailedAttempts());
                    response.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                    response.setTimestampCreated(activation.getTimestampCreated());
                    response.setTimestampLastUsed(activation.getTimestampLastUsed());
                    response.setTimestampLastChange(activation.getTimestampLastChange());
                    response.setEncryptedStatusBlob(Base64.getEncoder().encodeToString(encryptedStatusBlob));
                    response.setEncryptedStatusBlobNonce(encryptedStatusBlobNonce);
                    response.setActivationCode(null);
                    response.setActivationSignature(null);
                    response.setDevicePublicKeyFingerprint(activationFingerPrint);
                    response.setPlatform(activation.getPlatform());
                    response.setProtocol(convertProtocol(activation.getProtocol()));
                    response.setExternalId(activation.getExternalId());
                    response.setDeviceInfo(activation.getDeviceInfo());
                    response.getActivationFlags().addAll(activation.getFlags());
                    response.getApplicationRoles().addAll(application.getRoles());
                    // Unknown version is converted to 0 in service
                    response.setVersion(activation.getVersion() == null ? 0L : activation.getVersion());
                    response.setAdditionalData(activation.getAdditionalData());
                    response.setParentActivationId(activation.getParentActivation() == null ? null : activation.getParentActivation().getActivationId());
                    response.setTransferType(convertTransferType(activation.getTransferType()));
                    return response;
                }
            } else {

                // Activations that do not exist should return REMOVED state and
                // a random status blob
                final byte[] randomStatusBlob = keyGenerator.generateRandomBytes(32);
                // Use random nonce in case that challenge was provided.
                final String randomStatusBlobNonce = challenge == null ? null : Base64.getEncoder().encodeToString(keyGenerator.generateRandomBytes(16));

                // Generate date
                final Date zeroDate = new Date(0);

                // return the data
                final GetActivationStatusResponse response = new GetActivationStatusResponse();
                response.setActivationId(activationId);
                response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.REMOVED));
                response.setActivationOtpValidation(com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE);
                response.setCommitPhase(com.wultra.security.powerauth.client.model.enumeration.CommitPhase.ON_COMMIT);
                response.setBlockedReason(null);
                response.setActivationName("unknown");
                response.setUserId("unknown");
                response.setApplicationId(null);
                response.setExtras(null);
                response.setPlatform(null);
                response.setProtocol(null);
                response.setExternalId(null);
                response.setDeviceInfo(null);
                response.setTimestampCreated(zeroDate);
                response.setTimestampLastUsed(zeroDate);
                response.setTimestampLastChange(null);
                response.setFailedAttempts(0L);
                response.setMaxFailedAttempts(powerAuthServiceConfiguration.getAuthenticationCodeMaxFailedAttempts());
                response.setEncryptedStatusBlob(Base64.getEncoder().encodeToString(randomStatusBlob));
                response.setEncryptedStatusBlobNonce(randomStatusBlobNonce);
                response.setActivationCode(null);
                response.setActivationSignature(null);
                response.setDevicePublicKeyFingerprint(null);
                // Use 0 as version when version is undefined
                response.setVersion(0L);
                return response;
            }
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            /// Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    private static ActivationTransferType convertTransferType(final com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationTransferType source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case MOVE -> ActivationTransferType.MOVE;
            case SPAWN -> ActivationTransferType.SPAWN;
        };
    }

    private static ActivationProtocol convertProtocol(final com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol source) {
        if (source == null) {
            return null;
        }
        return switch(source) {
            case FIDO2 -> ActivationProtocol.FIDO2;
            case POWERAUTH -> ActivationProtocol.POWERAUTH;
        };
    }

}
