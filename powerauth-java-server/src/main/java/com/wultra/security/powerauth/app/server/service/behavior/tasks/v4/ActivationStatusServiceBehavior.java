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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.ActivationCommitPhaseConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationOtpValidationConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationSharedSecretConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.SharedSecret;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ActivationRemoveServiceBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.AlgorithmQueryService;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.client.model.request.v4.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetActivationStatusResponse;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation;
import com.wultra.security.powerauth.crypto.server.v4.keyfactory.PowerAuthServerKeyFactory;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

/**
 * Activation status service (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("activationStatusServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class ActivationStatusServiceBehavior {

    private static final byte STATUS_FLAG_ACTIVATION_CONFIRMATION = 1;
    private static final byte STATUS_FLAG_UPGRADE_CONFIRMATION    = 2;
    private static final byte STATUS_FLAG_UNSUPPORTED_ALGORITHM   = 4;
    private static final byte STATUS_FLAG_BIOMETRY_FACTOR_ON      = 8;

    private final ActivationRemoveServiceBehavior activationRemoveServiceBehavior;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationQueryService activationQueryService;
    private final CryptographyServiceFactory cryptographyServiceFactory;
    private final ActivationSharedSecretConverter activationSharedSecretConverter;
    private final AlgorithmQueryService algorithmQueryService;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final ActivationOtpValidationConverter activationOtpValidationConverter = new ActivationOtpValidationConverter();
    private final ActivationCommitPhaseConverter activationCommitPhaseConverter = new ActivationCommitPhaseConverter();

    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final PowerAuthServerKeyFactory SERVER_KEY_FACTORY = new PowerAuthServerKeyFactory();

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

                    final byte[] activationSignatureV3 = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256)
                            .generateSignatureForApplication(
                                    KeyType.ECDSA_P256,
                                    activation.getActivationCode().getBytes(StandardCharsets.UTF_8),
                                    application
                            );
                    final CryptographyService cryptographyServiceV4 = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P384_ML_L3);
                    final byte[] activationSignatureV4Ecdsa = cryptographyServiceV4.generateSignatureForApplication(
                            KeyType.ECDSA_P384,
                            activation.getActivationCode().getBytes(StandardCharsets.UTF_8),
                            application
                    );
                    final byte[] activationSignatureV4Mldsa = cryptographyServiceV4.generateSignatureForApplication(
                            KeyType.MLDSA_65,
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
                    response.setConfirmationPending(activation.isConfirmationPending());
                    response.setActivationName(activation.getActivationName());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(applicationId);
                    response.setFailedAttempts(activation.getFailedAttempts());
                    response.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                    response.setTimestampCreated(activation.getTimestampCreated());
                    response.setTimestampLastUsed(activation.getTimestampLastUsed());
                    response.setTimestampLastChange(activation.getTimestampLastChange());
                    response.setStatusBlob(Base64.getEncoder().encodeToString(randomStatusBlob));
                    response.setActivationCode(activation.getActivationCode());
                    response.setActivationSignature(activationSignatureV3 != null ? Base64.getEncoder().encodeToString(activationSignatureV3) : null);
                    response.setActivationSignatureEcdsa(activationSignatureV4Ecdsa != null ? Base64.getEncoder().encodeToString(activationSignatureV4Ecdsa) : null);
                    response.setActivationSignatureMldsa(activationSignatureV4Mldsa != null ? Base64.getEncoder().encodeToString(activationSignatureV4Mldsa) : null);
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
                    final String sharedSecretEncrypted = activation.getSharedSecret();

                    final byte[] statusBlob;
                    final SharedSecretAlgorithm sharedSecretAlgorithm;
                    final String activationFingerPrint;
                    if (sharedSecretEncrypted != null) {
                        // Resolve shared secret algorithm
                        sharedSecretAlgorithm = activation.getCryptoAlgorithm();
                        if (sharedSecretAlgorithm == null) {
                            logger.error("Missing shared secret algorithm for activation ID: {}", activation.getActivationId());
                            // Rollback is not required, database is not used for writing
                            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
                        }
                        final boolean algorithmSupported = algorithmQueryService.isAlgorithmSupported(application, sharedSecretAlgorithm);
                        final String ctrDataBase64 = activation.getCtrDataV4Base64();
                        final byte[] ctrData = Base64.getDecoder().decode(ctrDataBase64);
                        final ActivationStatusBlobInfo statusBlobInfo = new ActivationStatusBlobInfo();
                        statusBlobInfo.setActivationStatus(activation.getActivationStatus().getByte());
                        statusBlobInfo.setCurrentVersion(activation.getVersion().byteValue());
                        statusBlobInfo.setUpgradeVersion(PowerAuthServiceConfiguration.POWERAUTH_PROTOCOL_VERSION);
                        statusBlobInfo.setFailedAttempts(activation.getFailedAttempts().byteValue());
                        statusBlobInfo.setMaxFailedAttempts(activation.getMaxFailedAttempts().byteValue());
                        statusBlobInfo.setCtrLookAhead((byte) powerAuthServiceConfiguration.getAuthenticationCodeValidationLookahead());
                        statusBlobInfo.setCtrByte(activation.getCounter().byteValue());
                        statusBlobInfo.setStatusFlags(computeStatusFlags(
                                activation.isConfirmationPending(),
                                activation.isUpgradeConfirmationPending(),
                                !algorithmSupported,
                                activation.isBiometricFactorEnabled())
                        );
                        final EncryptionMode sharedSecretEncryptionMode = activation.getSharedSecretEncryption();
                        final SharedSecret sharedSecretDb = new SharedSecret(sharedSecretEncryptionMode, sharedSecretEncrypted);
                        final String sharedSecretKeyBase64 = activationSharedSecretConverter.fromDBValue(sharedSecretDb, activation.getUserId(), activation.getActivationId());
                        final SecretKey sharedSecretKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(sharedSecretKeyBase64));
                        final SecretKey keyCtrDataMac = SERVER_KEY_FACTORY.generateKeyMacCtrData(sharedSecretKey);
                        final SecretKey keyStatusMac = SERVER_KEY_FACTORY.generateKeyMacStatus(sharedSecretKey);
                        final byte[] ctrDataHashForStatusBlob = powerAuthServerActivation.calculateHashFromHashBasedCounter(ctrData, keyCtrDataMac, ProtocolVersion.V40);
                        statusBlobInfo.setCtrDataHash(ctrDataHashForStatusBlob);
                        final byte[] statusBlobData = powerAuthServerActivation.generateStatusBlob(statusBlobInfo, ProtocolVersion.V40);
                        final byte[] statusBlobMac = powerAuthServerActivation.calculateStatusMac(statusBlobData, keyStatusMac, ProtocolVersion.V40);
                        statusBlob = ByteBuffer
                                .allocate(statusBlobData.length + statusBlobMac.length)
                                .put(statusBlobData)
                                .put(statusBlobMac)
                                .array();
                        // Assign the activation fingerprint
                        activationFingerPrint = cryptographyServiceFactory.getService(sharedSecretAlgorithm).generateActivationFingerprint(activation);
                    } else {
                        statusBlob = null;
                        activationFingerPrint = null;
                    }

                    // return the data
                    final GetActivationStatusResponse response = new GetActivationStatusResponse();
                    response.setActivationId(activationId);
                    response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
                    response.setActivationOtpValidation(activationOtpValidationConverter.convertFrom(activation.getActivationOtpValidation()));
                    response.setCommitPhase(activationCommitPhaseConverter.convertFrom(activation.getCommitPhase()));
                    response.setBlockedReason(activation.getBlockedReason());
                    response.setConfirmationPending(activation.isConfirmationPending());
                    response.setActivationName(activation.getActivationName());
                    response.setUserId(activation.getUserId());
                    response.setExtras(activation.getExtras());
                    response.setApplicationId(applicationId);
                    response.setFailedAttempts(activation.getFailedAttempts());
                    response.setMaxFailedAttempts(activation.getMaxFailedAttempts());
                    response.setTimestampCreated(activation.getTimestampCreated());
                    response.setTimestampLastUsed(activation.getTimestampLastUsed());
                    response.setTimestampLastChange(activation.getTimestampLastChange());
                    if (statusBlob != null) {
                        response.setStatusBlob(Base64.getEncoder().encodeToString(statusBlob));
                    }
                    response.setActivationCode(null);
                    response.setActivationSignatureEcdsa(null);
                    response.setActivationSignatureMldsa(null);
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
                response.setStatusBlob(Base64.getEncoder().encodeToString(randomStatusBlob));
                response.setActivationCode(null);
                response.setActivationSignatureEcdsa(null);
                response.setActivationSignatureMldsa(null);
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

    private static byte computeStatusFlags(boolean activationConfirmationPending, boolean upgradeConfirmation, boolean unsupportedAlgorithm, boolean biometryOn) {
        byte flags = 0;
        if (activationConfirmationPending) flags |= STATUS_FLAG_ACTIVATION_CONFIRMATION;
        if (upgradeConfirmation) flags |= STATUS_FLAG_UPGRADE_CONFIRMATION;
        if (unsupportedAlgorithm) flags |= STATUS_FLAG_UNSUPPORTED_ALGORITHM;
        if (biometryOn) flags |= STATUS_FLAG_BIOMETRY_FACTOR_ON;
        return flags;
    }

}
