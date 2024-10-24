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

import com.wultra.security.powerauth.client.model.request.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.response.GetEciesDecryptorResponse;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import io.getlime.security.powerauth.app.server.service.replay.ReplayVerificationService;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;

/**
 * Behavior class implementing the ECIES service logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EciesEncryptionBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final TemporaryKeyBehavior temporaryKeyBehavior;
    private final ReplayVerificationService replayVerificationService;
    private final ActivationContextValidator activationValidator;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final MasterKeyPairRepository masterKeyPairRepository;

    // Helper classes
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Obtain ECIES decryptor parameters to allow decryption of ECIES-encrypted messages on intermediate server.
     * This interface doesn't allow keys derivation, it only provides ECIES decryptor parameters used for generic
     * encryption (sharedInfo1 = /pa/generic/**).
     * <p>
     * If activationId is not present, then it creates ECIES decryptor for application scope.
     * If activationId is present, then it creates ECIES decryptor for activation scope.
     *
     * @return ECIES decryptor parameters.
     */
    @Transactional
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws GenericServiceException {
        try {
            if (request.getApplicationKey() == null || request.getEphemeralPublicKey() == null) {
                logger.warn("Invalid request parameters in method getEciesDecryptor");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            if (request.getActivationId() == null) {
                // Application scope
                return getEciesDecryptorParametersForApplication(request);
            } else {
                // Activation scope
                return getEciesDecryptorParametersForActivation(request, keyConvertor);
            }
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

    /**
     * Get ECIES decryptor parameters for application scope.
     *
     * @param request Request to get ECIES decryptor parameters.
     * @return ECIES decryptor parameters for application scope.
     * @throws GenericServiceException In case ECIES decryptor parameters could not be extracted.
     */
    private GetEciesDecryptorResponse getEciesDecryptorParametersForApplication(GetEciesDecryptorRequest request) throws GenericServiceException {
        if (request.getApplicationKey() == null || request.getEphemeralPublicKey() == null) {
            logger.warn("Invalid request for ECIES decryptor");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }

        try {
            // Lookup the application version and check that it is supported
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(request.getApplicationKey());
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            if (request.getTimestamp() != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_APPLICATION_SCOPE,
                        new Date(request.getTimestamp()),
                        request.getEphemeralPublicKey(),
                        request.getNonce(),
                        null,
                        request.getProtocolVersion());
            }

            final String temporaryKeyId = request.getTemporaryKeyId();
            final PrivateKey privateKey;
            if (temporaryKeyId != null) {
                // Get the temporary private key
                privateKey = temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, request.getApplicationKey(), request.getActivationId());
            } else {
                // Get master private key
                final ApplicationEntity application = applicationVersion.getApplication();
                final String applicationId = application.getId();
                final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
                if (masterKeyPairEntity == null) {
                    logger.error("Missing key pair for application ID: {}", applicationId);
                    // Rollback is not required, database is not used for writing
                    throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
                }

                final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
                privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(masterPrivateKeyBase64));
            }

            // Build encryptor to derive shared info
            final ServerEncryptor encryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.APPLICATION_SCOPE_GENERIC,
                    new EncryptorParameters(request.getProtocolVersion(), applicationVersion.getApplicationKey(), null, temporaryKeyId),
                    new ServerEncryptorSecrets(privateKey, applicationVersion.getApplicationSecret())
            );
            // Calculate secrets for the external encryptor
            final EncryptorSecrets encryptorSecrets = encryptor.calculateSecretsForExternalEncryptor(
                    new EncryptedRequest(
                            request.getTemporaryKeyId(),
                            request.getEphemeralPublicKey(),
                            null,
                            null,
                            request.getNonce(),
                            request.getTimestamp()
                    )
            );
            if (encryptorSecrets instanceof ServerEncryptorSecrets encryptorSecretsV3) {
                // ECIES V3.0, V3.1, V3.2
                final GetEciesDecryptorResponse response = new GetEciesDecryptorResponse();
                response.setSecretKey(Base64.getEncoder().encodeToString(encryptorSecretsV3.getEnvelopeKey()));
                response.setSharedInfo2(Base64.getEncoder().encodeToString(encryptorSecretsV3.getSharedInfo2Base()));
                return response;
            }
            logger.error("Unsupported EncryptorSecrets object");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);

        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (EncryptorException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Get ECIES decryptor parameters for activation scope.
     *
     * @param request Request to get ECIES decryptor parameters.
     * @return ECIES decryptor parameters for activation scope.
     * @throws GenericServiceException In case ECIES decryptor parameters could not be extracted.
     */
    private GetEciesDecryptorResponse getEciesDecryptorParametersForActivation(GetEciesDecryptorRequest request, KeyConvertor keyConversion) throws GenericServiceException {

        final String temporaryKeyId = request.getTemporaryKeyId();
        final String applicationKey = request.getApplicationKey();
        final String activationId = request.getActivationId();
        final String ephemeralPublicKey = request.getEphemeralPublicKey();
        final Long timestamp = request.getTimestamp();
        final String nonce = request.getNonce();
        final String protocolVersion = request.getProtocolVersion();

        if (applicationKey == null || ephemeralPublicKey == null) {
            logger.warn("Invalid request for ECIES decryptor");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }
        try {
            // Lookup the activation
            final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
                logger.info("Activation does not exist, activation ID: {}", activationId);
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            if (timestamp != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_APPLICATION_SCOPE,
                        new Date(timestamp),
                        ephemeralPublicKey,
                        nonce,
                        activation.getActivationId(),
                        protocolVersion);
            }

            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            // Lookup the application version and check that it is supported
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            // Check that application key from request belongs to same application as activation ID from request
            if (!applicationVersion.getApplication().getRid().equals(activation.getApplication().getRid())) {
                logger.warn("Application version does not match, application key: {}", request.getApplicationKey());
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());
            final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
            final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get application secret and transport key used in sharedInfo2 parameter of ECIES
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConversion.convertSharedSecretKeyToBytes(transportKey);

            // Get temporary or server key, depending on availability
            final PrivateKey encryptorPrivateKey = (temporaryKeyId != null) ? temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, applicationKey, activationId) : serverPrivateKey;

            // Build encryptor to derive shared info
            final ServerEncryptor encryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.ACTIVATION_SCOPE_GENERIC,
                    new EncryptorParameters(protocolVersion, applicationVersion.getApplicationKey(), activation.getActivationId(), temporaryKeyId),
                    new ServerEncryptorSecrets(encryptorPrivateKey, applicationVersion.getApplicationSecret(), transportKeyBytes)
            );
            // Calculate secrets for the external encryptor. The request object may not contain encrypted data and mac.
            final EncryptorSecrets encryptorSecrets = encryptor.calculateSecretsForExternalEncryptor(
                    new EncryptedRequest(
                            temporaryKeyId,
                            ephemeralPublicKey,
                            null,
                            null,
                            nonce,
                            timestamp
                    )
            );
            if (encryptorSecrets instanceof ServerEncryptorSecrets encryptorSecretsV3) {
                // ECIES V3.0, V3.1, V3.2
                final GetEciesDecryptorResponse response = new GetEciesDecryptorResponse();
                response.setSecretKey(Base64.getEncoder().encodeToString(encryptorSecretsV3.getEnvelopeKey()));
                response.setSharedInfo2(Base64.getEncoder().encodeToString(encryptorSecretsV3.getSharedInfo2Base()));
                return response;
            }
            logger.error("Unsupported EncryptorSecrets object");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);

        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EncryptorException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

}