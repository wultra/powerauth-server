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
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.EciesUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

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
@Component
public class EciesEncryptionBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;

    // Helper classes
    private final EciesFactory eciesFactory = new EciesFactory();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(EciesEncryptionBehavior.class);

    @Autowired
    public EciesEncryptionBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider, ServerPrivateKeyConverter serverPrivateKeyConverter) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
    }

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
    public GetEciesDecryptorResponse getEciesDecryptorParameters(GetEciesDecryptorRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            // Application scope
            return getEciesDecryptorParametersForApplication(request);
        } else {
            // Activation scope
            return getEciesDecryptorParametersForActivation(request, keyConvertor);
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
            final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(request.getApplicationKey());
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }

            // Get master private key
            final ApplicationEntity application = applicationVersion.getApplication();
            final String applicationId = application.getId();
            final MasterKeyPairEntity masterKeyPairEntity = repositoryCatalogue.getMasterKeyPairRepository().findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
            if (masterKeyPairEntity == null) {
                logger.error("Missing key pair for application ID: {}", applicationId);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            }

            final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
            final PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(masterPrivateKeyBase64));

            // Get application secret
            final byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);

            final String applicationKey = request.getApplicationKey();
            final byte[] nonceBytes = request.getNonce() != null ? Base64.getDecoder().decode(request.getNonce()) : null;
            final String version = request.getProtocolVersion();
            final Long timestamp = "3.2".equals(version) ? request.getTimestamp() : null;
            final byte[] associatedData = "3.2".equals(version) ? EciesUtils.deriveAssociatedData(EciesScope.APPLICATION_SCOPE, version, applicationKey, null) : null;
            final EciesParameters eciesParameters = EciesParameters.builder().nonce(nonceBytes).timestamp(timestamp).associatedData(associatedData).build();
            final byte[] ephemeralPublicKeyBytes = Base64.getDecoder().decode(request.getEphemeralPublicKey());
            // Get decryptor for the application
            final EciesDecryptor decryptor = eciesFactory.getEciesDecryptorForApplication(
                    (ECPrivateKey) privateKey, applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC,
                    eciesParameters, ephemeralPublicKeyBytes);

            // Initialize decryptor with ephemeral public key
            decryptor.initEnvelopeKey(ephemeralPublicKeyBytes);

            // Extract envelope key and sharedInfo2 parameters to allow decryption on intermediate server
            final EciesEnvelopeKey envelopeKey = decryptor.getEnvelopeKey();
            final GetEciesDecryptorResponse response = new GetEciesDecryptorResponse();
            response.setSecretKey(Base64.getEncoder().encodeToString(envelopeKey.getSecretKey()));
            response.setSharedInfo2(Base64.getEncoder().encodeToString(decryptor.getSharedInfo2()));
            return response;
        } catch (InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (EciesException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
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
        if (request.getApplicationKey() == null || request.getEphemeralPublicKey() == null) {
            logger.warn("Invalid request for ECIES decryptor");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }

        try {
            // Lookup the activation
            final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithoutLock(request.getActivationId());
            if (activation == null) {
                logger.info("Activation does not exist, activation ID: {}", request.getActivationId());
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Check if the activation is in correct state
            if (!ActivationStatus.ACTIVE.equals(activation.getActivationStatus())) {
                logger.info("Activation is not ACTIVE, activation ID: {}", request.getActivationId());
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            // Lookup the application version and check that it is supported
            final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(request.getApplicationKey());
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", request.getApplicationKey());
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
            final byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConversion.convertSharedSecretKeyToBytes(transportKey);

            final Long timestamp = request.getTimestamp();
            final String version = request.getProtocolVersion();
            final String applicationKey = request.getApplicationKey();
            final String activationId = request.getActivationId();
            final byte[] nonceBytes = request.getNonce() != null ? Base64.getDecoder().decode(request.getNonce()) : null;
            final byte[] associatedData = EciesUtils.deriveAssociatedData(EciesScope.ACTIVATION_SCOPE, version, applicationKey, activationId);
            final EciesParameters eciesParameters = EciesParameters.builder().nonce(nonceBytes).timestamp(timestamp).associatedData(associatedData).build();
            final byte[] ephemeralPublicKeyBytes = Base64.getDecoder().decode(request.getEphemeralPublicKey());

            // Get decryptor for the activation
            final EciesDecryptor decryptor = eciesFactory.getEciesDecryptorForActivation(
                    (ECPrivateKey) serverPrivateKey, applicationSecret, transportKeyBytes, EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC,
                    eciesParameters, ephemeralPublicKeyBytes);

            // Initialize decryptor with ephemeral public key
            decryptor.initEnvelopeKey(ephemeralPublicKeyBytes);

            // Extract envelope key and sharedInfo2 parameters to allow decryption on intermediate server
            final EciesEnvelopeKey envelopeKey = decryptor.getEnvelopeKey();
            final GetEciesDecryptorResponse response = new GetEciesDecryptorResponse();
            response.setSecretKey(Base64.getEncoder().encodeToString(envelopeKey.getSecretKey()));
            response.setSharedInfo2(Base64.getEncoder().encodeToString(decryptor.getSharedInfo2()));
            return response;
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

}