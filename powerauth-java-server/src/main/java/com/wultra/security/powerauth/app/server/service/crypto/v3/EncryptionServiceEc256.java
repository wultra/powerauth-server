/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.app.server.service.crypto.v3;

import com.wultra.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import com.wultra.security.powerauth.app.server.database.model.ServerPrivateKey;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.EncryptionService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.replay.ReplayVerificationService;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ServerEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;

@Service
@Slf4j
@AllArgsConstructor
public class EncryptionServiceEc256 implements EncryptionService {

    private final MasterKeyPairRepository masterKeyPairRepository;
    private final ReplayVerificationService replayVerificationService;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final LocalizationProvider localizationProvider;
    private final TemporaryKeyServiceEc256 temporaryKeyService;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final ActivationQueryService activationQueryService;

    private final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private final PowerAuthServerKeyFactory SERVER_KEY_FACTORY = new PowerAuthServerKeyFactory();

    public DecryptionResult decrypt(EncryptedRequest encryptedRequest, String protocolVersion, String applicationKey, String activationId, EncryptorId encryptorId, boolean validateRequest) throws GenericServiceException {
        try {
            final ApplicationVersionEntity applicationVersion = findApplicationVersion(applicationKey);
            final ActivationRecordEntity activation = findActivation(activationId);

            // Validate encrypted request
            if (validateRequest && !ENCRYPTOR_FACTORY.getRequestResponseValidator(protocolVersion).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid encrypted request parameters");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final EciesEncryptedRequest eciesRequest = (EciesEncryptedRequest) encryptedRequest;
            final UniqueValueType uniqueValueType = switch (encryptorId) {
                case APPLICATION_SCOPE_GENERIC, ACTIVATION_LAYER_2 -> UniqueValueType.ECIES_APPLICATION_SCOPE;
                case ACTIVATION_SCOPE_GENERIC, UPGRADE, VAULT_UNLOCK, CREATE_TOKEN ->
                        UniqueValueType.ECIES_ACTIVATION_SCOPE;
            };
            if (eciesRequest.getTimestamp() != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        uniqueValueType,
                        new Date(eciesRequest.getTimestamp()),
                        eciesRequest.getEphemeralPublicKey(),
                        eciesRequest.getNonce(),
                        activation != null ? activation.getActivationId() : null,
                        protocolVersion);
            }

            if (activation == null) {
                return decryptInApplicationScope(eciesRequest, protocolVersion, applicationVersion, encryptorId);
            } else {
                return decryptInActivationScope(eciesRequest, protocolVersion, applicationVersion, activation, encryptorId);
            }
        } catch (EncryptorException | InvalidKeySpecException | CryptoProviderException | GenericCryptoException |
                 InvalidKeyException e) {
            logger.error("Decryption failed", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    private DecryptionResult decryptInApplicationScope(EciesEncryptedRequest eciesRequest, String protocolVersion, ApplicationVersionEntity applicationVersion, EncryptorId encryptorId) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException, EncryptorException {
        final PrivateKey privateKey;
        if (eciesRequest.getTemporaryKeyId() != null) {
            privateKey = temporaryKeyService.temporaryPrivateKey(eciesRequest.getTemporaryKeyId(), applicationVersion.getApplicationKey());
        } else {
            final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationVersion.getApplication().getId());
            if (masterKeyPairEntity == null) {
                logger.error("Missing key pair for application ID: {}", applicationVersion.getApplication().getId());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            }

            final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
            privateKey = KEY_CONVERTOR.convertBytesToPrivateKey(EcCurve.P256, Base64.getDecoder().decode(masterPrivateKeyBase64));
        }
        final DecryptionResult decryptionResult = new DecryptionResult();
        decryptionResult.setServerEncryptor(ENCRYPTOR_FACTORY.getServerEncryptor(
                encryptorId,
                new EncryptorParameters(protocolVersion, applicationVersion.getApplicationKey(), null, eciesRequest.getTemporaryKeyId()),
                new ServerEciesSecrets(privateKey, applicationVersion.getApplicationSecret())
        ));
        decryptionResult.setApplication(applicationVersion.getApplication());
        return decryptionResult;
    }

    private DecryptionResult decryptInActivationScope(EciesEncryptedRequest eciesRequest, String protocolVersion, ApplicationVersionEntity applicationVersion, ActivationRecordEntity activation, EncryptorId encryptorId) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException, EncryptorException, GenericCryptoException, InvalidKeyException {
        final PrivateKey privateKey;
        final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
        final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
        final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
        final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());
        final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
        final PrivateKey serverPrivateKey = KEY_CONVERTOR.convertBytesToPrivateKey(EcCurve.P256, serverPrivateKeyBytes);

        // Get application secret and transport key used in sharedInfo2 parameter of ECIES
        final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
        final PublicKey devicePublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, devicePublicKeyBytes);
        final SecretKey transportKey = SERVER_KEY_FACTORY.deriveTransportKey(serverPrivateKey, devicePublicKey);
        final byte[] transportKeyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(transportKey);

        if (eciesRequest.getTemporaryKeyId() != null) {
            privateKey = temporaryKeyService.temporaryPrivateKey(eciesRequest.getTemporaryKeyId(), applicationVersion.getApplicationKey(), activation.getActivationId());
        } else {
            privateKey = serverPrivateKey;
        }
        final DecryptionResult decryptionResult = new DecryptionResult();
        decryptionResult.setServerEncryptor(ENCRYPTOR_FACTORY.getServerEncryptor(
                encryptorId,
                new EncryptorParameters(protocolVersion, applicationVersion.getApplicationKey(), activation.getActivationId(), eciesRequest.getTemporaryKeyId()),
                new ServerEciesSecrets(privateKey, applicationVersion.getApplicationSecret(), transportKeyBytes)
        ));
        if (encryptorId == EncryptorId.VAULT_UNLOCK) {
            decryptionResult.setServerPrivateKey(serverPrivateKey);
            decryptionResult.setDevicePublicKey(devicePublicKey);
        }
        decryptionResult.setApplication(applicationVersion.getApplication());
        return decryptionResult;
    }

    private ApplicationVersionEntity findApplicationVersion(String applicationKey) throws GenericServiceException {
        // Find application by application key
        final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
        if (applicationVersion == null || !applicationVersion.getSupported() || applicationVersion.getApplication() == null) {
            logger.warn("Application version is incorrect, application key: {}", applicationKey);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }
        return applicationVersion;
    }

    private ActivationRecordEntity findActivation(String activationId) throws GenericServiceException {
        if (activationId == null) {
            return null;
        }
        return activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, database is not used for writing
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });
    }

}
