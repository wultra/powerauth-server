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

package com.wultra.security.powerauth.app.server.service.crypto.v4;

import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.crypto.EncryptionService;
import com.wultra.security.powerauth.app.server.service.crypto.KeyProvider;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.UniqueValueParam;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResultVaultUnlock;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.replay.ReplayVerificationService;
import com.wultra.security.powerauth.app.server.service.util.ReplayAttackUtils;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.server.v4.keyfactory.PowerAuthServerKeyFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

/**
 * Encryption service for AEAD (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class EncryptionServiceAead extends EncryptionService {

    private final LocalizationProvider localizationProvider;
    private final TemporaryKeyServiceAead temporaryKeyService;
    private final ReplayVerificationService replayVerificationService;
    private final SharedSecretService sharedSecretService;

    private final EncryptorFactory ENCRYPTOR_FACTORY = new EncryptorFactory();
    private final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final PowerAuthServerKeyFactory SERVER_KEY_FACTORY = new PowerAuthServerKeyFactory();
    private final KeyProvider keyProvider;

    @Autowired
    public EncryptionServiceAead(ApplicationVersionRepository applicationVersionRepository, LocalizationProvider localizationProvider, TemporaryKeyServiceAead temporaryKeyService, ActivationQueryService activationQueryService, ReplayVerificationService replayVerificationService, SharedSecretService sharedSecretService, KeyProvider keyProvider) {
        super(localizationProvider, applicationVersionRepository, activationQueryService);
        this.localizationProvider = localizationProvider;
        this.temporaryKeyService = temporaryKeyService;
        this.replayVerificationService = replayVerificationService;
        this.sharedSecretService = sharedSecretService;
        this.keyProvider = keyProvider;
    }

    @Override
    public DecryptionResult decrypt(EncryptedRequest encryptedRequest, String protocolVersion, String applicationKey, String activationId, EncryptorId encryptorId, boolean validateRequestData) throws GenericServiceException {
        try {

            validateEncryptedRequest(encryptedRequest, protocolVersion, validateRequestData);

            final ApplicationVersionEntity applicationVersion = findApplicationVersion(applicationKey);
            final ActivationRecordEntity activation = findActivation(activationId);

            final AeadEncryptedRequest aeadRequest = (AeadEncryptedRequest) encryptedRequest;
            if (activation == null) {
                final UniqueValueParam param = ReplayAttackUtils.deriveUniqueValuesApplicationScope(protocolVersion,  null, aeadRequest.getNonce(), aeadRequest.getTemporaryKeyId(), applicationKey);
                replayVerificationService.checkAndPersistUniqueValue(protocolVersion, new Date(aeadRequest.getTimestamp()), param);
                return decryptInApplicationScope(aeadRequest, protocolVersion, applicationVersion, encryptorId);
            } else {
                final UniqueValueParam param = ReplayAttackUtils.deriveUniqueValuesActivationScope(protocolVersion,  null, aeadRequest.getNonce(), aeadRequest.getTemporaryKeyId(), activationId);
                replayVerificationService.checkAndPersistUniqueValue(protocolVersion, new Date(aeadRequest.getTimestamp()), param);
                return decryptInActivationScope(aeadRequest, protocolVersion, applicationVersion, activation, encryptorId);
            }
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            logger.error("Invalid key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EncryptorException | CryptoProviderException | GenericCryptoException e) {
            logger.error("Decryption failed", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    private DecryptionResult decryptInApplicationScope(AeadEncryptedRequest aeadRequest, String protocolVersion, ApplicationVersionEntity applicationVersion, EncryptorId encryptorId) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException, EncryptorException {
        final SecretKey sharedSecret = temporaryKeyService.extractTemporarySharedSecret(aeadRequest.getTemporaryKeyId(), applicationVersion.getApplicationKey(), null);
        final byte[] sharedSecretBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(sharedSecret);
        final DecryptionResult decryptionResult = new DecryptionResult();
        decryptionResult.setServerEncryptor(ENCRYPTOR_FACTORY.getServerEncryptor(
                encryptorId,
                new EncryptorParameters(protocolVersion, applicationVersion.getApplicationKey(), null, aeadRequest.getTemporaryKeyId()),
                new AeadSecrets(sharedSecretBytes, applicationVersion.getApplicationSecret())
        ));
        decryptionResult.setApplication(applicationVersion.getApplication());
        return decryptionResult;
    }

    private DecryptionResult decryptInActivationScope(AeadEncryptedRequest aeadRequest, String protocolVersion, ApplicationVersionEntity applicationVersion, ActivationRecordEntity activation, EncryptorId encryptorId) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException, EncryptorException, GenericCryptoException, InvalidKeyException {
        // Check that application key from request belongs to same application as activation ID from request
        if (!applicationVersion.getApplication().getRid().equals(activation.getApplication().getRid())) {
            logger.warn("Application version does not match, application key: {}", applicationVersion.getApplicationKey());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        final SecretKey sharedSecret = temporaryKeyService.extractTemporarySharedSecret(aeadRequest.getTemporaryKeyId(), applicationVersion.getApplicationKey(), activation.getActivationId());

        final PrivateKey serverPrivateKey = keyProvider.getServerPrivateKey(activation, KeyType.ECDSA_P384).orElseThrow(() -> localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR));
        final PublicKey devicePublicKey = keyProvider.getDevicePublicKey(activation, KeyType.ECDSA_P384).orElseThrow(() -> localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR));

        final SecretKey activationSecret = sharedSecretService.extractActivationSecretKey(activation);
        final SecretKey sharedInfo2Key = SERVER_KEY_FACTORY.generateSharedInfo2Key(activationSecret);
        final byte[] sharedInfo2KeyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(sharedInfo2Key);

        final DecryptionResult decryptionResult;
        if (encryptorId == EncryptorId.VAULT_UNLOCK) {
            DecryptionResultVaultUnlock decryptionResultVaultUnlock = new DecryptionResultVaultUnlock();
            decryptionResultVaultUnlock.setServerPrivateKey(serverPrivateKey);
            decryptionResultVaultUnlock.setDevicePublicKey(devicePublicKey);
            decryptionResult = decryptionResultVaultUnlock;
        } else {
            decryptionResult = new DecryptionResult();
        }
        decryptionResult.setServerEncryptor(ENCRYPTOR_FACTORY.getServerEncryptor(
                encryptorId,
                new EncryptorParameters(protocolVersion, applicationVersion.getApplicationKey(), activation.getActivationId(), aeadRequest.getTemporaryKeyId()),
                new AeadSecrets(sharedSecret.getEncoded(), applicationVersion.getApplicationSecret(), sharedInfo2KeyBytes)
        ));
        decryptionResult.setApplication(applicationVersion.getApplication());
        return decryptionResult;
    }

}
