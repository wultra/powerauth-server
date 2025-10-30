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

import com.wultra.security.powerauth.app.server.converter.ActivationSharedSecretConverter;
import com.wultra.security.powerauth.app.server.converter.MasterPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.converter.ServerPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.*;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;
import com.wultra.security.powerauth.app.server.service.crypto.MasterKeyGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import com.wultra.security.powerauth.app.server.service.model.crypto.EcPublicKey;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.ActivationVersion;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.HybridPublicKeyFingerprint;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Cryptography Service V4 implementation based on EC curve P-384.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class CryptographyServiceEc384 extends CryptographyService {

    private final MasterKeyGenerationService masterKeyGenerationService;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final LocalizationProvider localizationProvider;
    private final MasterPrivateKeysConverter masterPrivateKeysConverter;
    private final ServerPrivateKeysConverter serverPrivateKeysConverter;
    private final ActivationSharedSecretConverter sharedSecretConverter;
    private final PublicKeysConverter publicKeysConverter;

    private final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();

    @Override
    public void generateMasterKeyPair(ApplicationEntity application) throws GenericServiceException {
        masterKeyGenerationService.generateMasterKeyPairs(application);
    }

    @Override
    public KeyPair getMasterKeyPair(KeyType keyType, ApplicationEntity application) throws GenericServiceException {
        if (keyType != KeyType.ECDSA_P384) {
            logger.error("Unsupported key type in master keypair request: {}", keyType);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
        if (masterKeyPairEntity == null) {
            logger.error("Missing master key pair for application ID: {}", application.getId());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
        try {
            String masterPrivateKeysBase64 = masterKeyPairEntity.getMasterPrivateKeys();
            if (masterPrivateKeysBase64 == null) {
                // In case of upgrade to V4, keys need to be generated dynamically
                generateMasterKeyPair(application);
                masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
                masterPrivateKeysBase64 = masterKeyPairEntity.getMasterPrivateKeys();
            }
            final EncryptionMode masterPrivateKeysEncryption = masterKeyPairEntity.getMasterPrivateKeysEncryption();
            final PrivateKeys privateKeys = new PrivateKeys(masterPrivateKeysEncryption, masterPrivateKeysBase64);
            final PrivateKeyRegistry privateKeyRegistry = masterPrivateKeysConverter.fromDBValue(privateKeys, application.getId());
            final PrivateKey privateKey = privateKeyRegistry.getPrivateKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing master private key for application ID: {}", application.getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            });
            final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(masterKeyPairEntity.getMasterPublicKeys());
            final PublicKey publicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing master public key for application ID: {}", application.getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            });
            return new KeyPair(publicKey, privateKey);
        } catch (GenericServiceException e) {
            logger.error("Invalid master key pair for application ID: {}", application.getId());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
    }

    @Override
    public SecretKey deriveSharedSecretKey(ActivationRecordEntity activation) throws GenericServiceException {
        final SharedSecret sharedSecret = new SharedSecret(activation.getSharedSecretEncryption(), activation.getSharedSecret());
        final String activationSecretBase64 = sharedSecretConverter.fromDBValue(sharedSecret, activation.getUserId(), activation.getActivationId());
        final byte[] activationSecretBytes = Base64.getDecoder().decode(activationSecretBase64);
        return KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(activationSecretBytes);
    }

    @Override
    public BasePublicKey convertDevicePublicKey(KeyType keyType, byte[] devicePublicKey) throws GenericServiceException {
        if (keyType != KeyType.ECDSA_P384) {
            logger.error("Unsupported key type in device public key conversion: {}", keyType);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        try {
            final PublicKey convertedPublicKey = KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, devicePublicKey);
            return EcPublicKey.builder().ecPublicKey(convertedPublicKey).build();
        } catch (InvalidKeySpecException e) {
            logger.error("Invalid device public key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Key conversion failed", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public void storeDevicePublicKey(ActivationRecordEntity activation, BasePublicKey devicePublicKey) throws GenericServiceException {
        // The device public key is stored in JSON format in column device_public_keys
        final PublicKey ecPublicKey = ((EcPublicKey) devicePublicKey).getEcPublicKey();
        final PublicKeyRegistry publicKeys;
        if (activation.getDevicePublicKeys() != null) {
            publicKeys = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
        } else {
            publicKeys = new PublicKeyRegistry();
        }
        publicKeys.storePublicKey(KeyType.ECDSA_P384, ecPublicKey);
        activation.setDevicePublicKeys(publicKeysConverter.toDBValue(publicKeys));
    }

    @Override
    public String generateActivationFingerprint(ActivationRecordEntity activation) throws GenericServiceException {
        try {
            final PublicKeyRegistry devicePublicKeyRegistry = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
            final ECPublicKey devicePublicKey = (ECPublicKey) devicePublicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing device public key for application ID: {}", activation.getApplication().getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            final PublicKeyRegistry serverPublicKeyRegistry = publicKeysConverter.fromDBValue(activation.getServerPublicKeys());
            final ECPublicKey serverPublicKey = (ECPublicKey) serverPublicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing server public key for application ID: {}", activation.getApplication().getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            return HybridPublicKeyFingerprint.computeEcdsaFingerprint(devicePublicKey, serverPublicKey, activation.getActivationId(), ActivationVersion.VERSION_4);
        } catch (GenericCryptoException e) {
            logger.error("Could not calculate activation fingerprint", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public byte[] generateSignatureForApplication(KeyType keyType, byte[] data, ApplicationEntity application) throws GenericServiceException {
        if (keyType != KeyType.ECDSA_P384) {
            logger.error("Unsupported key type in application signature: {}", keyType);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        try {
            final KeyPair keyPair = getMasterKeyPair(keyType, application);
            return SIGNATURE_UTILS.computeECDSASignature(EcCurve.P384, data, keyPair.getPrivate());
        } catch (CryptoProviderException | GenericCryptoException | InvalidKeyException e) {
            logger.error("Invalid keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public byte[] generateSignatureForActivation(KeyType keyType, byte[] data, ActivationRecordEntity activation) throws GenericServiceException {
        if (keyType != KeyType.ECDSA_P384) {
            logger.error("Unsupported key type in activation signature: {}", keyType);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        try {
            final PrivateKeys privateKeys = new PrivateKeys(activation.getServerPrivateKeysEncryption(), activation.getServerPrivateKeys());
            final PrivateKeyRegistry privateKeyRegistry = serverPrivateKeysConverter.fromDBValue(privateKeys, activation.getUserId(), activation.getActivationId());
            final PrivateKey serverPrivateKey = privateKeyRegistry.getPrivateKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing server private key for activation ID: {}", activation.getActivationId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            return SIGNATURE_UTILS.computeECDSASignature(EcCurve.P384, data, serverPrivateKey);
        } catch (InvalidKeyException e) {
            logger.error("Invalid key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Could not generate signature", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public boolean verifySignatureForActivation(KeyType keyType, byte[] data, byte[] signature, ActivationRecordEntity activation) throws GenericServiceException {
        if (keyType != KeyType.ECDSA_P384) {
            logger.error("Unsupported key type in signature verification: {}", keyType);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        try {
            final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
            final PublicKey devicePublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing device public key for application ID: {}", activation.getApplication().getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            return SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, data, signature, devicePublicKey);
        } catch (InvalidKeyException e) {
            logger.error("Invalid key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Could not verify signature", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

}
