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
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.crypto.*;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.ActivationVersion;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.HybridPublicKeyFingerprint;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import com.wultra.security.powerauth.crypto.server.v4.activation.PowerAuthServerActivation;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
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
 * Cryptography Service V4 implementation based on hybrid scheme with EC curve P-384 and ML-DSA-65.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class CryptographyServiceHybrid extends CryptographyService {

    private final MasterKeyPairRepository masterKeyPairRepository;
    private final LocalizationProvider localizationProvider;
    private final MasterPrivateKeysConverter masterPrivateKeysConverter;
    private final ServerPrivateKeysConverter serverPrivateKeysConverter;
    private final ActivationSharedSecretConverter sharedSecretConverter;
    private final PublicKeysConverter publicKeysConverter;

    private final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new PqcDsaKeyConvertor();
    private final PqcDsa PQC_DSA = new MlDsa();

    private final PowerAuthServerActivation SERVER_ACTIVATION = new PowerAuthServerActivation();

    @Autowired
    public CryptographyServiceHybrid(MasterKeyPairRepository masterKeyPairRepository, LocalizationProvider localizationProvider, MasterPrivateKeysConverter masterPrivateKeysConverter, ServerPrivateKeysConverter serverPrivateKeysConverter, ActivationSharedSecretConverter sharedSecretConverter, PublicKeysConverter publicKeysConverter) {
        this.masterKeyPairRepository = masterKeyPairRepository;
        this.localizationProvider = localizationProvider;
        this.masterPrivateKeysConverter = masterPrivateKeysConverter;
        this.serverPrivateKeysConverter = serverPrivateKeysConverter;
        this.sharedSecretConverter = sharedSecretConverter;
        this.publicKeysConverter = publicKeysConverter;
    }

    @Override
    public void generateMasterKeyPair(ApplicationEntity application) throws GenericServiceException {
        try {
            // Generate PQC key pair
            final KeyPair kpPqcDsa = SERVER_ACTIVATION.generatePqcServerKeyPair();
            final PrivateKey privateKeyPqcDsa = kpPqcDsa.getPrivate();
            final PublicKey publicKeyPqcDsa = kpPqcDsa.getPublic();

            // Key pairs for multiple algorithms are stored for the same entity in order:
            // 1. EC_P256 (ECDSA keypair)
            // 2. EC_P384 (ECDSA keypair)
            // 3. EC_P384_ML_L3 (ECDSA keypair and MLDSA keypair, ECDSA keypair is reused from algorithm EC_P384)
            MasterKeyPairEntity keyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
            if (keyPair == null) {
                logger.error("Key pair generation called in invalid order");
                throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            }
            final PrivateKeys privateKeys = new PrivateKeys(keyPair.getMasterPrivateKeysEncryption(), keyPair.getMasterPrivateKeys());
            final PrivateKeyRegistry privateKeyRegistry = masterPrivateKeysConverter.fromDBValue(privateKeys, application.getId());
            final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(keyPair.getMasterPublicKeys());

            // Store private and public keys for ML-DSA in JSON format
            privateKeyRegistry.storePrivateKey(KeyType.MLDSA_65, privateKeyPqcDsa);
            final PrivateKeys masterPrivateKeys = masterPrivateKeysConverter.toDBValue(privateKeyRegistry, application.getId());
            keyPair.setMasterPrivateKeys(masterPrivateKeys.privateKeysBase64());
            keyPair.setMasterPrivateKeysEncryption(masterPrivateKeys.encryptionMode());
            publicKeyRegistry.storePublicKey(KeyType.MLDSA_65, publicKeyPqcDsa);
            final String publicKeys384Json = publicKeysConverter.toDBValue(publicKeyRegistry);
            keyPair.setMasterPublicKeys(publicKeys384Json);
            masterKeyPairRepository.save(keyPair);
        } catch (CryptoProviderException e) {
            logger.error("Could not generate keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public KeyPair getMasterKeyPair(KeyType keyType, ApplicationEntity application) throws GenericServiceException {
        if (keyType != KeyType.ECDSA_P384 && keyType != KeyType.MLDSA_65) {
            logger.error("Unsupported key type in master keypair request: {}", keyType);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
        if (masterKeyPairEntity == null) {
            logger.error("Missing master key pair for application ID: {}", application.getId());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
        try {
            final String masterPrivateKeysBase64 = masterKeyPairEntity.getMasterPrivateKeys();
            final EncryptionMode masterPrivateKeysEncryption = masterKeyPairEntity.getMasterPrivateKeysEncryption();
            final PrivateKeys privateKeys = new PrivateKeys(masterPrivateKeysEncryption, masterPrivateKeysBase64);
            final PrivateKeyRegistry privateKeyRegistry = masterPrivateKeysConverter.fromDBValue(privateKeys, application.getId());
            final PrivateKey privateKey = privateKeyRegistry.getPrivateKey(keyType).orElseThrow(() -> {
                logger.error("Missing master private key for application ID: {}", application.getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            });
            final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(masterKeyPairEntity.getMasterPublicKeys());
            final PublicKey publicKey = publicKeyRegistry.getPublicKey(keyType).orElseThrow(() -> {
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
    public void generateServerKeyPair(ActivationRecordEntity activation) throws GenericServiceException {
        try {
            final KeyPair serverKeyPairEc = SERVER_ACTIVATION.generateEcServerKeyPair();
            final KeyPair serverKeyPairPqc = SERVER_ACTIVATION.generatePqcServerKeyPair();

            // Store server public key in JSON format
            final PublicKeyRegistry serverPublicKeys = new PublicKeyRegistry();
            serverPublicKeys.storePublicKey(KeyType.ECDSA_P384, serverKeyPairEc.getPublic());
            serverPublicKeys.storePublicKey(KeyType.MLDSA_65, serverKeyPairPqc.getPublic());
            activation.setServerPublicKeys(publicKeysConverter.toDBValue(serverPublicKeys));

            // Store server private key in JSON format
            final PrivateKeyRegistry serverPrivateKeys = new PrivateKeyRegistry();
            serverPrivateKeys.storePrivateKey(KeyType.ECDSA_P384, serverKeyPairEc.getPrivate());
            serverPrivateKeys.storePrivateKey(KeyType.MLDSA_65, serverKeyPairPqc.getPrivate());
            final PrivateKeys privateKeys = serverPrivateKeysConverter.toDBValue(serverPrivateKeys, activation.getUserId(), activation.getActivationId());
            activation.setServerPrivateKeysEncryption(privateKeys.encryptionMode());
            activation.setServerPrivateKeys(privateKeys.privateKeysBase64());
        } catch (CryptoProviderException e) {
            logger.error("Could not generate keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public BasePublicKey convertDevicePublicKey(KeyType keyType, byte[] devicePublicKey) throws GenericServiceException {
        try {
            switch (keyType) {
                case ECDSA_P384 -> {
                    final PublicKey convertedPublicKey = KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, devicePublicKey);
                    return EcPublicKey.builder().ecPublicKey(convertedPublicKey).build();
                }
                case MLDSA_65 -> {
                    final PublicKey convertedPublicKey = KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(devicePublicKey);
                    return PqcPublicKey.builder().pqcPublicKey(convertedPublicKey).build();
                }
                default -> {
                    logger.error("Unsupported key type when converting device public key: {}", keyType);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
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
        if (devicePublicKey instanceof EcPublicKey ecDevicePublicKey) {
            final PublicKey ecPublicKey = ecDevicePublicKey.getEcPublicKey();
            final PublicKeyRegistry publicKeys;
            if (activation.getDevicePublicKeys() != null) {
                publicKeys = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
            } else {
                publicKeys = new PublicKeyRegistry();
            }
            publicKeys.storePublicKey(KeyType.ECDSA_P384, ecPublicKey);
            activation.setDevicePublicKeys(publicKeysConverter.toDBValue(publicKeys));
            return;
        }
        if (devicePublicKey instanceof PqcPublicKey pqcDevicePublicKey) {
            final PublicKey pqcPublicKey = pqcDevicePublicKey.getPqcPublicKey();
            final PublicKeyRegistry publicKeys;
            if (activation.getDevicePublicKeys() != null) {
                publicKeys = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
            } else {
                publicKeys = new PublicKeyRegistry();
            }
            publicKeys.storePublicKey(KeyType.MLDSA_65, pqcPublicKey);
            activation.setDevicePublicKeys(publicKeysConverter.toDBValue(publicKeys));
            return;
        }
        logger.error("Unsupported key type: {}", devicePublicKey.getClass());
        throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
    }

    @Override
    public String generateActivationFingerprint(ActivationRecordEntity activation) throws GenericServiceException {
        try {
            final PublicKeyRegistry devicePublicKeyRegistry = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
            final ECPublicKey devicePublicKeyEcdsa = (ECPublicKey) devicePublicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing ECDSA device public key for application ID: {}", activation.getApplication().getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            final MLDSAPublicKey devicePublicKeyMldsa = (MLDSAPublicKey) devicePublicKeyRegistry.getPublicKey(KeyType.MLDSA_65).orElseThrow(() -> {
                logger.error("Missing ML-DSA device public key for application ID: {}", activation.getApplication().getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            final PublicKeyRegistry serverPublicKeyRegistry = publicKeysConverter.fromDBValue(activation.getServerPublicKeys());
            final ECPublicKey serverPublicKeyEcdsa = (ECPublicKey) serverPublicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                logger.error("Missing ECDSA server public key for application ID: {}", activation.getApplication().getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            final MLDSAPublicKey serverPublicKeyMldsa = (MLDSAPublicKey) serverPublicKeyRegistry.getPublicKey(KeyType.MLDSA_65).orElseThrow(() -> {
                logger.error("Missing ML-DSA server public key for application ID: {}", activation.getApplication().getId());
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            });
            return HybridPublicKeyFingerprint.computeHybridFingerprint(devicePublicKeyEcdsa, devicePublicKeyMldsa, serverPublicKeyEcdsa, serverPublicKeyMldsa, activation.getActivationId(), ActivationVersion.VERSION_4);
        } catch (GenericCryptoException e) {
            logger.error("Could not calculate activation fingerprint", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public byte[] generateSignatureForApplication(KeyType keyType, byte[] data, ApplicationEntity application) throws GenericServiceException {
        return switch (keyType) {
            case ECDSA_P384 -> {
                try {
                    final KeyPair keyPair = getMasterKeyPair(keyType, application);
                    yield SIGNATURE_UTILS.computeECDSASignature(EcCurve.P384, data, keyPair.getPrivate());
                } catch (CryptoProviderException | GenericCryptoException | InvalidKeyException e) {
                    logger.error("Invalid keypair", e);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            case MLDSA_65 -> {
                try {
                    final KeyPair keyPair = getMasterKeyPair(keyType, application);
                    yield PQC_DSA.sign(keyPair.getPrivate(), data);
                } catch (GenericCryptoException e) {
                    logger.error("Could not generate signature", e);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            default -> {
                logger.error("Unsupported key type in application signature: {}", keyType);
                throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            }
        };
    }

    @Override
    public byte[] generateSignatureForActivation(KeyType keyType, byte[] data, ActivationRecordEntity activation) throws GenericServiceException {
        return switch (keyType) {
            case ECDSA_P384 -> {
                try {
                    final PrivateKeys privateKeys = new PrivateKeys(activation.getServerPrivateKeysEncryption(), activation.getServerPrivateKeys());
                    final PrivateKeyRegistry privateKeyRegistry = serverPrivateKeysConverter.fromDBValue(privateKeys, activation.getUserId(), activation.getActivationId());
                    final PrivateKey serverPrivateKey = privateKeyRegistry.getPrivateKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                        logger.error("Missing server ECDSA private key for activation ID: {}", activation.getActivationId());
                        // Rollback is not required, database is not used for writing
                        return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                    });
                    yield SIGNATURE_UTILS.computeECDSASignature(EcCurve.P384, data, serverPrivateKey);
                } catch (CryptoProviderException | GenericCryptoException | InvalidKeyException e) {
                    logger.error("Invalid keypair", e);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            case MLDSA_65 -> {
                try {
                    final PrivateKeys privateKeys = new PrivateKeys(activation.getServerPrivateKeysEncryption(), activation.getServerPrivateKeys());
                    final PrivateKeyRegistry privateKeyRegistry = serverPrivateKeysConverter.fromDBValue(privateKeys, activation.getUserId(), activation.getActivationId());
                    final PrivateKey serverPrivateKey = privateKeyRegistry.getPrivateKey(KeyType.MLDSA_65).orElseThrow(() -> {
                        logger.error("Missing server ML-DSA private key for activation ID: {}", activation.getActivationId());
                        // Rollback is not required, database is not used for writing
                        return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                    });
                    yield PQC_DSA.sign(serverPrivateKey, data);
                } catch (GenericCryptoException e) {
                    logger.error("Could not generate signature", e);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            default -> {
                logger.error("Unsupported key type in activation signature: {}", keyType);
                throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            }
        };
    }

    @Override
    public boolean verifySignatureForActivation(KeyType keyType, byte[] data, byte[] signature, ActivationRecordEntity activation) throws GenericServiceException {
        return switch (keyType) {
            case ECDSA_P384 -> {
                try {
                    final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
                    final PublicKey devicePublicKey = publicKeyRegistry.getPublicKey(KeyType.ECDSA_P384).orElseThrow(() -> {
                        logger.error("Missing device public key for ECDSA for activation ID: {}", activation.getActivationId());
                        // Rollback is not required, database is not used for writing
                        return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                    });
                    yield SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, data, signature, devicePublicKey);
                } catch (CryptoProviderException | GenericCryptoException | InvalidKeyException e) {
                    logger.error("Invalid keypair", e);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            case MLDSA_65 -> {
                try {
                    final PublicKeyRegistry publicKeyRegistry = publicKeysConverter.fromDBValue(activation.getDevicePublicKeys());
                    final PublicKey devicePublicKey = publicKeyRegistry.getPublicKey(KeyType.MLDSA_65).orElseThrow(() -> {
                        logger.error("Missing device public key for ML-DSA for activation ID: {}", activation.getActivationId());
                        // Rollback is not required, database is not used for writing
                        return localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                    });
                    yield PQC_DSA.verify(devicePublicKey, data, signature);
                } catch (GenericCryptoException e) {
                    logger.error("Could not generate signature", e);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            default -> {
                logger.error("Unsupported key type in signature verification: {}", keyType);
                throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
            }
        };
    }

}
