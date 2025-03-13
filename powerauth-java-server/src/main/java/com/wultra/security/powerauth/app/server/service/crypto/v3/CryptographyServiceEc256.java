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
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.crypto.BasePublicKey;
import com.wultra.security.powerauth.app.server.service.model.crypto.EcKeyPair;
import com.wultra.security.powerauth.app.server.service.model.crypto.BaseKeyPair;
import com.wultra.security.powerauth.app.server.service.model.crypto.EcPublicKey;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationVersion;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.ECPublicKeyFingerprint;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
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
import java.util.Date;

/**
 * Cryptography Service V3 implementation based on EC curve P-256.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class CryptographyServiceEc256 implements CryptographyService {

    private final MasterKeyPairRepository masterKeyPairRepository;
    private final LocalizationProvider localizationProvider;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final TemporaryKeyServiceEc256 temporaryKeyService;
    private final EncryptionServiceEc256 encryptionService;

    private final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private final PowerAuthServerKeyFactory SERVER_KEY_FACTORY = new PowerAuthServerKeyFactory();

    @Override
    public void generateMasterKeyPair(ApplicationEntity application) throws GenericServiceException {
        try {
            final KeyGenerator keyGen = new KeyGenerator();
            final KeyPair kp = keyGen.generateKeyPair(EcCurve.P256);
            final PrivateKey privateKey = kp.getPrivate();
            final PublicKey publicKey = kp.getPublic();

            final MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
            keyPair.setApplication(application);
            keyPair.setMasterKeyPrivateBase64(Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPrivateKeyToBytes(privateKey)));
            keyPair.setMasterKeyPublicBase64(Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, publicKey)));
            keyPair.setTimestampCreated(new Date());
            keyPair.setName(application.getId() + " Default Keypair");
            masterKeyPairRepository.save(keyPair);
        } catch (CryptoProviderException e) {
            logger.error("Could not generate keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public BaseKeyPair getMasterKeyPair(ApplicationEntity application) throws GenericServiceException {
        final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId());
        if (masterKeyPairEntity == null) {
            logger.error("Missing key pair for application ID: {}", application.getId());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
        try {
            final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();
            final byte[] masterPrivateKeyBytes = Base64.getDecoder().decode(masterPrivateKeyBase64);
            final PrivateKey privateKey = KEY_CONVERTOR.convertBytesToPrivateKey(EcCurve.P256, masterPrivateKeyBytes);
            final String masterPublicKeyBase64 = masterKeyPairEntity.getMasterKeyPublicBase64();
            final byte[] masterPublicKeyBytes = Base64.getDecoder().decode(masterPublicKeyBase64);
            final PublicKey publicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, masterPublicKeyBytes);
            final KeyPair keyPair = new KeyPair(publicKey, privateKey);
            return EcKeyPair.builder().ecKeyPair(keyPair).build();
        } catch (InvalidKeySpecException e) {
            logger.error("Invalid key format", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Invalid keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }
    }

    @Override
    public SecretKey generateSharedSecretKey(ActivationRecordEntity activation) throws GenericServiceException {
        try {
            // Decrypt server private key (depending on encryption mode)
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());

            // Decode the keys to byte[]
            final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PrivateKey serverPrivateKey = KEY_CONVERTOR.convertBytesToPrivateKey(EcCurve.P256, serverPrivateKeyBytes);
            final PublicKey devicePublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, devicePublicKeyBytes);

            // Compute the master secret key
            return SERVER_KEY_FACTORY.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            logger.error("Invalid keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Key conversion failed", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public void generateDeviceKeyPair(ActivationRecordEntity activation) throws GenericServiceException {
        try {
            final KeyPair serverKeyPair = KEY_GENERATOR.generateKeyPair(EcCurve.P256);

            final byte[] serverKeyPrivateBytes = KEY_CONVERTOR.convertPrivateKeyToBytes(serverKeyPair.getPrivate());
            final byte[] serverKeyPublicBytes = KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, serverKeyPair.getPublic());

            activation.setServerPublicKeyBase64(Base64.getEncoder().encodeToString(serverKeyPublicBytes));

            // Convert server private key to DB columns serverPrivateKeyEncryption specifying encryption mode and serverPrivateKey with base64-encoded key.
            final ServerPrivateKey serverPrivateKey = serverPrivateKeyConverter.toDBValue(serverKeyPrivateBytes, activation.getUserId(), activation.getActivationId());
            activation.setServerPrivateKeyEncryption(serverPrivateKey.encryptionMode());
            activation.setServerPrivateKeyBase64(serverPrivateKey.serverPrivateKeyBase64());
        } catch (CryptoProviderException e) {
            logger.error("Could not generate keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public void storeDevicePublicKey(ActivationRecordEntity activation, BasePublicKey devicePublicKey) throws GenericServiceException {
        try {
            // The device public key is converted back to bytes and base64 encoded so that the key is saved in normalized form
            final PublicKey ecPublicKey = ((EcPublicKey) devicePublicKey).getEcPublicKey();
            activation.setDevicePublicKeyBase64(Base64.getEncoder().encodeToString(KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P256, ecPublicKey)));
        } catch (CryptoProviderException e) {
            logger.error("Could not store device public key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public String generateActivationFingerprint(ActivationRecordEntity activation) throws GenericServiceException {
        try {
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final ECPublicKey devicePublicKey = (ECPublicKey) KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, devicePublicKeyBytes);
            final byte[] serverPublicKeyBytes = Base64.getDecoder().decode(activation.getServerPublicKeyBase64());
            final ECPublicKey serverPublicKey = (ECPublicKey) KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, serverPublicKeyBytes);
            return ECPublicKeyFingerprint.compute(devicePublicKey, serverPublicKey, activation.getActivationId(), ActivationVersion.VERSION_3);
        } catch (InvalidKeySpecException e) {
            logger.error("Invalid key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Could not calculate activation fingerprint", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public byte[] generateSignatureForApplication(byte[] data, ApplicationEntity application) throws GenericServiceException {
        try {
            final EcKeyPair keyPair = (EcKeyPair) getMasterKeyPair(application);
            return SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, data, keyPair.getEcKeyPair().getPrivate());
        } catch (CryptoProviderException | GenericCryptoException | InvalidKeyException e) {
            logger.error("Invalid keypair", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public byte[] generateSignatureForActivation(byte[] data, ActivationRecordEntity activation) throws GenericServiceException {
        try {
            // Decrypt server private key (depending on encryption mode)
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activation.getActivationId());
            final PrivateKey serverPrivateKey = KEY_CONVERTOR.convertBytesToPrivateKey(EcCurve.P256, Base64.getDecoder().decode(serverPrivateKeyBase64));

            // Sign data with the private key
            return SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, data, serverPrivateKey);
        } catch (InvalidKeyException | InvalidKeySpecException e) {
            logger.error("Invalid key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Could not generate signature", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public boolean verifySignatureForActivation(byte[] data, byte[] signature, ActivationRecordEntity activation) throws GenericServiceException {
        try {
            final byte[] devicePublicKeyData = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, devicePublicKeyData);
            return SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, data, signature, devicePublicKey);
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            logger.error("Invalid key", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (CryptoProviderException | GenericCryptoException e) {
            logger.error("Could not verify signature", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

    @Override
    public DecryptionResult decryptRequest(EncryptedRequest encryptedRequest, EncryptionContext context) throws GenericServiceException {
        try {
            final DecryptionResult decryptionResult = encryptionService.decrypt(
                    encryptedRequest,
                    context.getProtocolVersion(),
                    context.getApplicationKey(),
                    context.getActivationId(),
                    context.getEncryptorId(),
                    true
            );
            final byte[] decrypted = decryptionResult.getServerEncryptor().decryptRequest(encryptedRequest);
            decryptionResult.setDecryptedData(decrypted);
            return decryptionResult;
        } catch (EncryptorException e) {
            logger.error("Decryption failed", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }
    }

    @Override
    public EncryptorSecrets deriveSecrets(EncryptedRequest encryptedRequest, EncryptionContext context) throws GenericServiceException {
        try {
            final DecryptionResult decryptionResult = encryptionService.decrypt(
                    encryptedRequest,
                    context.getProtocolVersion(),
                    context.getApplicationKey(),
                    context.getActivationId(),
                    context.getEncryptorId(),
                    false
            );
            return decryptionResult.getServerEncryptor().deriveSecretsForExternalEncryptor(encryptedRequest);
        } catch (EncryptorException e) {
            logger.error("Decryption failed", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }
    }

    @Override
    public String requestTemporaryKey(String jwt) throws GenericServiceException {
        return temporaryKeyService.requestTemporaryKey(jwt);
    }

}
