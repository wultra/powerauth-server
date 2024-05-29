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
package io.getlime.security.powerauth.app.server.converter;

import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPuk;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Converter for recovery PUK which handles record encryption and decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class RecoveryPukConverter {

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final LocalizationProvider localizationProvider;

    // Utility classes for crypto
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final AESEncryptionUtils aesEncryptionUtils = new AESEncryptionUtils();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    @Autowired
    public RecoveryPukConverter(PowerAuthServiceConfiguration powerAuthServiceConfiguration, LocalizationProvider localizationProvider) {
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
        this.localizationProvider = localizationProvider;
    }

    /**
     * Convert recovery PUK hash from composite database value to string value.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param pukHash Recovery PUK hash composite database value including PUK hash and encryption mode.
     * @param applicationRid Application RID used for derivation of secret key.
     * @param userId User ID used for derivation of secret key.
     * @param recoveryCode Recovery code used for derivation of secret key.
     * @param pukIndex Recovery PUK index used for derivation of secret key.
     * @return Decrypted recovery PUK hash.
     * @throws GenericServiceException In case recovery PUK hash decryption fails.
     */
    public String fromDBValue(RecoveryPuk pukHash, long applicationRid, String userId, String recoveryCode, long pukIndex) throws GenericServiceException {
        final String pukHashFromDB = pukHash.pukHash();
        final EncryptionMode encryptionMode = pukHash.encryptionMode();
        if (encryptionMode == null) {
            logger.error("Missing key encryption mode");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.UNSUPPORTED_ENCRYPTION_MODE);
        }

        switch (encryptionMode) {
            case NO_ENCRYPTION -> {
                return pukHashFromDB;
            }
            case AES_HMAC -> {
                final String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

                // In case master DB encryption key does not exist, do not encrypt the server private key
                if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
                    logger.error("Missing master DB encryption key");
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_MASTER_DB_ENCRYPTION_KEY);
                }
                try {
                    // Convert master DB encryption key
                    final SecretKey masterDbEncryptionKey = keyConvertor.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

                    // Derive secret key from master DB encryption key, userId and activationId
                    final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, applicationRid, userId, recoveryCode, pukIndex);

                    // Base64-decode PUK hash
                    final byte[] pukHashBytes = Base64.getDecoder().decode(pukHashFromDB);

                    // Check that the length of the byte array is sufficient to avoid AIOOBE on the next calls
                    if (pukHashBytes.length < 16) {
                        logger.error("Invalid encrypted PUK hash format - the byte array is too short");
                        // Rollback is not required, error occurs before writing to database
                        throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
                    }

                    // IV is present in first 16 bytes
                    final byte[] iv = Arrays.copyOfRange(pukHashBytes, 0, 16);

                    // Encrypted PUK hash is present after IV
                    final byte[] encryptedPukHash = Arrays.copyOfRange(pukHashBytes, 16, pukHashBytes.length);

                    // Decrypt serverPrivateKey
                    final byte[] decryptedPukHash = aesEncryptionUtils.decrypt(encryptedPukHash, iv, secretKey);

                    // Return decrypted PUK hash
                    return new String(decryptedPukHash, StandardCharsets.UTF_8);

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
            default -> {
                logger.error("Unknown key encryption mode: {}", encryptionMode.getValue());
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNSUPPORTED_ENCRYPTION_MODE);
            }
        }
    }

    /**
     * Convert PUK hash to composite database value. PUK hash is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param pukHash PUK hash to encrypt if master DB encryption key is present.
     * @param applicationRid Application RID used for derivation of secret key.
     * @param userId User ID used for derivation of secret key.
     * @param recoveryCode Recovery code used for derivation of secret key.
     * @param pukIndex Recovery PUK index used for derivation of secret key.
     * @return Server private key as composite database value.
     * @throws GenericServiceException Thrown when server private key encryption fails.
     */
    public RecoveryPuk toDBValue(String pukHash, long applicationRid, String userId, String recoveryCode, long pukIndex) throws GenericServiceException {
        final String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

        // In case master DB encryption key does not exist, do not encrypt the PUK hash
        if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
            return new RecoveryPuk(EncryptionMode.NO_ENCRYPTION, pukHash);
        }

        try {
            // Convert master DB encryption key
            final SecretKey masterDbEncryptionKey = keyConvertor.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

            // Derive secret key from master DB encryption key, userId and activationId
            final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, applicationRid, userId, recoveryCode, pukIndex);

            // Generate random IV
            final byte[] iv = keyGenerator.generateRandomBytes(16);

            // Encrypt serverPrivateKey using secretKey with generated IV
            final byte[] encrypted = aesEncryptionUtils.encrypt(pukHash.getBytes(StandardCharsets.UTF_8), iv, secretKey);

            // Generate output bytes as encrypted + IV
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(iv);
            baos.write(encrypted);
            final byte[] encryptedData = baos.toByteArray();

            // Base64-encode output and create ServerPrivateKey instance
            final String encryptedPukHashBase64 = Base64.getEncoder().encodeToString(encryptedData);

            // Return encrypted record including encryption mode
            return new RecoveryPuk(EncryptionMode.AES_HMAC, encryptedPukHashBase64);

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
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, serialization is executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        }
    }

    /**
     * Derive secret key from master DB encryption key, application ID, user ID, recovery code and puk index.<br/>
     * <br/>
     * See: <a href="https://github.com/wultra/powerauth-server/blob/develop/docs/Encrypting-Records-in-Database.md">...</a>
     *
     * @param masterDbEncryptionKey Master DB encryption key.
     * @param applicationRid Application RID used for derivation of secret key.
     * @param userId User ID used for derivation of secret key.
     * @param recoveryCode Recovery code used for derivation of secret key.
     * @param pukIndex Recovery PUK index used for derivation of secret key.
     * @return Derived secret key.
     * @throws GenericCryptoException In case key derivation fails.
     */
    private SecretKey deriveSecretKey(SecretKey masterDbEncryptionKey, long applicationRid, String userId, String recoveryCode, long pukIndex) throws GenericCryptoException, CryptoProviderException {
        // Use concatenated application ID, user ID, recovery code and PUK index bytes as index for KDF_INTERNAL
        final byte[] index = (applicationRid + "&" + userId + "&" + recoveryCode + "&" + pukIndex).getBytes(StandardCharsets.UTF_8);

        // Derive secretKey from master DB encryption key using KDF_INTERNAL with constructed index
        return keyGenerator.deriveSecretKeyHmac(masterDbEncryptionKey, index);
    }


}
