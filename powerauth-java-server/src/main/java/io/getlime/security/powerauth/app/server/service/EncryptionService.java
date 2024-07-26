/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service;

import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.Encryptable;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Service for encryption and decryption database data.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class EncryptionService {

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final LocalizationProvider localizationProvider;

    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final AESEncryptionUtils aesEncryptionUtils = new AESEncryptionUtils();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Convert encryptable composite database value to string value.
     * <p>
     * The method should be called before writing to the database because the GenericServiceException can be thrown.
     * This could lead to a database inconsistency because the transaction is not rolled back.
     *
     * @param source Ecryptable value.
     * @param secretKeyDerivationInput Values used for derivation of secret key.
     * @return Decrypted value.
     * @throws GenericServiceException In case decryption fails.
     */
    public String fromDBValue(final Encryptable source, final List<String> secretKeyDerivationInput) throws GenericServiceException {
        final String data = source.getEncryptedData();
        final EncryptionMode encryptionMode = source.getEncryptionMode();
        if (encryptionMode == null) {
            logger.error("Missing key encryption mode");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.UNSUPPORTED_ENCRYPTION_MODE);
        }

        switch (encryptionMode) {
            case NO_ENCRYPTION -> {
                return data;
            }
            case AES_HMAC -> {
                final String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

                // In case master DB encryption key does not exist, do not encrypt the value
                if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
                    logger.error("Missing master DB encryption key");
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_MASTER_DB_ENCRYPTION_KEY);
                }
                try {
                    // Convert master DB encryption key
                    final SecretKey masterDbEncryptionKey = keyConvertor.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

                    // Derive secret key from master DB encryption key, userId and activationId
                    final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, secretKeyDerivationInput);

                    // Base64-decode hash
                    final byte[] dataBytes = Base64.getDecoder().decode(data);

                    // Check that the length of the byte array is sufficient to avoid AIOOBE on the next calls
                    if (dataBytes.length < 16) {
                        logger.error("Invalid encrypted data hash format - the byte array is too short");
                        // Rollback is not required, error occurs before writing to database
                        throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
                    }

                    // IV is present in first 16 bytes
                    final byte[] iv = Arrays.copyOfRange(dataBytes, 0, 16);

                    // Encrypted data hash is present after IV
                    final byte[] encryptedData = Arrays.copyOfRange(dataBytes, 16, dataBytes.length);

                    final byte[] decryptedData = aesEncryptionUtils.decrypt(encryptedData, iv, secretKey);

                    // Return decrypted hash
                    return new String(decryptedData, StandardCharsets.UTF_8);

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
     * Convert to encryptable composite database value.
     * <p>
     * Value is encrypted in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown.
     * This could lead to a database inconsistency because the transaction is not rolled back.
     *
     * @param source Value to encrypt if master DB encryption key is present.
     * @param secretKeyDerivations Values used for derivation of secret key.
     * @return Encryptable composite database value.
     * @throws GenericServiceException Thrown when encryption fails.
     */
    public Encryptable toDBValue(final String source, final List<String> secretKeyDerivations) throws GenericServiceException {
        final String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

        // In case master DB encryption key does not exist, do not encrypt the value
        if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
            return new EncryptableRecord(EncryptionMode.NO_ENCRYPTION, source);
        }

        try {
            // Convert master DB encryption key
            final SecretKey masterDbEncryptionKey = keyConvertor.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

            // Derive secret key from master DB encryption key, userId and activationId
            final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, secretKeyDerivations);

            // Generate random IV
            final byte[] iv = keyGenerator.generateRandomBytes(16);

            // Encrypt serverPrivateKey using secretKey with generated IV
            final byte[] encrypted = aesEncryptionUtils.encrypt(source.getBytes(StandardCharsets.UTF_8), iv, secretKey);

            // Generate output bytes as encrypted + IV
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(iv);
            baos.write(encrypted);
            final byte[] encryptedData = baos.toByteArray();

            final String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedData);

            // Return encrypted data including encryption mode
            return new EncryptableRecord(EncryptionMode.AES_HMAC, encryptedBase64);

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
     * Derive secret key from master DB encryption key and the given derivations.
     *
     * @param masterDbEncryptionKey Master DB encryption key.
     * @param secretKeyDerivations Values used for derivation of secret key.
     * @return Derived secret key.
     * @throws GenericCryptoException In case key derivation fails.
     * @see <a href="https://github.com/wultra/powerauth-server/blob/develop/docs/Encrypting-Records-in-Database.md">Encrypting Records in Database</a>
     */
    private SecretKey deriveSecretKey(SecretKey masterDbEncryptionKey, final List<String> secretKeyDerivations) throws GenericCryptoException, CryptoProviderException {
        // Use concatenated value bytes as index for KDF_INTERNAL
        final byte[] index = String.join("&", secretKeyDerivations).getBytes(StandardCharsets.UTF_8);

        // Derive secretKey from master DB encryption key using KDF_INTERNAL with constructed index
        return keyGenerator.deriveSecretKeyHmac(masterDbEncryptionKey, index);
    }

    private record EncryptableRecord(EncryptionMode encryptionMode, String encryptedData) implements Encryptable {
        @Override
        public EncryptionMode getEncryptionMode() {
            return encryptionMode;
        }

        @Override
        public String getEncryptedData() {
            return encryptedData;
        }
    }

}
