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
package io.getlime.security.powerauth.app.server.service.encryption;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.stereotype.Service;

import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
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
     * Decrypt the given data.
     *
     * @param data Data to decrypt.
     * @param encryptionMode Encryption mode.
     * @param secretKeyDerivationInput Values used for derivation of secret key.
     * @return Decrypted value.
     * @throws GenericServiceException In case decryption fails.
     */
    public byte[] decrypt(final byte[] data, final EncryptionMode encryptionMode, final List<String> secretKeyDerivationInput) throws GenericServiceException {
        if (encryptionMode == null) {
            logger.error("Missing key encryption mode");
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
                    throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_MASTER_DB_ENCRYPTION_KEY);
                }
                try {
                    // Convert master DB encryption key
                    final SecretKey masterDbEncryptionKey = keyConvertor.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

                    // Derive secret key from master DB encryption key, userId and activationId
                    final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, secretKeyDerivationInput);

                    // Check that the length of the byte array is sufficient to avoid AIOOBE on the next calls
                    if (data.length < 16) {
                        logger.error("Invalid encrypted data hash format - the byte array is too short");
                        throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
                    }

                    // IV is present in first 16 bytes
                    final byte[] iv = Arrays.copyOfRange(data, 0, 16);

                    // Encrypted data hash is present after IV
                    final byte[] encryptedData = Arrays.copyOfRange(data, 16, data.length);

                    return aesEncryptionUtils.decrypt(encryptedData, iv, secretKey);
                } catch (InvalidKeyException ex) {
                    logger.error(ex.getMessage(), ex);
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
                } catch (GenericCryptoException ex) {
                    logger.error(ex.getMessage(), ex);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                } catch (CryptoProviderException ex) {
                    logger.error(ex.getMessage(), ex);
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
                }
            }
            default -> {
                logger.error("Unknown key encryption mode: {}", encryptionMode.getValue());
                throw localizationProvider.buildExceptionForCode(ServiceError.UNSUPPORTED_ENCRYPTION_MODE);
            }
        }
    }

    /**
     * Encrypt the given data.
     *
     * @param data Data to encrypt.
     * @param secretKeyDerivations Values used for derivation of secret key.
     * @return Encryptable composite data.
     * @throws GenericServiceException Thrown when encryption fails.
     */
    public Encryptable encrypt(final byte[] data, final List<String> secretKeyDerivations) throws GenericServiceException {
        final String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

        // In case master DB encryption key does not exist, do not encrypt the value
        if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
            return new EncryptableRecord(EncryptionMode.NO_ENCRYPTION, data);
        }

        try {
            // Convert master DB encryption key
            final SecretKey masterDbEncryptionKey = keyConvertor.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

            // Derive secret key from master DB encryption key, userId and activationId
            final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, secretKeyDerivations);

            // Generate random IV
            final byte[] iv = keyGenerator.generateRandomBytes(16);

            // Encrypt serverPrivateKey using secretKey with generated IV
            final byte[] encrypted = aesEncryptionUtils.encrypt(data, iv, secretKey);

            // Generate output bytes as encrypted + IV
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(iv);
            baos.write(encrypted);
            final byte[] encryptedData = baos.toByteArray();

            return new EncryptableRecord(EncryptionMode.AES_HMAC, encryptedData);
        } catch (InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
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

    private record EncryptableRecord(EncryptionMode encryptionMode, byte[] encryptedData) implements Encryptable {
        @Override
        public EncryptionMode getEncryptionMode() {
            return encryptionMode;
        }

        @Override
        public byte[] getEncryptedData() {
            return encryptedData;
        }

        @Override
        public String toString() {
            return "EncryptableRecord{" +
                "encryptionMode=" + encryptionMode +
                ", encryptedDataLength=" + ArrayUtils.getLength(encryptedData) +
                '}';
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof final EncryptableRecord that)) {
                return false;
            }
            return Objects.deepEquals(encryptedData, that.encryptedData) && encryptionMode == that.encryptionMode;
        }

        @Override
        public int hashCode() {
            return Objects.hash(encryptionMode, Arrays.hashCode(encryptedData));
        }
    }

}
