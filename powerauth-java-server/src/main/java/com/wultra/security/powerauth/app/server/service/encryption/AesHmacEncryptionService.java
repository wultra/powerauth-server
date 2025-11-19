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

package com.wultra.security.powerauth.app.server.service.encryption;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
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
import java.util.function.Supplier;

/**
 * Service which implements AES-based encryptor with a per-record encryption key derived using 16-byte
 * HMAC for database encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class AesHmacEncryptionService implements DatabaseEncryptor {

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final LocalizationProvider localizationProvider;

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final AESEncryptionUtils AES_ENCRYPTION = new AESEncryptionUtils();

    @Override
    public EncryptableData encrypt(byte[] plaintextData, EncryptionKeySupplier encryptionKeySupplier) throws GenericServiceException {
        if (plaintextData == null) {
            throw new GenericServiceException(ServiceError.ENCRYPTION_FAILED, "Data must not be null");
        }

        final String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

        // In case master DB encryption key does not exist, do not encrypt the value
        if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
            return new EncryptableData(EncryptionAlgorithm.NO_ENCRYPTION, plaintextData);
        }

        try {
            // Convert master DB encryption key
            final SecretKey masterDbEncryptionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

            // Derive secret key from master DB encryption key, userId and activationId
            final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, encryptionKeySupplier.keyDerivationData());

            // Generate random IV
            final byte[] iv = KEY_GENERATOR.generateRandomBytes(16);

            // Encrypt serverPrivateKey using secretKey with generated IV
            final byte[] encrypted = AES_ENCRYPTION.encrypt(plaintextData, iv, secretKey);

            // Generate output bytes as encrypted + IV
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(iv);
            baos.write(encrypted);
            final byte[] encryptedData = baos.toByteArray();

            return new EncryptableData(EncryptionAlgorithm.AES_HMAC, encryptedData);
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

    @Override
    public byte[] decrypt(byte[] encryptedData, EncryptionKeySupplier encryptionKeySupplier) throws GenericServiceException {
        final String masterDbEncryptionKeyBase64 = powerAuthServiceConfiguration.getMasterDbEncryptionKey();

        // In case master DB encryption key does not exist, do not encrypt the value
        if (masterDbEncryptionKeyBase64 == null || masterDbEncryptionKeyBase64.isEmpty()) {
            logger.error("Missing master DB encryption key");
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_MASTER_DB_ENCRYPTION_KEY);
        }
        try {
            // Convert master DB encryption key
            final SecretKey masterDbEncryptionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(masterDbEncryptionKeyBase64));

            // Derive secret key from master DB encryption key, userId and activationId
            final SecretKey secretKey = deriveSecretKey(masterDbEncryptionKey, encryptionKeySupplier.keyDerivationData());

            // Check that the length of the byte array is sufficient to avoid AIOOBE on the next calls
            if (encryptedData.length < 16) {
                logger.error("Invalid encrypted data hash format - the byte array is too short");
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
            }

            // IV is present in first 16 bytes
            final byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);

            // Encrypted data hash is present after IV
            final byte[] encryptedDataRaw = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);

            return AES_ENCRYPTION.decrypt(encryptedDataRaw, iv, secretKey);
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

    private SecretKey deriveSecretKey(SecretKey master, Supplier<List<String>> keySupplier) throws GenericCryptoException, CryptoProviderException {
        byte[] index = String.join("&", keySupplier.get()).getBytes(StandardCharsets.UTF_8);
        return KEY_GENERATOR.deriveSecretKeyHmac(master, index);
    }

}
