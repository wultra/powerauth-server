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
package com.wultra.security.powerauth.app.server.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeysRecord;
import com.wultra.security.powerauth.app.server.service.encryption.DatabaseEncryptionService;
import com.wultra.security.powerauth.app.server.service.encryption.DefaultEncryptionKeySupplier;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptableData;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptionKeySupplier;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

/**
 * Converter for master private keys which handles key conversion and encryption/decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class MasterPrivateKeysConverter {

    private final DatabaseEncryptionService encryptionService;
    private final ObjectMapper objectMapper;

    @Autowired
    public MasterPrivateKeysConverter(DatabaseEncryptionService encryptionService, @Qualifier("privateKeyObjectMapper") ObjectMapper objectMapper) {
        this.encryptionService = encryptionService;
        this.objectMapper = objectMapper;
    }

    /**
     * Convert master private keys from composite database value to object.
     * @param masterPrivateKeys Master private keys composite database value for private keys and encryption mode.
     * @param applicationId Application ID used for derivation of secret key.
     * @return Decrypted master private keys.
     * @throws GenericServiceException In case master private keys decryption fails.
     */
    public PrivateKeyRegistry fromDBValue(final PrivateKeysRecord masterPrivateKeys, final String applicationId) throws GenericServiceException {
        try {
            final byte[] encryptedData = fromBase64(masterPrivateKeys.privateKeysBase64());
            final EncryptionKeySupplier encryptionKeySupplier = encryptionKeySupplier(applicationId);
            final byte[] decrypted = encryptionService.decrypt(encryptedData, encryptionKeySupplier, masterPrivateKeys.encryptionAlgorithm());
            return deserialize(decrypted);
        } catch (IOException e) {
            logger.warn("Decryption failed", e);
            throw new GenericServiceException(ServiceError.DECRYPTION_FAILED, e.getMessage());
        }
    }

    /**
     * Convert master private keys to composite database value. Private key is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param masterPrivateKeys Master private key registry.
     * @param applicationId Application ID used for derivation of secret key.
     * @return Private key as composite database value.
     * @throws GenericServiceException Thrown when private keys encryption fails.
     */
    public PrivateKeysRecord toDBValue(final PrivateKeyRegistry masterPrivateKeys, final String applicationId) throws GenericServiceException {
        try {
            return toDBValue(serialize(masterPrivateKeys), applicationId);
        } catch (IOException e) {
            logger.warn("Encryption failed", e);
            throw new GenericServiceException(ServiceError.ENCRYPTION_FAILED, e.getMessage());
        }
    }

    /**
     * Convert master private keys to composite database value. Private key is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param masterPrivateKeysBytes Master private keys as byte array.
     * @param applicationId Application ID used for derivation of secret key.
     * @return Private key as composite database value.
     * @throws GenericServiceException Thrown when private keys encryption fails.
     */
    PrivateKeysRecord toDBValue(final byte[] masterPrivateKeysBytes, final String applicationId) throws GenericServiceException {
        final EncryptionKeySupplier encryptionKeySupplier = encryptionKeySupplier(applicationId);
        final EncryptableData encrypted = encryptionService.encrypt(masterPrivateKeysBytes, encryptionKeySupplier, encryptionService.getDefaultEncryptionAlgorithm());
        return new PrivateKeysRecord(encrypted.encryptionAlgorithm(), toBase64(encrypted.encryptedData()));
    }

    byte[] serialize(final PrivateKeyRegistry source) throws JsonProcessingException {
        return objectMapper.writeValueAsBytes(source);
    }

    private PrivateKeyRegistry deserialize(final byte[] source) throws IOException {
        return objectMapper.readValue(source, PrivateKeyRegistry.class);
    }

    private static String toBase64(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private static byte[] fromBase64(final String source) {
        return Base64.getDecoder().decode(source);
    }

    private static EncryptionKeySupplier encryptionKeySupplier(final String applicationId) {
        return new DefaultEncryptionKeySupplier(
                List.of(applicationId),
                List.of("pa_master_keypair", "master_private_keys", applicationId)
        );
    }

}