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

import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeysRecord;
import com.wultra.security.powerauth.app.server.service.encryption.*;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

/**
 * Converter for server private keys which handles key conversion and encryption/decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class ServerPrivateKeysConverter {

    private final DatabaseEncryptionService encryptionService;
    private final ObjectMapper objectMapper;

    @Autowired
    public ServerPrivateKeysConverter(DatabaseEncryptionService encryptionService, @Qualifier("privateKeyObjectMapper") ObjectMapper objectMapper) {
        this.encryptionService = encryptionService;
        this.objectMapper = objectMapper;
    }

    /**
     * Convert server private keys from composite database value to object.
     * @param privateKeys Server private keys composite database value for private keys and encryption mode.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Decrypted private keys.
     * @throws GenericServiceException In case private keys decryption fails.
     */
    public PrivateKeyRegistry fromDBValue(final PrivateKeysRecord privateKeys, final String userId, final String activationId) throws GenericServiceException {
        try {
            final byte[] encryptedData = fromBase64(privateKeys.privateKeysBase64());
            final EncryptionKeySupplier encryptionKeySupplier = encryptionKeySupplier(userId, activationId);
            final byte[] decrypted = encryptionService.decrypt(encryptedData, encryptionKeySupplier, privateKeys.encryptionAlgorithm());
            return deserialize(decrypted);
        } catch (IOException e) {
            logger.warn("Decryption failed", e);
            throw new GenericServiceException(ServiceError.DECRYPTION_FAILED, e.getMessage());
        }
    }

    /**
     * Convert private keys to composite database value. Private keys are encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param serverPrivateKeys Server private key registry.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Private keys as composite database value.
     * @throws GenericServiceException Thrown when private keys encryption fails.
     */
    public PrivateKeysRecord toDBValue(final PrivateKeyRegistry serverPrivateKeys, final String userId, final String activationId) throws GenericServiceException {
        try {
            return toDBValue(serialize(serverPrivateKeys), userId, activationId);
        } catch (JacksonException e) {
            logger.warn("Encryption failed", e);
            throw new GenericServiceException(ServiceError.ENCRYPTION_FAILED, e.getMessage());
        }
    }

    /**
     * Convert private keys to composite database value. Private keys are encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param privateKeysBytes Private keys as byte array.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Private keys as composite database value.
     * @throws GenericServiceException Thrown when private keys encryption fails.
     */
    public PrivateKeysRecord toDBValue(final byte[] privateKeysBytes, final String userId, final String activationId) throws GenericServiceException {
        final EncryptionKeySupplier encryptionKeySupplier = encryptionKeySupplier(userId, activationId);
        final EncryptableData encrypted = encryptionService.encrypt(privateKeysBytes, encryptionKeySupplier, encryptionService.getDefaultEncryptionAlgorithm());
        return new PrivateKeysRecord(encrypted.encryptionAlgorithm(), toBase64(encrypted.encryptedData()));
    }

    byte[] serialize(final PrivateKeyRegistry source) throws JacksonException {
        return objectMapper.writeValueAsBytes(source);
    }

    private PrivateKeyRegistry deserialize(final byte[] source) throws IOException {
        return objectMapper.readValue(source, PrivateKeyRegistry.class);
    }

    private String toBase64(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private byte[] fromBase64(final String source) {
        return Base64.getDecoder().decode(source);
    }

    private static EncryptionKeySupplier encryptionKeySupplier(final String userId, final String activationId) {
        return new DefaultEncryptionKeySupplier(
                List.of(userId, activationId),
                List.of("pa_activation", "server_private_keys", activationId)
        );
    }

}
