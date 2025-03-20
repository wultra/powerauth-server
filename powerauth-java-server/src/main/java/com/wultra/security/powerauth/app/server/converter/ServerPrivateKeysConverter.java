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
import com.wultra.security.powerauth.app.server.database.model.PrivateKeys;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptableData;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptionService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;

/**
 * Converter for server private keys which handles key conversion and encryption/decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class ServerPrivateKeysConverter {

    private final EncryptionService encryptionService;
    private final ObjectMapper objectMapper;

    @Autowired
    public ServerPrivateKeysConverter(EncryptionService encryptionService, @Qualifier("privateKeyObjectMapper") ObjectMapper objectMapper) {
        this.encryptionService = encryptionService;
        this.objectMapper = objectMapper;
    }

    /**
     * Convert private keys from composite database value to object.
     * @param privateKeys Private keys composite database value for private keys and encryption mode.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Decrypted private keys.
     * @throws GenericServiceException In case private keys decryption fails.
     */
    public PrivateKeyRegistry fromDBValue(final PrivateKeys privateKeys, final String userId, final String activationId) throws GenericServiceException {
        try {
            final byte[] data = convertFromBase64(privateKeys.privateKeysBase64());
            final byte[] decrypted = encryptionService.decrypt(data, privateKeys.encryptionMode(), createEncryptionKeyProvider(userId, activationId));
            return deserialize(decrypted);
        } catch (IOException e) {
            logger.warn(e.getMessage(), e);
            throw new GenericServiceException(ServiceError.DECRYPTION_FAILED, e.getMessage());
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
    public PrivateKeys toDBValue(final byte[] privateKeysBytes, final String userId, final String activationId) throws GenericServiceException {
        final EncryptableData encryptable = encryptionService.encrypt(privateKeysBytes, createEncryptionKeyProvider(userId, activationId));
        return new PrivateKeys(encryptable.encryptionMode(), convertToBase64(encryptable.encryptedData()));
    }

    public byte[] serialize(final PrivateKeyRegistry source) throws JsonProcessingException {
        return objectMapper.writeValueAsBytes(source);
    }

    private PrivateKeyRegistry deserialize(final byte[] source) throws IOException {
        return objectMapper.readValue(source, PrivateKeyRegistry.class);
    }

    private String convertToBase64(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private byte[] convertFromBase64(final String source) {
        return Base64.getDecoder().decode(source);
    }

    private static Supplier<List<String>> createEncryptionKeyProvider(final String userId, final String activationId) {
        return () -> List.of(userId, activationId);
    }

}
