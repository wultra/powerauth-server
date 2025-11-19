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
package com.wultra.security.powerauth.app.server.converter;

import com.wultra.security.powerauth.app.server.database.model.ServerPrivateKeyRecord;
import com.wultra.security.powerauth.app.server.service.encryption.DatabaseEncryptionService;
import com.wultra.security.powerauth.app.server.service.encryption.DefaultEncryptionKeySupplier;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptableData;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptionKeySupplier;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

/**
 * Converter for server private key which handles key encryption and decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class ServerPrivateKeyConverter {

    private final DatabaseEncryptionService encryptionService;

    /**
     * Convert server private key from composite database value to Base64-encoded string value.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param serverPrivateKey Server private key composite database value server private key and encryption mode.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Decrypted Base64-encoded server private key.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public String fromDBValue(final ServerPrivateKeyRecord serverPrivateKey, final String userId, final String activationId) throws GenericServiceException {
        final byte[] encrypted = fromBase64(serverPrivateKey.serverPrivateKeyBase64());
        final EncryptionKeySupplier encryptionKeySupplier = encryptionKeySupplier(userId, activationId);
        final byte[] decrypted = encryptionService.decrypt(encrypted, encryptionKeySupplier, serverPrivateKey.encryptionAlgorithm());
        return toBase64(decrypted);
    }

    /**
     * Convert server private key to composite database value. Server private key is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param serverPrivateKey Server private key.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Server private key as composite database value.
     * @throws GenericServiceException Thrown when server private key encryption fails.
     */
    public ServerPrivateKeyRecord toDBValue(final byte[] serverPrivateKey, final String userId, final String activationId) throws GenericServiceException {
        final EncryptionKeySupplier encryptionKeySupplier = encryptionKeySupplier(userId, activationId);
        final EncryptableData encrypted = encryptionService.encrypt(serverPrivateKey, encryptionKeySupplier, encryptionService.getDefaultEncryptionAlgorithm());
        return new ServerPrivateKeyRecord(encrypted.encryptionAlgorithm(), toBase64(encrypted.encryptedData()));
    }

    private static String toBase64(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private static byte[] fromBase64(final String source) {
        return Base64.getDecoder().decode(source);
    }

    private static EncryptionKeySupplier encryptionKeySupplier(final String userId, final String activationId) {
        return new DefaultEncryptionKeySupplier(
                List.of(userId, activationId),
                List.of("pa_activation", "server_private_key_base64", activationId)
        );
    }

}
