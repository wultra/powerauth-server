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

import com.wultra.security.powerauth.app.server.database.model.SharedSecret;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptableData;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptionService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;

/**
 * Converter for shared secret which handles key encryption and decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class SharedSecretConverter {

    private final EncryptionService encryptionService;

    /**
     * Convert shared secret from composite database value to Base64-encoded string value.
     * @param sharedSecret Shared secret composite database value shared secret and encryption mode.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Decrypted Base64-encoded shared secret.
     * @throws GenericServiceException In case shared secret decryption fails.
     */
    public String fromDBValue(final SharedSecret sharedSecret, final String userId, final String activationId) throws GenericServiceException {
        final byte[] data = convert(sharedSecret.sharedSecretBase64());
        final byte[] decrypted = encryptionService.decrypt(data, sharedSecret.encryptionMode(), createEncryptionKeyProvider(userId, activationId));
        return convert(decrypted);
    }

    /**
     * Convert shared secret to composite database value. Shared secret is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param sharedSecret Shared secret value.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Shared secret as composite database value.
     * @throws GenericServiceException Thrown when shared secret encryption fails.
     */
    public SharedSecret toDBValue(final byte[] sharedSecret, final String userId, final String activationId) throws GenericServiceException {
        final EncryptableData encryptable = encryptionService.encrypt(sharedSecret, createEncryptionKeyProvider(userId, activationId));
        return new SharedSecret(encryptable.encryptionMode(), convert(encryptable.encryptedData()));
    }

    private static String convert(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private static byte[] convert(final String source) {
        return Base64.getDecoder().decode(source);
    }

    private static Supplier<List<String>> createEncryptionKeyProvider(final String userId, final String activationId) {
        return () -> List.of(userId, activationId);
    }

}
