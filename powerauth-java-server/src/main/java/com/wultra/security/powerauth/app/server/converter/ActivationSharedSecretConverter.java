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

import com.wultra.security.powerauth.app.server.database.model.SharedSecretRecord;
import com.wultra.security.powerauth.app.server.service.encryption.*;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

/**
 * Converter for activation shared secret which handles key encryption and decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class ActivationSharedSecretConverter {

    private final DatabaseEncryptionService encryptionService;

    /**
     * Convert shared secret from composite database value to Base64-encoded string value.
     * @param sharedSecret Shared secret composite database value shared secret and encryption mode.
     * @param userId User ID used for derivation of secret key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Decrypted Base64-encoded shared secret.
     * @throws GenericServiceException In case shared secret decryption fails.
     */
    public String fromDBValue(final SharedSecretRecord sharedSecret, final String userId, final String activationId) throws GenericServiceException {
        final byte[] data = fromBase64(sharedSecret.sharedSecretBase64());
        final EncryptionKeySupplier encryptionKeySupplier = createSecretKeyDerivationInput(userId, activationId);
        final byte[] decrypted = encryptionService.decrypt(data, encryptionKeySupplier, sharedSecret.encryptionAlgorithm());
        return toBase64(decrypted);
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
    public SharedSecretRecord toDBValue(final byte[] sharedSecret, final String userId, final String activationId) throws GenericServiceException {
        final EncryptionKeySupplier encryptionKeySupplier = createSecretKeyDerivationInput(userId, activationId);
        final EncryptableData encryptable = encryptionService.encrypt(sharedSecret, encryptionKeySupplier, encryptionService.getDefaultEncryptionAlgorithm());
        return new SharedSecretRecord(encryptable.encryptionAlgorithm(), toBase64(encryptable.encryptedData()));
    }

    private static String toBase64(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private static byte[] fromBase64(final String source) {
        return Base64.getDecoder().decode(source);
    }

    private static EncryptionKeySupplier createSecretKeyDerivationInput(final String userId, final String activationId) {
        return new DefaultEncryptionKeySupplier(List.of(userId, activationId), List.of("pa_activation", "shared_secret", activationId));
    }

}
