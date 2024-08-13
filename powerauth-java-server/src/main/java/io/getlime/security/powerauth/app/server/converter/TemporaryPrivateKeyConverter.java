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

import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptableData;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptionService;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

/**
 * Converter for temporary private key which handles key encryption and decryption in case it is configured.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class TemporaryPrivateKeyConverter {

    private final EncryptionService encryptionService;

    /**
     * Convert server private key from composite database value to Base64-encoded string value.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param serverPrivateKey Server private key composite database value server private key and encryption mode.
     * @param keyId Key ID.
     * @param appKey App key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Decrypted Base64-encoded server private key.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public String fromDBValue(ServerPrivateKey serverPrivateKey, String keyId, String appKey, String activationId) throws GenericServiceException {
        final byte[] data = convert(serverPrivateKey.serverPrivateKeyBase64());
        final byte[] decrypted = encryptionService.decrypt(data, serverPrivateKey.encryptionMode(), createSecretKeyDerivationInput(keyId, appKey, activationId));
        return convert(decrypted);
    }

    /**
     * Convert server private key to composite database value. Server private key is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param serverPrivateKey Server private key.
     * @param keyId Key ID.
     * @param appKey App Key.
     * @param activationId Activation ID used for derivation of secret key.
     * @return Server private key as composite database value.
     * @throws GenericServiceException Thrown when server private key encryption fails.
     */
    public ServerPrivateKey toDBValue(byte[] serverPrivateKey, String keyId, String appKey, String activationId) throws GenericServiceException {
        final EncryptableData encryptable = encryptionService.encrypt(serverPrivateKey, createSecretKeyDerivationInput(keyId, appKey, activationId));
        return new ServerPrivateKey(encryptable.encryptionMode(), convert(encryptable.encryptedData()));
    }

    private static String convert(final byte[] source) {
        return Base64.getEncoder().encodeToString(source);
    }

    private static byte[] convert(final String source) {
        return Base64.getDecoder().decode(source);
    }

    private static List<String> createSecretKeyDerivationInput(final String keyId, final String appKey, final String activationId) {
        return List.of(keyId, appKey, activationId);
    }

}
