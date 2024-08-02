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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.springframework.stereotype.Component;

import io.getlime.security.powerauth.app.server.database.model.RecoveryPuk;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.service.encryption.Encryptable;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptionService;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Converter for recovery PUK which handles record encryption and decryption in case it is configured.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public class RecoveryPukConverter {

    private final EncryptionService encryptionService;

    /**
     * Convert recovery PUK hash from composite database value to string value.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param recoveryPuk Recovery PUK hash composite database value including PUK hash and encryption mode.
     * @param applicationRid Application RID used for derivation of secret key.
     * @param userId User ID used for derivation of secret key.
     * @param recoveryCode Recovery code used for derivation of secret key.
     * @param pukIndex Recovery PUK index used for derivation of secret key.
     * @return Decrypted recovery PUK hash.
     * @throws GenericServiceException In case recovery PUK hash decryption fails.
     */
    public String fromDBValue(final RecoveryPuk recoveryPuk, final long applicationRid, final String userId, final String recoveryCode, final long pukIndex) throws GenericServiceException {
        final byte[] data = convert(recoveryPuk);
        final byte[] decrypted = encryptionService.decrypt(data, recoveryPuk.encryptionMode(), createSecretKeyDerivationInput(applicationRid, userId, recoveryCode, pukIndex));
        return convert(decrypted);
    }

    /**
     * Convert PUK hash to composite database value. PUK hash is encrypted
     * in case master DB encryption key is configured in PA server configuration.
     * The method should be called before writing to the database because the GenericServiceException can be thrown. This could lead to a database inconsistency because
     * the transaction is not rolled back.
     * @param pukHash PUK hash to encrypt if master DB encryption key is present.
     * @param applicationRid Application RID used for derivation of secret key.
     * @param userId User ID used for derivation of secret key.
     * @param recoveryCode Recovery code used for derivation of secret key.
     * @param pukIndex Recovery PUK index used for derivation of secret key.
     * @return Server private key as composite database value.
     * @throws GenericServiceException Thrown when server private key encryption fails.
     */
    public RecoveryPuk toDBValue(final String pukHash, final long applicationRid, final String userId, final String recoveryCode, final long pukIndex) throws GenericServiceException {
        final byte[] data = convert(pukHash);
        final Encryptable encryptable = encryptionService.encrypt(data, createSecretKeyDerivationInput(applicationRid, userId, recoveryCode, pukIndex));
        return new RecoveryPuk(encryptable.getEncryptionMode(), convert(encryptable));
    }

    private static byte[] convert(final RecoveryPuk source) {
        if (source.encryptionMode() == EncryptionMode.NO_ENCRYPTION) {
            return source.pukHash().getBytes(StandardCharsets.UTF_8);
        } else {
            return Base64.getDecoder().decode(source.pukHash());
        }
    }

    private static byte[] convert(final String source) {
        return source.getBytes(StandardCharsets.UTF_8);
    }

    private static String convert(final Encryptable source) {
        if (source.getEncryptionMode() == EncryptionMode.NO_ENCRYPTION) {
            return convert(source.getEncryptedData());
        } else {
            return Base64.getEncoder().encodeToString(source.getEncryptedData());
        }
    }

    private static String convert(final byte[] source) {
        return new String(source, StandardCharsets.UTF_8);
    }

    private static List<String> createSecretKeyDerivationInput(final long applicationRid, final String userId, final String recoveryCode, final long pukIndex) {
        return List.of(String.valueOf(applicationRid), userId, recoveryCode, String.valueOf(pukIndex));
    }

}
