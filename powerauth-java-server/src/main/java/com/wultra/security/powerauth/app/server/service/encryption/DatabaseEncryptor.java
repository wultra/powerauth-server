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

import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Database encryptor interface for symmetric encryption and decryption of database data.
 * The keys are derived dynamically per database row with data taken from an encryption key supplier.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface DatabaseEncryptor {

    /**
     * Encrypt plaintext database data bytes.
     * @param plaintextData Database data to encrypt.
     * @param encryptionKeySupplier Key supplier for derivation of per-record encryption keys.
     * @return Encrypted data as bytes.
     * @throws GenericServiceException Thrown in case of encryption errors.
     */
    EncryptableData encrypt(byte[] plaintextData, EncryptionKeySupplier encryptionKeySupplier) throws GenericServiceException;

    /**
     * Encrypt plaintext database data string.
     * @param plaintextData Database data to encrypt.
     * @param encryptionKeySupplier Key supplier for derivation of per-record encryption keys.
     * @return Encrypted data as a String.
     * @throws GenericServiceException Thrown in case of encryption errors.
     */
    default EncryptableString encrypt(String plaintextData, EncryptionKeySupplier encryptionKeySupplier) throws GenericServiceException {
        if (plaintextData == null) {
            throw new GenericServiceException(ServiceError.ENCRYPTION_FAILED, "Data must not be null");
        }
        final byte[] bytes = plaintextData.getBytes(StandardCharsets.UTF_8);
        final EncryptableData encrypted = encrypt(bytes, encryptionKeySupplier);
        return new EncryptableString(encrypted.encryptionAlgorithm(),
                encrypted.encryptionAlgorithm() == EncryptionAlgorithm.NO_ENCRYPTION
                        ? new String(encrypted.encryptedData(), StandardCharsets.UTF_8)
                        : Base64.getEncoder().encodeToString(encrypted.encryptedData()));
    }

    /**
     * Decrypt encrypted database byte array data.
     * @param encryptedData Encrypted data.
     * @param encryptionKeySupplier Key supplier for derivation of per-record encryption keys.
     * @return Plaintext data.
     * @throws GenericServiceException Thrown in case of decryption errors.
     */
    byte[] decrypt(byte[] encryptedData, EncryptionKeySupplier encryptionKeySupplier) throws GenericServiceException;

    /**
     * Decrypt encrypted database string data.
     * @param dataString String to decrypt.
     * @param encryptionKeySupplier Key supplier for derivation of per-record encryption keys.
     * @param encryptionAlgorithm Encryption mode.
     * @return Decrypted value as a String.
     * @throws GenericServiceException In case decryption fails.
     */
    default String decrypt(final String dataString, final EncryptionKeySupplier encryptionKeySupplier,  final EncryptionAlgorithm encryptionAlgorithm) throws GenericServiceException {
        final byte[] dataBytes = encryptionAlgorithm == EncryptionAlgorithm.NO_ENCRYPTION
                ? dataString.getBytes(StandardCharsets.UTF_8)
                : Base64.getDecoder().decode(dataString);
        final byte[] decrypted = decrypt(dataBytes, encryptionKeySupplier);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

}
