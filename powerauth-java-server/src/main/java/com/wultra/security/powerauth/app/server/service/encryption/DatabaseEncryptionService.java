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
 */
package com.wultra.security.powerauth.app.server.service.encryption;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class DatabaseEncryptionService {

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final DatabaseEncryptionFactory factory;

    /**
     * Encrypt plaintext byte array database data using a per-record encryption key.
     * @param plaintextData Plaintext data.
     * @param encryptionKeySupplier Encryption key supplier for key derivation.
     * @param mode Encryption mode.
     * @return Encrypted data as a byte array.
     * @throws GenericServiceException Thrown in case encryption fails.
     */
    public EncryptableData encrypt(byte[] plaintextData, EncryptionKeySupplier encryptionKeySupplier, EncryptionAlgorithm mode) throws GenericServiceException {
        return factory.get(mode).encrypt(plaintextData, encryptionKeySupplier);
    }

    /**
     * Encrypt plaintext string database data using a per-record encryption key.
     * @param plaintextData Plaintext data.
     * @param encryptionKeySupplier Encryption key supplier for key derivation.
     * @param mode Encryption mode.
     * @return Encrypted data as a String.
     * @throws GenericServiceException Thrown in case encryption fails.
     */
    public EncryptableString encrypt(String plaintextData, EncryptionKeySupplier encryptionKeySupplier, EncryptionAlgorithm mode) throws GenericServiceException {
        return factory.get(mode).encrypt(plaintextData, encryptionKeySupplier);
    }

    /**
     * Decrypt encrypted database byte array data using a per-record encryption key.
     * @param encryptedData Encrypted data.
     * @param encryptionKeySupplier Encryption key supplier for key derivation.
     * @param mode Encryption mode.
     * @return Plaintext data.
     * @throws GenericServiceException Thrown in case decryption fails.
     */
    public byte[] decrypt(byte[] encryptedData, EncryptionKeySupplier encryptionKeySupplier, EncryptionAlgorithm mode) throws GenericServiceException {
        return factory.get(mode).decrypt(encryptedData, encryptionKeySupplier);
    }

    /**
     * Decrypt encrypted database String data using a per-record encryption key.
     * @param encryptedData Encrypted data.
     * @param encryptionKeySupplier Encryption key supplier for key derivation.
     * @param mode Encryption mode.
     * @return Plaintext data as a String.
     * @throws GenericServiceException Thrown in case decryption fails.
     */
    public String decrypt(String encryptedData, EncryptionKeySupplier encryptionKeySupplier, EncryptionAlgorithm mode) throws GenericServiceException {
        return factory.get(mode).decrypt(encryptedData, encryptionKeySupplier, mode);
    }

    /**
     * Get default encryption algorithm for encrypting new database records.
     * @return Default encryption algorithm.
     */
    public EncryptionAlgorithm getDefaultEncryptionAlgorithm() {
        return powerAuthServiceConfiguration.getMasterDbEncryptionAlgorithm();
    }

}