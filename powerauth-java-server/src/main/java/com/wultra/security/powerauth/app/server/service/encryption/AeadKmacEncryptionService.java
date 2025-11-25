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

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.aead.Aead;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;

/**
 * Service which implements AEAD-based encryptor with a per-record 32-byte encryption key
 * derived using KMAC-256 for database encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class AeadKmacEncryptionService implements DatabaseEncryptor {

    private static final byte[] CUSTOM_BYTES = "PA4DBENC".getBytes(StandardCharsets.UTF_8);

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final LocalizationProvider localizationProvider;

    @Override
    public EncryptableData encrypt(byte[] plaintextData, EncryptionKeySupplier encryptionKeySupplier) throws GenericServiceException {
        try {
            final SecretKey masterKey = loadMasterDbEncryptionKey();
            final SecretKey encKey = deriveKmacKey(masterKey, encryptionKeySupplier.keyDerivationData());
            final byte[] ad = deriveAssociatedData(encryptionKeySupplier.associatedData());
            final byte[] ciphertext = Aead.seal(encKey, null, null, ad, plaintextData);
            return new EncryptableData(EncryptionAlgorithm.AEAD_KMAC, ciphertext);
        } catch (Exception ex) {
            logger.error("Encryption failed", ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, EncryptionKeySupplier encryptionKeySupplier) throws GenericServiceException {
        try {
            final SecretKey masterKey = loadMasterDbEncryptionKey();
            final SecretKey encryptionKey = deriveKmacKey(masterKey, encryptionKeySupplier.keyDerivationData());
            final byte[] ad = deriveAssociatedData(encryptionKeySupplier.associatedData());
            return Aead.open(encryptionKey, null, ad, encryptedData);
        } catch (Exception ex) {
            logger.error("Decryption failed", ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }
    }

    private SecretKey loadMasterDbEncryptionKey() throws GenericServiceException {
        String base64 = powerAuthServiceConfiguration.getMasterDbEncryptionKeyAeadKmac();
        if (base64 == null || base64.isEmpty()) {
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_MASTER_DB_ENCRYPTION_KEY);
        }
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(Base64.getDecoder().decode(base64));
    }

    private SecretKey deriveKmacKey(SecretKey masterKey, Supplier<List<String>> supplier) throws GenericCryptoException {
        byte[] index = String.join("&", supplier.get()).getBytes(StandardCharsets.UTF_8);
        byte[] out = Kmac.kmac256(masterKey, index, CUSTOM_BYTES, 32);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(out);
    }

    private byte[] deriveAssociatedData(Supplier<List<String>> supplier) {
        return String.join("&", supplier.get()).getBytes(StandardCharsets.UTF_8);
    }

}
