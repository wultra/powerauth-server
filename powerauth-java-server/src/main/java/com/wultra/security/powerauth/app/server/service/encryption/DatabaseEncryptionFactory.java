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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Factory for database encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class DatabaseEncryptionFactory {

    private final Map<EncryptionAlgorithm, DatabaseEncryptor> encryptorMap;

    @Autowired
    public DatabaseEncryptionFactory(NoEncryptionService noEncryptionService, AesHmacEncryptionService aesHmacService, AeadKmacEncryptionService aeadKmacService) {
        this.encryptorMap = Map.of(
                EncryptionAlgorithm.NO_ENCRYPTION, noEncryptionService,
                EncryptionAlgorithm.AES_HMAC, aesHmacService,
                EncryptionAlgorithm.AEAD_KMAC, aeadKmacService
        );
    }

    private Map<EncryptionAlgorithm, DatabaseEncryptor> encryptorMap() {
        return encryptorMap;
    }

    /**
     * Get database encryptor for an encryption mode.
     * @param mode Encryption mode.
     * @return Database encryptor.
     */
    public DatabaseEncryptor get(EncryptionAlgorithm mode) {
        return encryptorMap().get(mode);
    }

}
