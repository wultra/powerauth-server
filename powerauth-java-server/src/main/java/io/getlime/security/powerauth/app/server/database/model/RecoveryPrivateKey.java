/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.database.model;

/**
 * Compound value of recovery postcard private key. Key can be stored encrypted or decrypted based on key encryption mode.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoveryPrivateKey {

    private final EncryptionMode encryptionMode;
    private final String recoveryPrivateKeyBase64;

    /**
     * Constructor with key encryption mode and base64-encoded key.
     * @param encryptionMode Key encryption mode.
     * @param recoveryPrivateKeyBase64 Base64-encoded recovery postcard private key.
     */
    public RecoveryPrivateKey(EncryptionMode encryptionMode, String recoveryPrivateKeyBase64) {
        this.encryptionMode = encryptionMode;
        this.recoveryPrivateKeyBase64 = recoveryPrivateKeyBase64;
    }

    /**
     * Get key encryption mode.
     * @return Key encryption mode.
     */
    public EncryptionMode getEncryptionMode() {
        return encryptionMode;
    }

    /**
     * Get Base64-encoded recovery postcard key.
     * @return Base64-encoded recovery postcardrecovery postcard key.
     */
    public String getRecoveryPrivateKeyBase64() {
        return recoveryPrivateKeyBase64;
    }
}
