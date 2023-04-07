/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;

/**
 * Compound value of recovery PUK. PUK hash can be stored encrypted or decrypted based on key encryption mode.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoveryPuk {

    private final EncryptionMode encryptionMode;
    private final String pukHash;

    /**
     * Constructor with key encryption mode and PUK hash.
     * @param encryptionMode Key encryption mode.
     * @param pukHash PUK hash, encrypted if speciefied by key encryption mode.
     */
    public RecoveryPuk(EncryptionMode encryptionMode, String pukHash) {
        this.encryptionMode = encryptionMode;
        this.pukHash = pukHash;
    }

    /**
     * Get key encryption mode.
     * @return Key encryption mode.
     */
    public EncryptionMode getEncryptionMode() {
        return encryptionMode;
    }

    /**
     * Get PUK hash, encrypted if speciefied by key encryption mode.
     * @return PUK hash, encrypted if speciefied by key encryption mode.
     */
    public String getPukHash() {
        return pukHash;
    }
}
