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
 * Enum representing encryption modes. Following values are supported:
 * <p>
 * - NO_ENCRYPTION = 0
 * - AES_HMAC = 1
 * </p>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum EncryptionMode {

    /**
     * No encryption.
     */
    NO_ENCRYPTION((byte) 0),

    /**
     * AES encryption with HMAC-based index.
     */
    AES_HMAC((byte) 1);

    /**
     * Byte value of encryption mode.
     */
    final byte value;

    /**
     * Default constructor with byte value of encryption mode.
     * @param value Byte value of encryption mode.
     */
    EncryptionMode(final byte value) {
        this.value = value;
    }

    /**
     * Get byte value of encryption mode.
     * @return Byte value of encryption mode.
     */
    public byte getValue() {
        return value;
    }
}
