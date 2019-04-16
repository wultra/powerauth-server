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
 * Enum representing possible recovery PUK states. Following values are supported:
 * <p>
 * - VALID = 1
 * - USED = 2
 * - INVALID = 3
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum RecoveryPukStatus {

    /**
     * VALID - valid recovery PUK, ready to be used.
     */
    VALID((byte) 1),

    /**
     * USED - recovery PUK has already been used.
     */
    USED((byte) 2),

    /**
     * INVALID - recovery PUK is no longer valid.
     */
    INVALID((byte) 3);

    final byte value;

    RecoveryPukStatus(final byte value) {
        this.value = value;
    }

    /**
     * Get byte representation of the enum value.
     *
     * @return Byte representing enum value.
     */
    public byte getByte() {
        return value;
    }
}
