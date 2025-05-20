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
package io.getlime.security.powerauth.app.server.database.model.enumeration;

/**
 * Enum representing possible recovery code states. Following values are supported:
 * <p>
 * - CREATED = 1
 * - ACTIVE = 2
 * - BLOCKED = 3
 * - REVOKED = 4
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum RecoveryCodeStatus {

    /**
     * CREATED - recovery code has been created, however it is not active yet.
     */
    CREATED((byte) 1),

    /**
     * ACTIVE - recovery code is active and can be used for a recovery scenario.
     */
    ACTIVE((byte) 2),

    /**
     * BLOCKED - recovery code has been blocked due to too many failed attempts.
     */
    BLOCKED((byte) 3),

    /**
     * REVOKED - recovery code has been revoked.
     */
    REVOKED((byte) 4);

    final byte value;

    RecoveryCodeStatus(final byte value) {
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
