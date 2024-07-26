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
 * Enum representing possible activation states. Following values are supported:
 * <p>
 * - CREATED = 1
 * - PENDING_COMMIT = 2
 * - ACTIVE = 3
 * - BLOCKED = 4
 * - REMOVED = 5
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public enum ActivationStatus {

    /**
     * CREATED - status right after the activation record was created.
     */
    CREATED((byte) 1),

    /**
     * PENDING_COMMIT - status right after PowerAuth Server receives PowerAuth Client public
     * key. This status means that activation is awaiting commit.
     */
    PENDING_COMMIT((byte) 2),

    /**
     * ACTIVE - status after the activation record was committed
     * or after activation was unblocked from the BLOCKED state
     */
    ACTIVE((byte) 3),

    /**
     * BLOCKED - status after the activation record was blocked or
     * after too many authentication failed attempt occurred.
     */
    BLOCKED((byte) 4),

    /**
     * REMOVED - status after the activation record was removed.
     */
    REMOVED((byte) 5);

    final byte value;

    ActivationStatus(final byte value) {
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
