/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
 * Enum representing phase when activation is committed. Following values are supported:
 *
 * <ul>
 * <li>{@code ON_COMMIT} = 0</li>
 * <li>{@code ON_KEY_EXCHANGE} = 1</li>
 * </ul>
 */
public enum CommitPhase {

    /**
     * ON_COMMIT - activation is commited in PENDING_COMMIT state (default).
     */
    ON_COMMIT((byte) 0),

    /**
     * ON_KEY_EXCHANGE - activation is committed during key exchange.
     */
    ON_KEY_EXCHANGE((byte) 1);

    final byte value;

    CommitPhase(final byte value) {
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