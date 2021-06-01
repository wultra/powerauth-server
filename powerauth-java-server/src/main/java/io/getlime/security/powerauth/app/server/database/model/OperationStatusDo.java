/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
 * Enum representing possible operation states. Following values are supported:
 * <p>
 * - PENDING = 1
 * - CANCELED = 2
 * - EXPIRED = 3
 * - APPROVED = 4
 * - REJECTED = 5
 * - FAILED = 6
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public enum OperationStatusDo {

    /**
     * PENDING - status right after the operation record was created.
     */
    PENDING((byte) 1),

    /**
     * CANCELED - status in the case operation was canceled by external system.
     */
    CANCELED((byte) 2),

    /**
     * EXPIRED - status after the operation expired and was accessed (so that the expiration takes effect on the DB level).
     */
    EXPIRED((byte) 3),

    /**
     * APPROVED - status after the operation was successfully approved.
     */
    APPROVED((byte) 4),

    /**
     * REJECTED - status after the operation was rejected.
     */
    REJECTED((byte) 5),

    /**
     * FAILED - status after the operation was attempted to be approved incorrectly too many times.
     */
    FAILED((byte) 6);

    final byte value;

    OperationStatusDo(final byte value) {
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
