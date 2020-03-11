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

import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;

/**
 * Enum representing possible activation states. Following values are supported:
 * <p>
 * - CREATED = 1
 * - OTP_USED = 2
 * - ACTIVE = 3
 * - BLOCKED = 4
 * - REMOVED = 5
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public enum ActivationStatus {

    /**
     * CREATED - status right after the activation record was created by calling
     * {@link PowerAuthService#initActivation(io.getlime.security.powerauth.v3.InitActivationRequest)}.
     */
    CREATED((byte) 1),

    /**
     * OTP_USED - status right after PowerAuth Server receives PowerAuth Client public
     * key, via {@link PowerAuthService#prepareActivation(io.getlime.security.powerauth.v3.PrepareActivationRequest)}
     * method. This status means that activation is awaiting commit.
     */
    OTP_USED((byte) 2),

    /**
     * ACTIVE - status after the activation record was committed by calling
     * {@link PowerAuthService#commitActivation(io.getlime.security.powerauth.v3.CommitActivationRequest)},
     * or after activation was unblocked from the BLOCKED state by calling
     * {@link PowerAuthService#unblockActivation(io.getlime.security.powerauth.v3.UnblockActivationRequest)}.
     */
    ACTIVE((byte) 3),

    /**
     * BLOCKED - status after the activation record was blocked by calling
     * {@link PowerAuthService#blockActivation(io.getlime.security.powerauth.v3.BlockActivationRequest)} or
     * after too many authentication failed attempt occurred.
     */
    BLOCKED((byte) 4),

    /**
     * REMOVED - status after the activation record was removed by calling
     * {@link PowerAuthService#removeActivation(io.getlime.security.powerauth.v3.RemoveActivationRequest)}.
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
