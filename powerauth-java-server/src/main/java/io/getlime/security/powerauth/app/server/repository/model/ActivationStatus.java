/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.server.repository.model;

import io.getlime.security.powerauth.app.server.service.PowerAuthService;

/**
 * Enum representing possible activation states. Following values are supported:
 * <p>
 * - CREATED = 1
 * - OTP_USED = 2
 * - ACTIVE = 3
 * - BLOCKED = 4
 * - REMOVED = 5
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public enum ActivationStatus {

    /**
     * CREATED - status right after the activation record was created by calling
     * {@link PowerAuthService#initActivation(io.getlime.security.powerauth.InitActivationRequest)}.
     */
    CREATED((byte) 1),

    /**
     * OTP_USED - status right after PowerAuth 2.0 Server receives PowerAuth 2.0 Client public
     * key, via {@link PowerAuthService#prepareActivation(io.getlime.security.powerauth.PrepareActivationRequest)}
     * method.
     */
    OTP_USED((byte) 2),

    /**
     * ACTIVE - status after the activation record was committed by calling
     * {@link PowerAuthService#commitActivation(io.getlime.security.powerauth.CommitActivationRequest)},
     * or after activation was unblocked from the BLOCKED state by calling
     * {@link PowerAuthService#unblockActivation(io.getlime.security.powerauth.UnblockActivationRequest)}.
     */
    ACTIVE((byte) 3),

    /**
     * BLOCKED - status after the activation record was blocked by calling
     * {@link PowerAuthService#blockActivation(io.getlime.security.powerauth.BlockActivationRequest)} or
     * after too many authentication failed attempt occurred.
     */
    BLOCKED((byte) 4),

    /**
     * REMOVED - status after the activation record was removed by calling
     * {@link PowerAuthService#removeActivation(io.getlime.security.powerauth.RemoveActivationRequest)}.
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
