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
 * Enum representing possible activation OTP validation stages. Following values are supported:
 * <p>
 * - NONE = 0
 * - KEYS_EXCHANGE = 1
 * - COMMIT = 2
 */
public enum ActivationOtpValidation {

    /**
     * NONE - no additional OTP validation is required during the activation.
     */
    NONE((byte) 0),

    /**
     * ON_KEY_EXCHANGE - an additional OTP is validated during the keys-exchange activation phase.
     */
    ON_KEY_EXCHANGE((byte) 1),

    /**
     * ON_COMMIT - an additional OTP is validated during the commit activation phase.
     */
    ON_COMMIT((byte) 2);

    final byte value;

    ActivationOtpValidation(final byte value) {
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