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
package com.wultra.security.powerauth.fido2.model.error;

import java.io.Serial;
import java.util.Optional;

/**
 * PowerAuth FIDO2 client exception.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public class PowerAuthFido2Exception extends Exception {

    @Serial
    private static final long serialVersionUID = -7019570662090688520L;

    private final PowerAuthError powerAuthError;

    /**
     * No-arg constructor.
     */
    public PowerAuthFido2Exception() {
        this.powerAuthError = null;
    }

    /**
     * Constructor with message.
     * @param message Error message.
     */
    public PowerAuthFido2Exception(String message) {
        super(message);
        this.powerAuthError = null;
    }

    /**
     * Constructor with message and cause.
     * @param message Error message.
     * @param cause Exception which caused the error.
     */
    public PowerAuthFido2Exception(String message, Throwable cause) {
        super(message, cause);
        this.powerAuthError = null;
    }

    /**
     * Constructor for specific PowerAuth errors.
     * @param message Error message.
     * @param cause Exception which caused the error.
     * @param powerAuthError PowerAuth error with additional details.
     */
    public PowerAuthFido2Exception(String message, Throwable cause, PowerAuthError powerAuthError) {
        super(message, cause);
        this.powerAuthError = powerAuthError;
    }

    /**
     * Get the PowerAuth error object.
     * @return PowerAuth error object.
     */
    public Optional<PowerAuthError> getPowerAuthError() {
        return Optional.ofNullable(powerAuthError);
    }

}