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
package com.wultra.security.powerauth.client.model.error;

/**
 * PowerAuth client exception.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthClientException extends Exception {

    private static final long serialVersionUID = -4721271754602015511L;

    private PowerAuthError powerAuthError;

    /**
     * Default constructor.
     */
    public PowerAuthClientException() {
    }

    /**
     * Constructor with message.
     * @param message Error message.
     */
    public PowerAuthClientException(String message) {
        super(message);
    }

    /**
     * Constructor with message and cause.
     * @param message Error message.
     * @param cause Exception which caused the error.
     */
    public PowerAuthClientException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructor for specific PowerAuth errors.
     * @param message Error message.
     * @param cause Exception which caused the error.
     * @param powerAuthError PowerAuth error with additional details.
     */
    public PowerAuthClientException(String message, Throwable cause, PowerAuthError powerAuthError) {
        super(message, cause);
        this.powerAuthError = powerAuthError;
    }

    /**
     * Get the PowerAuth error object.
     * @return PowerAuth error object.
     */
    public PowerAuthError getPowerAuthError() {
        return powerAuthError;
    }

}