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
package com.wultra.security.powerauth.client.model.error;

/**
 * Class representing a PowerAuth error.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthError {

    private String code;
    private String message;
    private String localizedMessage;
    
    /**
     * Get error code.
     *
     * @return Error code.
     */
    public String getCode() {
        return code;
    }

    /**
     * Set error code.
     *
     * @param code Error code.
     */
    public void setCode(String code) {
        this.code = code;
    }

    /**
     * Get message (not localized).
     *
     * @return Message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Set message (not localized).
     *
     * @param message Message.
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * Get localized message.
     *
     * @return Localized message.
     */
    public String getLocalizedMessage() {
        return localizedMessage;
    }

    /**
     * Set localized message.
     *
     * @param localizedMessage Localized message.
     */
    public void setLocalizedMessage(String localizedMessage) {
        this.localizedMessage = localizedMessage;
    }

}
