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
package io.getlime.security.powerauth.app.server.service.exceptions;

/**
 * Exception for any SOAP interface error. Note that this type of exception doesn't cause the transaction rollback.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class GenericServiceException extends Exception {

    private static final long serialVersionUID = 7185138483623356230L;

    private String code;
    private final String localizedMessage;

    /**
     * Constructor with error code and error message
     *
     * @param code             Error code
     * @param message          Error message
     * @param localizedMessage Localized error message
     */
    public GenericServiceException(String code, String message, String localizedMessage) {
        super(message);
        this.code = code;
        this.localizedMessage = localizedMessage;
    }

    /**
     * Get the error code
     *
     * @return Error code
     */
    public String getCode() {
        return code;
    }

    /**
     * Get the error message
     *
     * @param code Error message
     */
    public void setCode(String code) {
        this.code = code;
    }

    @Override
    public String getLocalizedMessage() {
        return this.localizedMessage;
    }

}
