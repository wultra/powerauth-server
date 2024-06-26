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

import java.io.Serial;

/**
 * Exception for any service interface error. Note that this type of exception doesn't cause the transaction rollback.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class GenericServiceException extends Exception {

    @Serial
    private static final long serialVersionUID = 7185138483623356230L;

    private final String code;

    /**
     * Constructor with error code and error message
     *
     * @param code             Error code
     * @param message          Error message
     */
    public GenericServiceException(String code, String message) {
        super(message);
        this.code = code;
    }

    /**
     * Get the error code
     *
     * @return Error code
     */
    public String getCode() {
        return code;
    }

}
