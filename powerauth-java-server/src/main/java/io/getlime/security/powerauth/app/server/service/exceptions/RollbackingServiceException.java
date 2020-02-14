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
package io.getlime.security.powerauth.app.server.service.exceptions;

/**
 * Exception used in case when database transaction needs to be rolled back. Do not use this exception in case
 * any data needs to be written to the database.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RollbackingServiceException extends GenericServiceException {

    private static final long serialVersionUID = -7531176695609348598L;

    /**
     * Constructor with error code and error message.
     *
     * @param code             Error code.
     * @param message          Error message.
     * @param localizedMessage Localized error message.
     */
    public RollbackingServiceException(String code, String message, String localizedMessage) {
        super(code, message, localizedMessage);
    }

}
