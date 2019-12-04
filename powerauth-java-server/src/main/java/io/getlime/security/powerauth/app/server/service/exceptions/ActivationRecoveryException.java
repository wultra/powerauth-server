/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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
 * Exception for case when activation recovery fails.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ActivationRecoveryException extends GenericServiceException {

    private static final long serialVersionUID = 3813163488487380284L;

    private final int currentRecoveryPukIndex;

    /**
     * Constructor with error code and error message.
     *
     * @param code                     Error code.
     * @param message                  Error message.
     * @param localizedMessage         Localized error message.
     * @param currentRecoveryPukIndex  Current recovery PUK index.
     */
    public ActivationRecoveryException(String code, String message, String localizedMessage, int currentRecoveryPukIndex) {
        super(code, message, localizedMessage);
        this.currentRecoveryPukIndex = currentRecoveryPukIndex;
    }

    /**
     * Get current recovery PUK index.
     * @return Current recovery PUK index.
     */
    public int getCurrentRecoveryPukIndex() {
        return currentRecoveryPukIndex;
    }

}
