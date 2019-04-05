/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
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
package io.getlime.security.powerauth.app.server.service.model.request;

/**
 * Request object for confirm recovery code ECIES payload.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ConfirmRecoveryRequestPayload {

    private String recoveryCode;

    /**
     * Default constructor.
     */
    public ConfirmRecoveryRequestPayload() {
    }

    /**
     * Constructor with recovery code.
     * @param recoveryCode Recovery code.
     */
    public ConfirmRecoveryRequestPayload(String recoveryCode) {
        this.recoveryCode = recoveryCode;
    }

    /**
     * Get recovery code.
     * @return Recovery code.
     */
    public String getRecoveryCode() {
        return recoveryCode;
    }

    /**
     * Set recovery code.
     * @param recoveryCode Recovery code.
     */
    public void setRecoveryCode(String recoveryCode) {
        this.recoveryCode = recoveryCode;
    }
}