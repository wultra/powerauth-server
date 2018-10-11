/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Lime - HighTech Solutions s.r.o.
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
 * Request object for vault unlock ECIES payload.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class VaultUnlockRequestPayload {

    private String reason;

    /**
     * Get vault unlock reason.
     * @return Vault unlock reason.
     */
    public String getReason() {
        return reason;
    }

    /**
     * Set vault unlock reason.
     * @param reason Vault unlock reason.
     */
    public void setReason(String reason) {
        this.reason = reason;
    }
}