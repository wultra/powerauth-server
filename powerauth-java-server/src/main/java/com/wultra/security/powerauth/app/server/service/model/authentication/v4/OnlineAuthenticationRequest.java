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
package com.wultra.security.powerauth.app.server.service.model.authentication.v4;

import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;

/**
 * Request to verify online authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class OnlineAuthenticationRequest {

    private AuthenticationData authenticationData;
    private AuthenticationCodeType authenticationCodeType;

    /**
     * No-arg constructor.
     */
    public OnlineAuthenticationRequest() {
    }

    /**
     * Online authentication request constructor.
     * @param authenticationData Data related to the authentication.
     * @param authenticationCodeType Authentication type to use during verification of authentication.
     */
    public OnlineAuthenticationRequest(AuthenticationData authenticationData, AuthenticationCodeType authenticationCodeType) {
        this.authenticationData = authenticationData;
        this.authenticationCodeType = authenticationCodeType;
    }

    /**
     * Get data related to the authentication.
     * @return Data related to the authentication.
     */
    public AuthenticationData getAuthenticationData() {
        return authenticationData;
    }

    /**
     * Get authentication type to use during verification of authentication code.
     * @return Authentication type to use during verification.
     */
    public AuthenticationCodeType getAuthenticationCodeType() {
        return authenticationCodeType;
    }

}
