/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.service.model.authentication.v4;

import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;

import java.util.List;

/**
 * Request to verify offline authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class OfflineAuthenticationRequest {

    private AuthenticationData authenticationData;
    private List<AuthenticationCodeType> authenticationCodeTypes;

    /**
     * No-arg constructor.
     */
    public OfflineAuthenticationRequest() {
    }

    /**
     * Offline authentication request constructor.
     * @param authenticationData Data related to the authentication.
     * @param authenticationCodeTypes Authentication code types to try to use during verification of authentication code.
     */
    public OfflineAuthenticationRequest(AuthenticationData authenticationData, List<AuthenticationCodeType> authenticationCodeTypes) {
        this.authenticationData = authenticationData;
        this.authenticationCodeTypes = authenticationCodeTypes;
    }

    /**
     * Get data related to the authentication.
     * @return Data related to the authentication.
     */
    public AuthenticationData getAuthenticationData() {
        return authenticationData;
    }

    /**
     * Get authentication code type to try to use during verification of authentication code.
     * @return Authentication code type to try to use during verification of authentication code.
     */
    public List<AuthenticationCodeType> getAuthenticationCodeTypes() {
        return authenticationCodeTypes;
    }

}
