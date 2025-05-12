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

/**
 * Verify authentication response.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class AuthenticationResponse {

    private boolean authenticationValid;
    private long ctrNext;
    private byte[] ctrDataNext;
    private Integer forcedAuthenticationVersion;
    private AuthenticationCodeType usedAuthenticationCodeType;

    /**
     * No-arg constructor.
     */
    public AuthenticationResponse() {
    }

    /**
     * Verify authentication response constructor.
     * @param authenticationValid Whether authentication is valid.
     * @param ctrNext Next numeric counter value in case authentication is valid.
     * @param ctrDataNext Next hash based counter data in case authentication is valid.
     * @param forcedAuthenticationVersion Authentication version which may differ from activation version during upgrade.
     * @param usedAuthenticationCodeType Authentication code type which was used during verification of the authentication code.
     */
    public AuthenticationResponse(boolean authenticationValid, long ctrNext, byte[] ctrDataNext, Integer forcedAuthenticationVersion, AuthenticationCodeType usedAuthenticationCodeType) {
        this.authenticationValid = authenticationValid;
        this.ctrNext = ctrNext;
        this.ctrDataNext = ctrDataNext;
        this.forcedAuthenticationVersion = forcedAuthenticationVersion;
        this.usedAuthenticationCodeType = usedAuthenticationCodeType;
    }

    /**
     * Get whether authentication is valid.
     * @return Whether authentication is valid.
     */
    public boolean isAuthenticationValid() {
        return authenticationValid;
    }

    /**
     * Get next numeric counter value in case authentication is valid.
     * @return Next numeric counter value.
     */
    public long getCtrNext() {
        return ctrNext;
    }

    /**
     * Get next hash based counter value in case authentication is valid.
     * @return Next hash based counter value.
     */
    public byte[] getCtrDataNext() {
        return ctrDataNext;
    }

    /**
     * Get authentication version.
     * @return Authentication version.
     */
    public Integer getForcedAuthenticationVersion() {
        return forcedAuthenticationVersion;
    }

    /**
     * Get authentication code type which was used during authentication code validation.
     * @return Authentication code type which was used during authentication code validation.
     */
    public AuthenticationCodeType getUsedAuthenticationCodeType() {
        return usedAuthenticationCodeType;
    }
}
