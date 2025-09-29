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

import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;

import java.util.List;

/**
 * Data related to both online and offline authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class AuthenticationData {

    private byte[] data;
    private AuthenticationRequestData requestData;
    private String authenticationCode;
    private String authenticationVersion;
    private AuthenticationCodeConfiguration authCodeConfiguration;
    private List<KeyValue> additionalInfo;

    /**
     * No-arg constructor.
     */
    public AuthenticationData() {
    }

    /**
     * Authentication data constructor.
     * @param data Authenticated data.
     * @param authenticationCode Authentication code.
     * @param authCodeConfiguration Format of authentication code with associated parameters.
     * @param authenticationVersion Version of requested authentication.
     * @param additionalInfo Additional information related to the authentication.
     */
    public AuthenticationData(byte[] data, String authenticationCode, AuthenticationCodeConfiguration authCodeConfiguration, String authenticationVersion, List<KeyValue> additionalInfo) {
        this.data = data;
        this.authenticationCode = authenticationCode;
        this.authenticationVersion = authenticationVersion;
        this.authCodeConfiguration = authCodeConfiguration;
        this.additionalInfo = additionalInfo;
        this.requestData = AuthenticationDataParser.parseRequestData(data);
    }

    /**
     * Get authenticated data.
     * @return Authenticated data.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Get authentication code.
     * @return Authentication code.
     */
    public String getAuthenticationCode() {
        return authenticationCode;
    }

    /**
     * Get requested authentication version.
     * @return Authentication version.
     */
    public String getAuthenticationVersion() {
        return authenticationVersion;
    }

    /**
     * Get authentication configuration.
     * @return Authentication configuration.
     */
    public AuthenticationCodeConfiguration getAuthCodeConfiguration() {
        return authCodeConfiguration;
    }

    /**
     * Get additional information related to the authentication.
     * @return Additional information related to the authentication.
     */
    public List<KeyValue> getAdditionalInfo() {
        return additionalInfo;
    }

    /**
     * Get parsed method from request data.
     * @return Method from request data.
     */
    public String getRequestMethod() {
        if (requestData == null) {
            return null;
        }
        return requestData.getMethod();
    }

    /**
     * Get parsed URI identifier from request data.
     * @return URI identifier from request data.
     */
    public String getRequestUriId() {
        if (requestData == null) {
            return null;
        }
        return requestData.getUriIdentifier();
    }

    /**
     * Get parsed request body from request data.
     * @return Request body from request data.
     */
    public String getRequestBody() {
        if (requestData == null) {
            return null;
        }
        return requestData.getBody();
    }

}
