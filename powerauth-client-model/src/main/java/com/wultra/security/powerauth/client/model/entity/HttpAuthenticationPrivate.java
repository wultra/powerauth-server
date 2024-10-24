/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
package com.wultra.security.powerauth.client.model.entity;

import lombok.Data;
import lombok.ToString;

/**
 * HTTP authentication class that is intended for private, strictly internal usage. It may contain
 * sensitive data, such as passwords.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class HttpAuthenticationPrivate {

    private Certificate certificate = new Certificate();
    private HttpBasic httpBasic = new HttpBasic();
    private OAuth2 oAuth2 = new OAuth2();

    @Data
    public static class Certificate {
        private boolean enabled;
        private boolean useCustomKeyStore;
        private String keyStoreLocation;
        @ToString.Exclude
        private String keyStorePassword;
        private String keyAlias;
        @ToString.Exclude
        private String keyPassword;
        private boolean useCustomTrustStore;
        private String trustStoreLocation;
        @ToString.Exclude
        private String trustStorePassword;
    }

    @Data
    public static class HttpBasic {
        private boolean enabled;
        private String username;
        @ToString.Exclude
        private String password;
    }

    @Data
    public static class OAuth2 {
        private boolean enabled;
        private String tokenUri;
        private String clientId;
        @ToString.Exclude
        private String clientSecret;
        private String scope;
    }

}
